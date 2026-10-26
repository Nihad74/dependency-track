/*
 * This file is part of Dependency-Track.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) OWASP Foundation. All Rights Reserved.
 */
package org.dependencytrack.assessmentsync.workflow;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Meter.MeterProvider;
import io.micrometer.core.instrument.MeterRegistry;
import org.dependencytrack.assessmentsync.AssessmentEmbeddingIndexer;
import org.dependencytrack.assessmentsync.AssessmentMutationGuard;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao;
import org.dependencytrack.assessmentsync.AssessmentSyncMetrics;
import org.dependencytrack.assessmentsync.AssessmentSyncMode;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao;
import org.dependencytrack.assessmentsync.AssessmentSynchronizer;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.model.FindingKey;
import org.dependencytrack.proto.internal.workflow.v1.AssessmentMaintenanceOperation;
import org.dependencytrack.proto.internal.workflow.v1.MaintainAssessmentProjectionsArg;
import org.dependencytrack.proto.internal.workflow.v1.MaintainAssessmentProjectionsRes;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;

import java.util.List;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/// One project-UUID page of backfill, verification, or withdrawal.
@ActivitySpec(
        name = "maintain-assessment-projections",
        defaultTaskQueue = MaintainAssessmentProjectionsActivity.QUEUE_NAME)
public final class MaintainAssessmentProjectionsActivity
        implements Activity<MaintainAssessmentProjectionsArg, MaintainAssessmentProjectionsRes> {

    public static final String QUEUE_NAME = ExpandAssessmentChangesActivity.QUEUE_NAME;

    private static final String OPERATION_TAG = "operation";
    private static final UUID ZERO_CURSOR = UUID.fromString("00000000-0000-0000-0000-000000000000");

    private final int projectBatchSize;
    private final int findingBatchSize;
    private final MeterProvider<Counter> driftCounter;

    public MaintainAssessmentProjectionsActivity(
            final int projectBatchSize, final int findingBatchSize, final MeterRegistry meterRegistry) {
        if (projectBatchSize <= 0) {
            throw new IllegalArgumentException("projectBatchSize must be positive");
        }
        if (findingBatchSize <= 0) {
            throw new IllegalArgumentException("findingBatchSize must be positive");
        }
        requireNonNull(meterRegistry, "meterRegistry must not be null");
        this.projectBatchSize = projectBatchSize;
        this.findingBatchSize = findingBatchSize;
        this.driftCounter = Counter.builder(AssessmentSyncMetrics.DRIFT)
                .description("Findings whose maintained projection differed from current source consensus")
                .withRegistry(meterRegistry);
    }

    @Override
    public MaintainAssessmentProjectionsRes execute(
            final ActivityContext ctx, final @Nullable MaintainAssessmentProjectionsArg argument)
            throws InterruptedException {
        if (Thread.interrupted()) {
            throw new InterruptedException("Interrupted before assessment maintenance");
        }
        if (argument == null) {
            throw new TerminalApplicationFailureException("operation must be BOOTSTRAP, VERIFY, or WITHDRAW");
        }
        final AssessmentMaintenanceOperation operation = requireOperation(argument);
        final UUID cursor = cursor(argument);
        if (!allows(operation, AssessmentSyncMode.current())) {
            return result(cursor, false, 0, 0, 0);
        }

        final List<UUID> projects = withJdbiHandle(handle -> listProjects(handle, cursor, projectBatchSize));
        var scanned = 0;
        var drift = 0;
        var enqueued = 0;
        UUID next = cursor;
        for (final UUID projectUuid : projects) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted during assessment maintenance");
            }
            if (!allows(operation, AssessmentSyncMode.current())) {
                return result(next, false, scanned, drift, enqueued);
            }
            final ProjectOutcome outcome = inJdbiTransaction(handle -> processProject(handle, operation, projectUuid));
            if (outcome.halted()) {
                return result(next, false, scanned, drift, enqueued);
            }
            scanned++;
            drift += outcome.drift();
            enqueued += outcome.enqueued();
            next = projectUuid;
        }
        if (drift > 0) {
            driftCounter
                    .withTag(OPERATION_TAG, MaintainAssessmentProjectionsWorkflow.operationName(operation))
                    .increment(drift);
        }
        final boolean hasMore = projects.size() == projectBatchSize;
        return result(next, hasMore, scanned, drift, enqueued);
    }

    private ProjectOutcome processProject(
            final Handle handle, final AssessmentMaintenanceOperation operation, final UUID projectUuid)
            throws InterruptedException {
        final AssessmentSyncMode mode = AssessmentSyncMode.current();
        if (!allows(operation, mode)) {
            return ProjectOutcome.halt();
        }
        AssessmentMutationGuard.lockProject(handle, projectUuid);
        final Long projectId = projectId(handle, projectUuid);
        if (projectId == null) {
            return ProjectOutcome.advance(0, 0);
        }

        var drift = 0;
        var enqueued = 0;
        switch (operation) {
            case ASSESSMENT_MAINTENANCE_OPERATION_BOOTSTRAP -> {
                new AssessmentProjectionDao(handle).backfillProjectOrigins(projectUuid);
                new AssessmentEmbeddingIndexer(handle).rebuild(projectUuid);
                if (mode == AssessmentSyncMode.ACTIVE || mode == AssessmentSyncMode.CAPTURE) {
                    new AssessmentSyncWorkDao(handle).requestFull(projectUuid);
                    enqueued = 1;
                }
            }
            case ASSESSMENT_MAINTENANCE_OPERATION_VERIFY -> {
                new AssessmentEmbeddingIndexer(handle).rebuild(projectUuid);
                drift = countProjectDrift(handle, projectUuid, projectId);
                if (drift > 0 && (mode == AssessmentSyncMode.ACTIVE || mode == AssessmentSyncMode.CAPTURE)) {
                    new AssessmentSyncWorkDao(handle).requestFull(projectUuid);
                    enqueued = 1;
                }
            }
            case ASSESSMENT_MAINTENANCE_OPERATION_WITHDRAW -> {
                final int withdrawn = new AssessmentProjectionDao(handle).withdrawInherited(projectUuid);
                if (withdrawn > 0) {
                    new AssessmentSyncWorkDao(handle).requestRefresh(projectUuid);
                    enqueued = 1;
                }
            }
            case ASSESSMENT_MAINTENANCE_OPERATION_UNSPECIFIED, UNRECOGNIZED ->
                throw new TerminalApplicationFailureException("operation must be BOOTSTRAP, VERIFY, or WITHDRAW");
        }
        return ProjectOutcome.advance(drift, enqueued);
    }

    private int countProjectDrift(final Handle handle, final UUID projectUuid, final long projectId)
            throws InterruptedException {
        final var synchronizer = new AssessmentSynchronizer();
        var drift = 0;
        Long cursorComponentId = null;
        Long cursorVulnerabilityId = null;
        while (true) {
            if (Thread.interrupted()) {
                throw new InterruptedException("Interrupted during assessment verification");
            }
            final List<FindingKey> page =
                    findingPage(handle, projectId, cursorComponentId, cursorVulnerabilityId, findingBatchSize);
            if (page.isEmpty()) {
                return drift;
            }
            drift += synchronizer.countDrift(handle, projectUuid, page);
            if (page.size() < findingBatchSize) {
                return drift;
            }
            final FindingKey last = page.getLast();
            cursorComponentId = last.componentId();
            cursorVulnerabilityId = last.vulnDbId();
        }
    }

    private static boolean allows(final AssessmentMaintenanceOperation operation, final AssessmentSyncMode mode) {
        return switch (operation) {
            case ASSESSMENT_MAINTENANCE_OPERATION_BOOTSTRAP, ASSESSMENT_MAINTENANCE_OPERATION_VERIFY ->
                mode == AssessmentSyncMode.CAPTURE || mode == AssessmentSyncMode.ACTIVE;
            case ASSESSMENT_MAINTENANCE_OPERATION_WITHDRAW -> mode == AssessmentSyncMode.WITHDRAW;
            case ASSESSMENT_MAINTENANCE_OPERATION_UNSPECIFIED, UNRECOGNIZED -> false;
        };
    }

    private static List<UUID> listProjects(final Handle handle, final @Nullable UUID cursor, final int limit) {
        final boolean hasCursor = cursor != null;
        return handle.createQuery(/* language=SQL */ """
                        SELECT "UUID"
                          FROM "PROJECT"
                         WHERE (:hasCursor = FALSE OR "UUID" > :cursor)
                         ORDER BY "UUID"
                         LIMIT :limit
                        """)
                .bind("hasCursor", hasCursor)
                .bind("cursor", hasCursor ? cursor : ZERO_CURSOR)
                .bind("limit", limit)
                .map((rs, ctx) -> requireNonNull(rs.getObject("UUID", UUID.class)))
                .list();
    }

    private static List<FindingKey> findingPage(
            final Handle handle,
            final long projectId,
            final @Nullable Long cursorComponentId,
            final @Nullable Long cursorVulnerabilityId,
            final int limit) {
        final boolean hasCursor = cursorComponentId != null && cursorVulnerabilityId != null;
        return handle.createQuery(/* language=SQL */ """
                        SELECT component_id
                             , vulnerability_id
                          FROM (
                                SELECT DISTINCT fa."COMPONENT_ID" AS component_id
                                     , fa."VULNERABILITY_ID" AS vulnerability_id
                                  FROM "FINDINGATTRIBUTION" AS fa
                                 INNER JOIN "COMPONENT" AS c
                                    ON c."ID" = fa."COMPONENT_ID"
                                 WHERE c."PROJECT_ID" = :projectId
                                   AND fa."DELETED_AT" IS NULL
                                UNION
                                SELECT a."COMPONENT_ID"
                                     , a."VULNERABILITY_ID"
                                  FROM "ANALYSIS" AS a
                                 INNER JOIN "ASSESSMENT_ORIGIN" AS o
                                    ON o."ANALYSIS_ID" = a."ID"
                                 WHERE a."PROJECT_ID" = :projectId
                                   AND o."OWNER" = 'INHERITED'
                                   AND a."COMPONENT_ID" IS NOT NULL
                               ) AS keys
                         WHERE :hasCursor = FALSE
                            OR component_id > :cursorComponentId
                            OR (
                              component_id = :cursorComponentId
                              AND vulnerability_id > :cursorVulnerabilityId
                            )
                         ORDER BY component_id, vulnerability_id
                         LIMIT :limit
                        """)
                .bind("projectId", projectId)
                .bind("hasCursor", hasCursor)
                .bind("cursorComponentId", cursorComponentId == null ? 0L : cursorComponentId)
                .bind("cursorVulnerabilityId", cursorVulnerabilityId == null ? 0L : cursorVulnerabilityId)
                .bind("limit", limit)
                .map((rs, ctx) -> new FindingKey(rs.getLong("component_id"), rs.getLong("vulnerability_id")))
                .list();
    }

    private static @Nullable Long projectId(final Handle handle, final UUID projectUuid) {
        return handle.createQuery(/* language=SQL */ """
                        SELECT "ID"
                          FROM "PROJECT"
                         WHERE "UUID" = :projectUuid
                        """)
                .bind("projectUuid", projectUuid)
                .mapTo(long.class)
                .findOne()
                .orElse(null);
    }

    private static MaintainAssessmentProjectionsRes result(
            final @Nullable UUID cursor,
            final boolean hasMore,
            final int scanned,
            final int drift,
            final int enqueued) {
        final var builder = MaintainAssessmentProjectionsRes.newBuilder()
                .setHasMore(hasMore)
                .setScanned(scanned)
                .setDrift(drift)
                .setEnqueued(enqueued);
        if (cursor != null) {
            builder.setProjectUuidCursor(cursor.toString());
        }
        return builder.build();
    }

    private static AssessmentMaintenanceOperation requireOperation(
            final @Nullable MaintainAssessmentProjectionsArg argument) {
        if (argument == null) {
            throw new TerminalApplicationFailureException("operation must be BOOTSTRAP, VERIFY, or WITHDRAW");
        }
        return switch (argument.getOperation()) {
            case ASSESSMENT_MAINTENANCE_OPERATION_BOOTSTRAP,
                    ASSESSMENT_MAINTENANCE_OPERATION_VERIFY,
                    ASSESSMENT_MAINTENANCE_OPERATION_WITHDRAW -> argument.getOperation();
            case ASSESSMENT_MAINTENANCE_OPERATION_UNSPECIFIED, UNRECOGNIZED ->
                throw new TerminalApplicationFailureException("operation must be BOOTSTRAP, VERIFY, or WITHDRAW");
        };
    }

    private static @Nullable UUID cursor(final MaintainAssessmentProjectionsArg argument) {
        if (!argument.hasProjectUuidCursor() || argument.getProjectUuidCursor().isBlank()) {
            return null;
        }
        try {
            return UUID.fromString(argument.getProjectUuidCursor());
        } catch (IllegalArgumentException e) {
            throw new TerminalApplicationFailureException("project_uuid_cursor must be a UUID", e);
        }
    }

    private record ProjectOutcome(int drift, int enqueued, boolean halted) {

        private static ProjectOutcome halt() {
            return new ProjectOutcome(0, 0, true);
        }

        private static ProjectOutcome advance(final int drift, final int enqueued) {
            return new ProjectOutcome(drift, enqueued, false);
        }
    }
}
