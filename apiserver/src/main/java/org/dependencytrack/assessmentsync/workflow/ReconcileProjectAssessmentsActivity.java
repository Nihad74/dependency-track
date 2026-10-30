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

import org.dependencytrack.assessmentsync.AssessmentEmbeddingIndexer;
import org.dependencytrack.assessmentsync.AssessmentMutationGuard;
import org.dependencytrack.assessmentsync.AssessmentSyncMode;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao.Pass;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao.WorkRow;
import org.dependencytrack.assessmentsync.AssessmentSynchronizer;
import org.dependencytrack.assessmentsync.AssessmentSynchronizer.BatchResult;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.model.FindingKey;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileProjectAssessmentsRes;
import org.dependencytrack.proto.internal.workflow.v1.SynchronizeProjectAssessmentsArg;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;

/// One reconciliation batch for a target project. The work row holds the cursor.
@ActivitySpec(name = "reconcile-project-assessments", defaultTaskQueue = ReconcileProjectAssessmentsActivity.QUEUE_NAME)
public final class ReconcileProjectAssessmentsActivity
        implements Activity<SynchronizeProjectAssessmentsArg, ReconcileProjectAssessmentsRes> {

    public static final String QUEUE_NAME = ExpandAssessmentChangesActivity.QUEUE_NAME;

    private final int reconcileBatchSize;
    private final Duration inactiveBackoff;
    private final Runnable afterWrite;

    public ReconcileProjectAssessmentsActivity(final int reconcileBatchSize, final Duration inactiveBackoff) {
        this(reconcileBatchSize, inactiveBackoff, () -> {});
    }

    /// {@code afterWrite} runs inside the batch transaction after the batch is written, so a test can
    /// make the batch fail and roll back.
    ReconcileProjectAssessmentsActivity(
            final int reconcileBatchSize, final Duration inactiveBackoff, final Runnable afterWrite) {
        if (reconcileBatchSize <= 0) {
            throw new IllegalArgumentException("reconcileBatchSize must be positive");
        }
        if (inactiveBackoff == null || inactiveBackoff.isZero() || inactiveBackoff.isNegative()) {
            throw new IllegalArgumentException("inactiveBackoff must be positive");
        }
        this.reconcileBatchSize = reconcileBatchSize;
        this.inactiveBackoff = inactiveBackoff;
        this.afterWrite = requireNonNull(afterWrite, "afterWrite must not be null");
    }

    @Override
    public ReconcileProjectAssessmentsRes execute(
            final ActivityContext ctx, final @Nullable SynchronizeProjectAssessmentsArg argument)
            throws InterruptedException {
        if (Thread.interrupted()) {
            throw new InterruptedException("Interrupted before assessment reconciliation");
        }
        final UUID targetUuid = AssessmentSyncArguments.projectUuid(
                AssessmentSyncArguments.require(argument).getProjectUuid());
        if (AssessmentSyncMode.current() != AssessmentSyncMode.ACTIVE) {
            return inJdbiTransaction(handle -> deferInactive(handle, targetUuid));
        }
        return inJdbiTransaction(handle -> reconcile(handle, targetUuid));
    }

    private ReconcileProjectAssessmentsRes deferInactive(final Handle handle, final UUID targetUuid) {
        new AssessmentSyncWorkDao(handle)
                .scheduleDispatch(targetUuid, Instant.now().plus(inactiveBackoff));
        return ReconcileProjectAssessmentsRes.newBuilder()
                .setHasMore(false)
                .setRefreshRevision(0)
                .setTargetDeleted(false)
                .setApplied(0)
                .setWithdrawn(0)
                .setSkipped(0)
                .build();
    }

    private ReconcileProjectAssessmentsRes reconcile(final Handle handle, final UUID targetUuid) {
        AssessmentMutationGuard.lockProject(handle, targetUuid);
        final var workDao = new AssessmentSyncWorkDao(handle);
        final Long projectId = handle.createQuery(/* language=SQL */ """
                        SELECT "ID"
                          FROM "PROJECT"
                         WHERE "UUID" = :targetUuid
                        """)
                .bind("targetUuid", targetUuid)
                .mapTo(long.class)
                .findOne()
                .orElse(null);
        if (projectId == null) {
            workDao.acknowledgeCancellation(targetUuid);
            return ReconcileProjectAssessmentsRes.newBuilder()
                    .setHasMore(false)
                    .setRefreshRevision(0)
                    .setTargetDeleted(true)
                    .setApplied(0)
                    .setWithdrawn(0)
                    .setSkipped(0)
                    .build();
        }

        final Pass pass = workDao.beginOrResumePass(targetUuid);
        if (pass == null) {
            return ReconcileProjectAssessmentsRes.newBuilder()
                    .setHasMore(false)
                    .setRefreshRevision(0)
                    .setTargetDeleted(false)
                    .setApplied(0)
                    .setWithdrawn(0)
                    .setSkipped(0)
                    .build();
        }
        if (pass.full() && !pass.resumed()) {
            new AssessmentEmbeddingIndexer(handle).rebuild(targetUuid);
        }

        final List<FindingKey> fetched = pageKeys(handle, projectId, targetUuid, pass, reconcileBatchSize + 1);
        final boolean moreInPass = fetched.size() > reconcileBatchSize;
        final List<FindingKey> page = moreInPass ? fetched.subList(0, reconcileBatchSize) : fetched;
        final BatchResult batch = new AssessmentSynchronizer().reconcileBatch(handle, targetUuid, page);
        afterWrite.run();

        final long refreshRevision = batch.machineFieldsChanged() ? workDao.requestRefresh(targetUuid) : 0;
        if (moreInPass) {
            if (page.isEmpty()) {
                throw new IllegalStateException("Assessment page was empty while more keys were reported");
            }
            final FindingKey last = page.getLast();
            if (!workDao.advancePass(targetUuid, pass.activeRevision(), last.componentId(), last.vulnDbId())) {
                throw new IllegalStateException("Assessment cursor was not advanced for " + targetUuid);
            }
        } else if (!workDao.completePass(targetUuid, pass.activeRevision())) {
            throw new IllegalStateException("Assessment pass was not completed for " + targetUuid);
        }

        final WorkRow row = workDao.find(targetUuid);
        final boolean revisionPending = row != null && row.requestedRevision() > row.completedRevision();
        return ReconcileProjectAssessmentsRes.newBuilder()
                .setHasMore(moreInPass || revisionPending)
                .setRefreshRevision(refreshRevision)
                .setTargetDeleted(false)
                .setApplied(batch.applied())
                .setWithdrawn(batch.withdrawn())
                .setSkipped(batch.skipped())
                .build();
    }

    private static List<FindingKey> pageKeys(
            final Handle handle, final long projectId, final UUID targetUuid, final Pass pass, final int limit) {
        final Long storedCursorComponentId = pass.cursorComponentId();
        final Long storedCursorVulnerabilityId = pass.cursorVulnerabilityId();
        final boolean hasCursor = storedCursorComponentId != null && storedCursorVulnerabilityId != null;
        final long cursorComponentId = storedCursorComponentId == null ? 0L : storedCursorComponentId;
        final long cursorVulnerabilityId = storedCursorVulnerabilityId == null ? 0L : storedCursorVulnerabilityId;
        if (pass.full()) {
            return InheritableFindingKeys.page(
                    handle, projectId, pass.cursorComponentId(), pass.cursorVulnerabilityId(), limit);
        }
        return handle.createQuery(/* language=SQL */ """
                        SELECT "COMPONENT_ID"
                             , "VULNERABILITY_ID"
                          FROM "ASSESSMENT_SYNC_FINDING"
                         WHERE "TARGET_UUID" = :targetUuid
                           AND "REVISION" <= :activeRevision
                           AND (
                             :hasCursor = FALSE
                             OR "COMPONENT_ID" > :cursorComponentId
                             OR (
                               "COMPONENT_ID" = :cursorComponentId
                               AND "VULNERABILITY_ID" > :cursorVulnerabilityId
                             )
                           )
                         ORDER BY "COMPONENT_ID", "VULNERABILITY_ID"
                         LIMIT :limit
                        """)
                .bind("targetUuid", targetUuid)
                .bind("activeRevision", pass.activeRevision())
                .bind("hasCursor", hasCursor)
                .bind("cursorComponentId", cursorComponentId)
                .bind("cursorVulnerabilityId", cursorVulnerabilityId)
                .bind("limit", limit)
                .map((rs, ctx) -> new FindingKey(rs.getLong("COMPONENT_ID"), rs.getLong("VULNERABILITY_ID")))
                .list();
    }
}
