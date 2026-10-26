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

import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.assessmentsync.AssessmentChange;
import org.dependencytrack.assessmentsync.AssessmentChange.Scope;
import org.dependencytrack.assessmentsync.AssessmentChangeRecorder;
import org.dependencytrack.assessmentsync.AssessmentSyncMetrics;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao.WorkRow;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.proto.internal.workflow.v1.AssessmentMaintenanceOperation;
import org.dependencytrack.proto.internal.workflow.v1.MaintainAssessmentProjectionsArg;
import org.dependencytrack.proto.internal.workflow.v1.MaintainAssessmentProjectionsRes;
import org.dependencytrack.proto.internal.workflow.v1.SynchronizeProjectAssessmentsArg;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class AssessmentMaintenanceWorkflowTest extends PersistenceCapableTest {

    private static final ActivityContext CONTEXT = () -> UUID.randomUUID();
    private static final UUID UUID_1 = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final UUID UUID_2 = UUID.fromString("00000000-0000-4000-8000-000000000002");
    private static final UUID UUID_3 = UUID.fromString("00000000-0000-4000-8000-000000000003");
    private static final UUID UUID_5 = UUID.fromString("00000000-0000-4000-8000-000000000005");
    private static final UUID UUID_7 = UUID.fromString("00000000-0000-4000-8000-000000000007");

    private static final AssessmentMaintenanceOperation BOOTSTRAP =
            AssessmentMaintenanceOperation.ASSESSMENT_MAINTENANCE_OPERATION_BOOTSTRAP;
    private static final AssessmentMaintenanceOperation VERIFY =
            AssessmentMaintenanceOperation.ASSESSMENT_MAINTENANCE_OPERATION_VERIFY;
    private static final AssessmentMaintenanceOperation WITHDRAW =
            AssessmentMaintenanceOperation.ASSESSMENT_MAINTENANCE_OPERATION_WITHDRAW;

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    @AfterEach
    void clearMode() {
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_WORKFLOW_MAX_BATCHES);
    }

    @Test
    void captureOverlappingAScanLeavesTheEventAndDoesNotApply() throws Exception {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "OFF");
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 1);
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        recordProject(fixture.target.getUuid(), "before-scan");

        final Handle slow = openJdbiHandle();
        try {
            slow.begin();
            new AssessmentChangeRecorder(slow).record(projectChange(fixture.target.getUuid(), "during-scan"));
            scan(activity(1, new SimpleMeterRegistry()), BOOTSTRAP);

            assertThat(outboxReasons()).containsExactly("before-scan");
            assertThat(ReconcileFixture.state(fixture.library().getId(), fixture.vulnerability.getId()))
                    .isNull();
            assertThat(ReconcileFixture.owner(fixture.library().getId(), fixture.vulnerability.getId()))
                    .isNull();
            assertThat(requestedRevision(fixture.target.getUuid())).isEqualTo(1);

            slow.commit();
        } finally {
            if (slow.isInTransaction()) {
                slow.rollback();
            }
            slow.close();
        }

        assertThat(outboxReasons()).containsExactly("before-scan", "during-scan");
        assertThat(ReconcileFixture.state(fixture.library().getId(), fixture.vulnerability.getId()))
                .isNull();
        assertThat(registryBacklog()).isGreaterThanOrEqualTo(2d);
    }

    @Test
    void newUuidBehindTheCursorIsLeftForCapturedEvents() throws Exception {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        insertProject(UUID_1, "behind");
        insertProject(UUID_3, "ahead");
        recordProject(UUID_1, "behind-cursor");

        final MaintainAssessmentProjectionsRes page =
                activity(10, new SimpleMeterRegistry()).execute(CONTEXT, argument(BOOTSTRAP, UUID_2));

        assertThat(page.getHasMore()).isFalse();
        assertThat(page.getProjectUuidCursor()).isEqualTo(UUID_3.toString());
        assertThat(requestedRevision(UUID_3)).isEqualTo(1);
        assertThat(requestedRevision(UUID_1)).isZero();
        assertThat(outboxReasons()).containsExactly("behind-cursor");
    }

    @Test
    void lateCommitAfterTheCursorIsStillSeen() throws Exception {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        insertProject(UUID_1, "first");
        final var maintenance = activity(1, new SimpleMeterRegistry());

        final MaintainAssessmentProjectionsRes first = maintenance.execute(CONTEXT, argument(BOOTSTRAP, null));
        assertThat(first.getHasMore()).isTrue();
        assertThat(first.getProjectUuidCursor()).isEqualTo(UUID_1.toString());
        assertThat(requestedRevision(UUID_1)).isEqualTo(1);

        final Handle slow = openJdbiHandle();
        try {
            slow.begin();
            slow.createUpdate("""
                            INSERT INTO "PROJECT" ("NAME", "UUID")
                            VALUES (:name, :uuid)
                            """).bind("name", "late").bind("uuid", UUID_5).execute();
            final long lateId =
                    slow.createQuery("""
                            SELECT "ID"
                              FROM "PROJECT"
                             WHERE "UUID" = :uuid
                            """).bind("uuid", UUID_5).mapTo(long.class).one();
            insertProject(UUID_3, "committed-while-late-is-open");
            final long higherId = projectRowId(UUID_3);
            assertThat(lateId).isLessThan(higherId);

            final MaintainAssessmentProjectionsRes hidden = maintenance.execute(CONTEXT, argument(BOOTSTRAP, UUID_1));
            assertThat(hidden.getProjectUuidCursor()).isEqualTo(UUID_3.toString());
            assertThat(requestedRevision(UUID_5)).isZero();
            assertThat(requestedRevision(UUID_3)).isEqualTo(1);
            assertThat(requestedRevision(UUID_1)).isEqualTo(1);

            slow.commit();
        } finally {
            if (slow.isInTransaction()) {
                slow.rollback();
            }
            slow.close();
        }

        final MaintainAssessmentProjectionsRes seen = maintenance.execute(CONTEXT, argument(BOOTSTRAP, UUID_3));
        assertThat(seen.getProjectUuidCursor()).isEqualTo(UUID_5.toString());
        assertThat(requestedRevision(UUID_5)).isEqualTo(1);
    }

    @Test
    void missedHookDriftIsDetectedAndRepairedWithoutPromoteDuringVerify() throws Exception {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "ACTIVE");
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 1);
        ReconcileFixture.requestFull(fixture.target.getUuid());
        final var reconcile = new ReconcileProjectAssessmentsActivity(50, Duration.ofMinutes(10));
        final var target = SynchronizeProjectAssessmentsArg.newBuilder()
                .setProjectUuid(fixture.target.getUuid().toString())
                .build();
        reconcile.execute(CONTEXT, target);
        assertThat(ReconcileFixture.state(fixture.library().getId(), fixture.vulnerability.getId()))
                .isEqualTo("EXPLOITABLE");

        useJdbiTransaction(handle ->
                handle.createUpdate("""
                        UPDATE "ANALYSIS"
                           SET "STATE" = 'NOT_AFFECTED'
                         WHERE "ID" = :id
                        """).bind("id", fixture.alpineAnalysisId).execute());
        final WorkRow before = ReconcileFixture.work(fixture.target.getUuid());
        assertThat(before).isNotNull();
        final var registry = new SimpleMeterRegistry();

        scan(activity(20, registry), VERIFY);

        assertThat(ReconcileFixture.state(fixture.library().getId(), fixture.vulnerability.getId()))
                .isEqualTo("EXPLOITABLE");
        assertThat(ReconcileFixture.owner(fixture.library().getId(), fixture.vulnerability.getId()))
                .isEqualTo("INHERITED");
        final WorkRow enqueued = ReconcileFixture.work(fixture.target.getUuid());
        assertThat(enqueued).isNotNull();
        assertThat(enqueued.requestedRevision()).isGreaterThan(before.requestedRevision());
        assertThat(registry.counter(AssessmentSyncMetrics.DRIFT, "operation", "VERIFY")
                        .count())
                .isPositive();

        reconcile.execute(CONTEXT, target);
        assertThat(ReconcileFixture.state(fixture.library().getId(), fixture.vulnerability.getId()))
                .isEqualTo("NOT_AFFECTED");
        assertThat(ReconcileFixture.owner(fixture.library().getId(), fixture.vulnerability.getId()))
                .isEqualTo("INHERITED");
    }

    @Test
    void legacyOriginStaysProtected() throws Exception {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "OFF");
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 1);
        final long analysisId = qm.makeAnalysis(new MakeAnalysisCommand(fixture.library(), fixture.vulnerability)
                .withState(AnalysisState.IN_TRIAGE)
                .withDetails("legacy-details")
                .withOptions(Set.of(
                        MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL, MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        useJdbiTransaction(
                handle -> handle.createUpdate("""
                        DELETE FROM "ASSESSMENT_ORIGIN"
                         WHERE "ANALYSIS_ID" = :id
                        """).bind("id", analysisId).execute());
        insertComment(analysisId, "legacy-note");
        final long componentId = fixture.library().getId();
        final long vulnerabilityId = fixture.vulnerability.getId();

        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "ACTIVE");
        final var registry = new SimpleMeterRegistry();
        scan(activity(20, registry), VERIFY);

        assertThat(ReconcileFixture.state(componentId, vulnerabilityId)).isEqualTo("IN_TRIAGE");
        assertThat(ReconcileFixture.owner(componentId, vulnerabilityId)).isNull();
        assertThat(ReconcileFixture.details(componentId, vulnerabilityId)).isEqualTo("legacy-details");
        assertThat(ReconcileFixture.localComments(componentId, vulnerabilityId)).containsExactly("legacy-note");
        assertThat(registry.find(AssessmentSyncMetrics.DRIFT).counters()).isEmpty();

        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        scan(activity(20, new SimpleMeterRegistry()), BOOTSTRAP);

        assertThat(ReconcileFixture.owner(componentId, vulnerabilityId)).isEqualTo("LOCAL");
        assertThat(ReconcileFixture.state(componentId, vulnerabilityId)).isEqualTo("IN_TRIAGE");
        assertThat(ReconcileFixture.details(componentId, vulnerabilityId)).isEqualTo("legacy-details");
        assertThat(ReconcileFixture.localComments(componentId, vulnerabilityId)).containsExactly("legacy-note");

        scan(activity(20, new SimpleMeterRegistry()), VERIFY);
        assertThat(ReconcileFixture.owner(componentId, vulnerabilityId)).isEqualTo("LOCAL");
        assertThat(ReconcileFixture.state(componentId, vulnerabilityId)).isEqualTo("IN_TRIAGE");
    }

    @Test
    void pauseAndResumeContinuesFromTheCursor() throws Exception {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_WORKFLOW_MAX_BATCHES, "1");
        insertProject(UUID_1, "a");
        insertProject(UUID_3, "b");
        insertProject(UUID_5, "c");
        final var maintenance = activity(1, new SimpleMeterRegistry());

        final MaintainAssessmentProjectionsRes first = maintenance.execute(CONTEXT, argument(BOOTSTRAP, null));
        assertThat(first.getProjectUuidCursor()).isEqualTo(UUID_1.toString());
        assertThat(first.getHasMore()).isTrue();
        assertThat(requestedRevision(UUID_1)).isEqualTo(1);

        final MaintainAssessmentProjectionsRes resumed =
                maintenance.execute(CONTEXT, argument(BOOTSTRAP, UUID.fromString(first.getProjectUuidCursor())));
        assertThat(resumed.getProjectUuidCursor()).isEqualTo(UUID_3.toString());
        assertThat(requestedRevision(UUID_1)).isEqualTo(1);
        assertThat(requestedRevision(UUID_3)).isEqualTo(1);
        assertThat(requestedRevision(UUID_5)).isZero();

        startWorkflow();
        assertThat(MaintainAssessmentProjectionsWorkflow.instanceId(BOOTSTRAP))
                .isEqualTo("assessment-maintenance:BOOTSTRAP");
        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(MaintainAssessmentProjectionsWorkflow.class)
                        .withWorkflowInstanceId(MaintainAssessmentProjectionsWorkflow.instanceId(BOOTSTRAP))
                        .withConcurrencyKey(MaintainAssessmentProjectionsWorkflow.instanceId(BOOTSTRAP))
                        .withArgument(argument(BOOTSTRAP, UUID_3)));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(requestedRevision(UUID_1)).isEqualTo(1);
        assertThat(requestedRevision(UUID_3)).isEqualTo(1);
        assertThat(requestedRevision(UUID_5)).isEqualTo(1);

        insertProject(UUID_7, "after-pause");
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "WITHDRAW");
        final MaintainAssessmentProjectionsRes stopped = maintenance.execute(CONTEXT, argument(BOOTSTRAP, null));
        assertThat(stopped.getHasMore()).isFalse();
        assertThat(stopped.getScanned()).isZero();
        assertThat(requestedRevision(UUID_7)).isZero();
        assertThat(requestedRevision(UUID_1)).isEqualTo(1);
    }

    @Test
    void withdrawalRemovesInheritedRowsAndKeepsAuthoredRows() throws Exception {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "ACTIVE");
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 1);
        ReconcileFixture.requestFull(fixture.target.getUuid());
        new ReconcileProjectAssessmentsActivity(50, Duration.ofMinutes(10))
                .execute(
                        CONTEXT,
                        SynchronizeProjectAssessmentsArg.newBuilder()
                                .setProjectUuid(fixture.target.getUuid().toString())
                                .build());
        final long componentId = fixture.library().getId();
        final long inheritedVulnerabilityId = fixture.vulnerability.getId();
        assertThat(ReconcileFixture.copiedCommentTimestamp(componentId, inheritedVulnerabilityId))
                .isNotNull();
        insertComment(analysisId(componentId, inheritedVulnerabilityId), "keep-local-note");

        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "OFF");
        final long localVulnerabilityId = authored(fixture, "LOCAL", AnalysisState.IN_TRIAGE, "local-authored");
        final long policyVulnerabilityId = authored(fixture, "POLICY", AnalysisState.IN_TRIAGE, "policy-authored");
        setOwner(analysisId(componentId, policyVulnerabilityId), "POLICY");
        final long neutralVulnerabilityId =
                authored(fixture, "NEUTRAL", AnalysisState.FALSE_POSITIVE, "neutral-authored");
        setOwner(analysisId(componentId, neutralVulnerabilityId), "NEUTRAL");

        final var registry = new SimpleMeterRegistry();
        AssessmentSyncMetrics.bind(registry);
        assertThat(registry.get(AssessmentSyncMetrics.ROLLBACK_INCOMPLETE)
                        .gauge()
                        .value())
                .isEqualTo(1d);
        assertThat(registry.get(AssessmentSyncMetrics.INHERITED).gauge().value())
                .isGreaterThanOrEqualTo(1d);
        assertThat(registry.get(AssessmentSyncMetrics.MODE)
                        .tag("mode", "OFF")
                        .gauge()
                        .value())
                .isEqualTo(1d);
        final WorkRow before = ReconcileFixture.work(fixture.target.getUuid());
        assertThat(before).isNotNull();

        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "WITHDRAW");
        scan(activity(20, registry), WITHDRAW);

        assertThat(ReconcileFixture.state(componentId, inheritedVulnerabilityId))
                .isEqualTo("NOT_SET");
        assertThat(ReconcileFixture.owner(componentId, inheritedVulnerabilityId))
                .isEqualTo("NEUTRAL");
        assertThat(ReconcileFixture.contributionCount(componentId, inheritedVulnerabilityId))
                .isZero();
        assertThat(ReconcileFixture.localComments(componentId, inheritedVulnerabilityId))
                .containsExactly("keep-local-note");
        assertThat(ReconcileFixture.copiedCommentTimestamp(componentId, inheritedVulnerabilityId))
                .isNull();
        assertThat(ReconcileFixture.state(componentId, localVulnerabilityId)).isEqualTo("IN_TRIAGE");
        assertThat(ReconcileFixture.owner(componentId, localVulnerabilityId)).isEqualTo("LOCAL");
        assertThat(ReconcileFixture.details(componentId, localVulnerabilityId)).isEqualTo("local-authored");
        assertThat(ReconcileFixture.state(componentId, policyVulnerabilityId)).isEqualTo("IN_TRIAGE");
        assertThat(ReconcileFixture.owner(componentId, policyVulnerabilityId)).isEqualTo("POLICY");
        assertThat(ReconcileFixture.details(componentId, policyVulnerabilityId)).isEqualTo("policy-authored");
        assertThat(ReconcileFixture.state(componentId, neutralVulnerabilityId)).isEqualTo("FALSE_POSITIVE");
        assertThat(ReconcileFixture.owner(componentId, neutralVulnerabilityId)).isEqualTo("NEUTRAL");
        assertThat(ReconcileFixture.details(componentId, neutralVulnerabilityId))
                .isEqualTo("neutral-authored");
        final WorkRow after = ReconcileFixture.work(fixture.target.getUuid());
        assertThat(after).isNotNull();
        assertThat(after.refreshRequested()).isGreaterThan(before.refreshRequested());

        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "OFF");
        assertThat(registry.get(AssessmentSyncMetrics.ROLLBACK_INCOMPLETE)
                        .gauge()
                        .value())
                .isZero();
        assertThat(registry.get(AssessmentSyncMetrics.INHERITED).gauge().value())
                .isZero();
    }

    private static MaintainAssessmentProjectionsActivity activity(
            final int projectBatchSize, final SimpleMeterRegistry registry) {
        return new MaintainAssessmentProjectionsActivity(projectBatchSize, 50, registry);
    }

    private static MaintainAssessmentProjectionsRes scan(
            final MaintainAssessmentProjectionsActivity maintenance, final AssessmentMaintenanceOperation operation)
            throws Exception {
        var argument = argument(operation, null);
        MaintainAssessmentProjectionsRes last = null;
        for (int i = 0; i < 30; i++) {
            last = maintenance.execute(CONTEXT, argument);
            if (!last.getHasMore()) {
                return last;
            }
            argument = argument.toBuilder()
                    .setProjectUuidCursor(last.getProjectUuidCursor())
                    .build();
        }
        throw new AssertionError("maintenance scan did not finish");
    }

    private static MaintainAssessmentProjectionsArg argument(
            final AssessmentMaintenanceOperation operation, final @Nullable UUID cursor) {
        final var builder = MaintainAssessmentProjectionsArg.newBuilder().setOperation(operation);
        if (cursor != null) {
            builder.setProjectUuidCursor(cursor.toString());
        }
        return builder.build();
    }

    private static void insertProject(final UUID uuid, final String name) {
        useJdbiTransaction(handle ->
                handle.createUpdate("""
                        INSERT INTO "PROJECT" ("NAME", "UUID")
                        VALUES (:name, :uuid)
                        """).bind("name", name).bind("uuid", uuid).execute());
    }

    private static void recordProject(final UUID projectUuid, final String reason) {
        useJdbiTransaction(handle -> new AssessmentChangeRecorder(handle).record(projectChange(projectUuid, reason)));
    }

    private static AssessmentChange projectChange(final UUID projectUuid, final String reason) {
        return new AssessmentChange(Scope.PROJECT, projectUuid, null, null, reason, List.of());
    }

    private static long requestedRevision(final UUID projectUuid) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "REQUESTED_REVISION"
                          FROM "ASSESSMENT_SYNC_WORK"
                         WHERE "TARGET_UUID" = :projectUuid
                        """)
                .bind("projectUuid", projectUuid)
                .mapTo(long.class)
                .findOne()
                .orElse(0L));
    }

    private static long projectRowId(final UUID projectUuid) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "ID"
                          FROM "PROJECT"
                         WHERE "UUID" = :projectUuid
                        """)
                .bind("projectUuid", projectUuid)
                .mapTo(long.class)
                .one());
    }

    private static List<String> outboxReasons() {
        return withJdbiHandle(
                handle -> handle.createQuery("""
                        SELECT "REASON"
                          FROM "ASSESSMENT_SYNC_OUTBOX"
                         ORDER BY "ID"
                        """).mapTo(String.class).list());
    }

    private static double registryBacklog() {
        final var registry = new SimpleMeterRegistry();
        AssessmentSyncMetrics.bind(registry);
        return registry.get(AssessmentSyncMetrics.BACKLOG_EVENTS).gauge().value();
    }

    private static long analysisId(final long componentId, final long vulnerabilityId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "ID"
                          FROM "ANALYSIS"
                         WHERE "COMPONENT_ID" = :componentId
                           AND "VULNERABILITY_ID" = :vulnerabilityId
                        """)
                .bind("componentId", componentId)
                .bind("vulnerabilityId", vulnerabilityId)
                .mapTo(long.class)
                .one());
    }

    private static void insertComment(final long analysisId, final String comment) {
        useJdbiTransaction(handle -> handle.createUpdate("""
                        INSERT INTO "ANALYSISCOMMENT" ("ANALYSIS_ID", "COMMENT", "COMMENTER", "TIMESTAMP")
                        VALUES (:analysisId, :comment, :commenter, :timestamp)
                        """)
                .bind("analysisId", analysisId)
                .bind("comment", comment)
                .bind("commenter", "erin")
                .bind("timestamp", OffsetDateTime.parse("2024-05-06T07:08:09Z"))
                .execute());
    }

    private static void setOwner(final long analysisId, final String owner) {
        useJdbiTransaction(handle -> handle.createUpdate("""
                        UPDATE "ASSESSMENT_ORIGIN"
                           SET "OWNER" = :owner
                         WHERE "ANALYSIS_ID" = :analysisId
                        """)
                .bind("owner", owner)
                .bind("analysisId", analysisId)
                .execute());
    }

    private long authored(
            final ReconcileFixture fixture, final String name, final AnalysisState state, final String details) {
        final var vulnerability = new Vulnerability();
        vulnerability.setVulnId(name + "-" + UUID.randomUUID());
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        final Vulnerability persisted = qm.persist(vulnerability);
        qm.addVulnerability(persisted, fixture.library(), "internal");
        qm.makeAnalysis(new MakeAnalysisCommand(fixture.library(), persisted)
                .withState(state)
                .withDetails(details)
                .withOptions(Set.of(
                        MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL, MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        return persisted.getId();
    }

    private void startWorkflow() {
        final DexEngine engine = workflowTest.getEngine();
        engine.registerWorkflow(
                new MaintainAssessmentProjectionsWorkflow(),
                protoConverter(MaintainAssessmentProjectionsArg.class),
                voidConverter(),
                Duration.ofSeconds(15));
        engine.registerActivity(
                activity(1, new SimpleMeterRegistry()),
                protoConverter(MaintainAssessmentProjectionsArg.class),
                protoConverter(MaintainAssessmentProjectionsRes.class));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 10));
        engine.createTaskQueue(
                new CreateTaskQueueRequest(TaskType.ACTIVITY, MaintainAssessmentProjectionsActivity.QUEUE_NAME, 10));
        engine.registerTaskWorker(new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 2)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(new TaskWorkerOptions(
                        TaskType.ACTIVITY, "assessment-sync", MaintainAssessmentProjectionsActivity.QUEUE_NAME, 2)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.start();
    }
}
