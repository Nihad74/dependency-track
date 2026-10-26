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
package org.dependencytrack.assessmentsync;

import io.github.resilience4j.core.IntervalFunction;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Meter;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.assessmentsync.AssessmentChange.Scope;
import org.dependencytrack.assessmentsync.AssessmentSyncOutboxDao.OutboxEntry;
import org.dependencytrack.assessmentsync.workflow.ExpandAssessmentChangesActivity;
import org.dependencytrack.assessmentsync.workflow.ExpandAssessmentChangesWorkflow;
import org.dependencytrack.assessmentsync.workflow.SynchronizeProjectAssessmentsWorkflow;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.proto.internal.workflow.v1.ExpandAssessmentChangesArg;
import org.dependencytrack.proto.internal.workflow.v1.ExpandAssessmentChangesRes;
import org.dependencytrack.proto.internal.workflow.v1.SynchronizeProjectAssessmentsArg;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class AssessmentSyncRelayTest extends PersistenceCapableTest {

    private static final long POLL_INTERVAL_MILLIS = 30;
    private static final int BATCH_SIZE = 2;

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    private SimpleMeterRegistry meterRegistry;
    private AssessmentSyncRelay relay;

    @BeforeEach
    void beforeEach() {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, AssessmentSyncMode.ACTIVE.name());
        meterRegistry = new SimpleMeterRegistry();
        relay = new AssessmentSyncRelay(
                workflowTest.getEngine(),
                meterRegistry,
                POLL_INTERVAL_MILLIS,
                BATCH_SIZE,
                /* maxBackoffMillis */ 5_000);
    }

    @AfterEach
    void afterEach() {
        ExpandAssessmentChangesActivity.failTerminalForTest(false);
        if (relay != null) {
            relay.close();
        }
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
        dropBookkeepingTrigger();
    }

    @Test
    void duplicateDispatchDoesNotCreateASecondActiveRun() throws Exception {
        startEngine(false);
        final long outboxId = insertProjectOutbox();
        final String instanceId = ExpandAssessmentChangesWorkflow.instanceId(outboxId);

        relay.executeCycle();
        makeDue(outboxId);
        relay.executeCycle();

        assertThat(runStatuses(instanceId)).containsExactly("CREATED");
        assertThat(concurrencyKey(instanceId)).isEqualTo(instanceId);
        final OutboxEntry row = outbox(outboxId);
        assertThat(row).isNotNull();
        assertThat(row.dispatchAttempts()).isEqualTo(2);
        assertThat(row.lastErrorCode()).isNull();
    }

    @Test
    void bookkeepingFailureLeavesTheRowAndReplayIsHarmless() throws Exception {
        startEngine(false);
        final long outboxId = insertProjectOutbox();
        final String instanceId = ExpandAssessmentChangesWorkflow.instanceId(outboxId);
        installBookkeepingTrigger();

        assertThatThrownBy(() -> relay.executeCycle()).isInstanceOf(RuntimeException.class);

        assertThat(runStatuses(instanceId)).containsExactly("CREATED");
        OutboxEntry row = outbox(outboxId);
        assertThat(row).isNotNull();
        assertThat(row.dispatchAttempts()).isZero();

        dropBookkeepingTrigger();
        relay.executeCycle();

        assertThat(runStatuses(instanceId)).containsExactly("CREATED");
        row = outbox(outboxId);
        assertThat(row).isNotNull();
        assertThat(row.dispatchAttempts()).isEqualTo(1);
    }

    @Test
    void activeInstanceConflictDoesNotDeleteTheRow() throws Exception {
        startEngine(false);
        final long outboxId = insertProjectOutbox();
        final String instanceId = ExpandAssessmentChangesWorkflow.instanceId(outboxId);
        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ExpandAssessmentChangesWorkflow.class)
                        .withWorkflowInstanceId(instanceId)
                        .withConcurrencyKey(instanceId)
                        .withArgument(ExpandAssessmentChangesArg.newBuilder()
                                .setOutboxId(outboxId)
                                .setSchemaVersion(1)
                                .build()));
        assertThat(runId).isNotNull();

        relay.executeCycle();

        assertThat(runStatuses(instanceId)).containsExactly("CREATED");
        final OutboxEntry row = outbox(outboxId);
        assertThat(row).isNotNull();
        assertThat(row.dispatchAttempts()).isEqualTo(1);
        assertThat(meterRegistry
                        .find("dt.assessment_sync.relay.dispatches")
                        .tag("outcome", "ACTIVE")
                        .tag("scope", "OUTBOX")
                        .counter())
                .isNotNull()
                .extracting(Counter::count)
                .isEqualTo(1.0);
    }

    @Test
    void terminalWorkflowFailureLeavesTheRowForRetryAfterBackoff() throws Exception {
        ExpandAssessmentChangesActivity.failTerminalForTest(true);
        startEngine(true);
        final long outboxId = insertProjectOutbox();
        final String instanceId = ExpandAssessmentChangesWorkflow.instanceId(outboxId);

        relay.executeCycle();
        final UUID failedRunId = runId(instanceId);
        workflowTest.awaitRunStatus(failedRunId, WorkflowRunStatus.FAILED);
        assertThat(outbox(outboxId)).isNotNull();

        ExpandAssessmentChangesActivity.failTerminalForTest(false);
        makeDue(outboxId);
        relay.executeCycle();

        await("retry run to finish and delete the outbox row")
                .atMost(Duration.ofSeconds(20))
                .untilAsserted(() -> {
                    assertThat(outbox(outboxId)).isNull();
                    assertThat(runStatuses(instanceId)).containsExactlyInAnyOrder("FAILED", "COMPLETED");
                });
    }

    @Test
    void unknownSchemaVersionDoesNotDeleteTheRowOrCreateARun() throws Exception {
        startEngine(false);
        final UUID projectUuid = UUID.randomUUID();
        useJdbiTransaction(handle -> {
            handle.execute("""
                    ALTER TABLE "ASSESSMENT_SYNC_OUTBOX"
                    DROP CONSTRAINT "ASSESSMENT_SYNC_OUTBOX_SCHEMA_VERSION_CHECK"
                    """);
            handle.createUpdate("""
                            INSERT INTO "ASSESSMENT_SYNC_OUTBOX" (
                              "SCHEMA_VERSION", "SCOPE_KEY", "SCOPE", "PROJECT_UUID", "REASON"
                            ) VALUES (2, :scopeKey, 'PROJECT', :projectUuid, 'SCHEMA')
                            """)
                    .bind("scopeKey", "project:" + projectUuid)
                    .bind("projectUuid", projectUuid)
                    .execute();
        });

        try {
            relay.executeCycle();

            final long runs = withJdbiHandle(handle -> handle.createQuery("""
                            SELECT COUNT(*)
                              FROM dex_workflow_run
                             WHERE workflow_name = :workflowName
                            """)
                    .bind("workflowName", ExpandAssessmentChangesWorkflow.NAME)
                    .mapTo(long.class)
                    .one());
            assertThat(runs).isZero();
            final long storedId = withJdbiHandle(
                    handle -> handle.createQuery("""
                            SELECT "ID"
                              FROM "ASSESSMENT_SYNC_OUTBOX"
                             WHERE "SCHEMA_VERSION" = 2
                            """).mapTo(long.class).one());
            final OutboxEntry stored = outbox(storedId);
            assertThat(stored).isNotNull();
            assertThat(stored.schemaVersion()).isEqualTo(2);
            assertThat(stored.lastErrorCode()).isEqualTo(AssessmentSyncSettings.UNKNOWN_SCHEMA_VERSION);
            assertThat(stored.dispatchAttempts()).isEqualTo(1);
        } finally {
            useJdbiTransaction(handle -> {
                handle.execute("""
                        DELETE FROM "ASSESSMENT_SYNC_OUTBOX" WHERE "SCHEMA_VERSION" <> 1
                        """);
                handle.execute("""
                        ALTER TABLE "ASSESSMENT_SYNC_OUTBOX"
                        ADD CONSTRAINT "ASSESSMENT_SYNC_OUTBOX_SCHEMA_VERSION_CHECK"
                        CHECK ("SCHEMA_VERSION" = 1)
                        """);
            });
        }
    }

    @Test
    void shutdownStopsFurtherPolls() throws Exception {
        startEngine(false);
        relay.start();
        relay.close();
        relay = null;

        insertProjectOutbox();

        await("no dispatch after shutdown")
                .pollDelay(Duration.ofMillis(300))
                .atMost(Duration.ofSeconds(2))
                .until(() -> withJdbiHandle(handle -> handle.createQuery("""
                                SELECT COUNT(*)
                                  FROM dex_workflow_run
                                 WHERE workflow_name = :workflowName
                                """)
                                .bind("workflowName", ExpandAssessmentChangesWorkflow.NAME)
                                .mapTo(long.class)
                                .one())
                        == 0);
    }

    @Test
    void batchSizeIsHonored() throws Exception {
        startEngine(false);
        final long first = insertProjectOutbox();
        final long second = insertProjectOutbox();
        final long third = insertProjectOutbox();

        relay.executeCycle();

        assertThat(outbox(first).dispatchAttempts()).isEqualTo(1);
        assertThat(outbox(second).dispatchAttempts()).isEqualTo(1);
        assertThat(outbox(third).dispatchAttempts()).isZero();
        final long runs = withJdbiHandle(handle -> handle.createQuery("""
                        SELECT COUNT(*)
                          FROM dex_workflow_run
                         WHERE workflow_name = :workflowName
                        """)
                .bind("workflowName", ExpandAssessmentChangesWorkflow.NAME)
                .mapTo(long.class)
                .one());
        assertThat(runs).isEqualTo(2);

        final Counter created = meterRegistry
                .find("dt.assessment_sync.relay.dispatches")
                .tag("outcome", "CREATED")
                .tag("scope", "OUTBOX")
                .counter();
        assertThat(created).isNotNull();
        assertThat(created.count()).isEqualTo(2);
        assertThat(meterRegistry.getMeters())
                .filteredOn(meter -> meter.getId().getName().startsWith("dt.assessment_sync.relay"))
                .allSatisfy(meter -> assertThat(meter.getId().getTags())
                        .extracting(Tag::getKey)
                        .allMatch(key -> key.equals("outcome") || key.equals("scope")));
        assertThat(meterRegistry.getMeters())
                .filteredOn(meter -> meter.getId().getName().startsWith("dt.assessment_sync.relay"))
                .extracting(Meter::getId)
                .allSatisfy(id ->
                        assertThat(id.getTags()).extracting(Tag::getKey).doesNotContain("uuid", "purl", "projectUuid"));
    }

    @Test
    void inactiveModesLeaveRowsPending() throws Exception {
        startEngine(false);
        final long outboxId = insertProjectOutbox();
        for (final AssessmentSyncMode mode :
                List.of(AssessmentSyncMode.CAPTURE, AssessmentSyncMode.OFF, AssessmentSyncMode.WITHDRAW)) {
            MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, mode.name());
            relay.executeCycle();
        }
        assertThat(outbox(outboxId).dispatchAttempts()).isZero();
        final long runs = withJdbiHandle(
                handle -> handle.createQuery("""
                        SELECT COUNT(*) FROM dex_workflow_run
                        """).mapTo(long.class).one());
        assertThat(runs).isZero();
    }

    @Test
    void dueWorkRowCreatesOneRunAndStaysPending() throws Exception {
        startEngine(false);
        final UUID targetUuid = UUID.randomUUID();
        useJdbiTransaction(handle -> new AssessmentSyncWorkDao(handle).requestFull(targetUuid));

        relay.executeCycle();

        final String instanceId = SynchronizeProjectAssessmentsWorkflow.instanceId(targetUuid);
        assertThat(runStatuses(instanceId)).containsExactly("CREATED");
        assertThat(concurrencyKey(instanceId)).isEqualTo(instanceId);
        final var work = withJdbiHandle(handle -> new AssessmentSyncWorkDao(handle).find(targetUuid));
        assertThat(work).isNotNull();
        assertThat(work.requestedRevision()).isEqualTo(1);
        assertThat(work.completedRevision()).isZero();
        assertThat(work.refreshCompleted()).isEqualTo(work.refreshRequested());
    }

    @Test
    void rejectsNonPositiveRelayBounds() {
        assertThatThrownBy(() -> new AssessmentSyncRelay(workflowTest.getEngine(), meterRegistry, 0, BATCH_SIZE, 5_000))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AssessmentSyncRelay(
                        workflowTest.getEngine(), meterRegistry, POLL_INTERVAL_MILLIS, 0, 5_000))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AssessmentSyncRelay(
                        workflowTest.getEngine(), meterRegistry, POLL_INTERVAL_MILLIS, BATCH_SIZE, 0))
                .isInstanceOf(IllegalArgumentException.class);
    }

    private void startEngine(final boolean workers) {
        final DexEngine engine = workflowTest.getEngine();
        engine.registerWorkflow(
                new ExpandAssessmentChangesWorkflow(),
                protoConverter(ExpandAssessmentChangesArg.class),
                voidConverter(),
                Duration.ofSeconds(10));
        engine.registerWorkflow(
                new SynchronizeProjectAssessmentsWorkflow(),
                protoConverter(SynchronizeProjectAssessmentsArg.class),
                voidConverter(),
                Duration.ofSeconds(10));
        engine.registerActivity(
                new ExpandAssessmentChangesActivity(100, 200),
                protoConverter(ExpandAssessmentChangesArg.class),
                protoConverter(ExpandAssessmentChangesRes.class));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 10));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 10));
        engine.createTaskQueue(
                new CreateTaskQueueRequest(TaskType.ACTIVITY, ExpandAssessmentChangesActivity.QUEUE_NAME, 10));
        if (workers) {
            engine.registerTaskWorker(new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 2)
                    .withMinPollInterval(Duration.ofMillis(25))
                    .withPollBackoffFunction(IntervalFunction.of(25)));
            engine.registerTaskWorker(new TaskWorkerOptions(
                            TaskType.ACTIVITY, "assessment-sync", ExpandAssessmentChangesActivity.QUEUE_NAME, 2)
                    .withMinPollInterval(Duration.ofMillis(25))
                    .withPollBackoffFunction(IntervalFunction.of(25)));
        }
        engine.start();
    }

    private static long insertProjectOutbox() {
        return inJdbiTransaction(handle -> new AssessmentSyncOutboxDao(handle)
                .record(new AssessmentChange(
                        Scope.PROJECT, UUID.randomUUID(), null, null, "PROJECT_CHANGED", List.of())));
    }

    private static OutboxEntry outbox(final long id) {
        return inJdbiTransaction(handle -> new AssessmentSyncOutboxDao(handle).lock(id));
    }

    private static void makeDue(final long id) {
        useJdbiTransaction(handle -> handle.createUpdate("""
                        UPDATE "ASSESSMENT_SYNC_OUTBOX"
                           SET "NEXT_DISPATCH_AT" = clock_timestamp() - INTERVAL '1 second'
                         WHERE "ID" = :id
                        """).bind("id", id).execute());
    }

    private static List<String> runStatuses(final String instanceId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT status
                          FROM dex_workflow_run
                         WHERE workflow_instance_id = :instanceId
                         ORDER BY created_at
                        """)
                .bind("instanceId", instanceId)
                .mapTo(String.class)
                .list());
    }

    private static UUID runId(final String instanceId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT id
                          FROM dex_workflow_run
                         WHERE workflow_instance_id = :instanceId
                         ORDER BY created_at
                         LIMIT 1
                        """)
                .bind("instanceId", instanceId)
                .mapTo(UUID.class)
                .one());
    }

    private static String concurrencyKey(final String instanceId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT concurrency_key
                          FROM dex_workflow_run
                         WHERE workflow_instance_id = :instanceId
                        """)
                .bind("instanceId", instanceId)
                .mapTo(String.class)
                .one());
    }

    private static void installBookkeepingTrigger() {
        useJdbiTransaction(handle -> {
            handle.execute("""
                    CREATE OR REPLACE FUNCTION assessment_sync_fail_dispatch_bookkeeping()
                    RETURNS trigger
                    LANGUAGE plpgsql
                    AS $$
                    BEGIN
                      RAISE EXCEPTION 'bookkeeping failed';
                    END;
                    $$
                    """);
            handle.execute("""
                    DROP TRIGGER IF EXISTS assessment_sync_fail_dispatch_bookkeeping
                      ON "ASSESSMENT_SYNC_OUTBOX"
                    """);
            handle.execute("""
                    CREATE TRIGGER assessment_sync_fail_dispatch_bookkeeping
                    BEFORE UPDATE OF "DISPATCH_ATTEMPTS" ON "ASSESSMENT_SYNC_OUTBOX"
                    FOR EACH ROW
                    EXECUTE FUNCTION assessment_sync_fail_dispatch_bookkeeping()
                    """);
        });
    }

    private static void dropBookkeepingTrigger() {
        useJdbiTransaction(handle -> {
            handle.execute("""
                    DROP TRIGGER IF EXISTS assessment_sync_fail_dispatch_bookkeeping
                      ON "ASSESSMENT_SYNC_OUTBOX"
                    """);
            handle.execute("""
                    DROP FUNCTION IF EXISTS assessment_sync_fail_dispatch_bookkeeping()
                    """);
        });
    }
}
