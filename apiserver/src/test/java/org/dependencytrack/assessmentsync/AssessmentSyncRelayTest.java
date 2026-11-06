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
import org.dependencytrack.assessmentsync.AssessmentChange.Reason;
import org.dependencytrack.assessmentsync.AssessmentChange.Scope;
import org.dependencytrack.assessmentsync.AssessmentSyncOutboxDao.OutboxEntry;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao.WorkRow;
import org.dependencytrack.assessmentsync.workflow.ExpandAssessmentChangesActivity;
import org.dependencytrack.assessmentsync.workflow.ExpandAssessmentChangesWorkflow;
import org.dependencytrack.assessmentsync.workflow.SynchronizeProjectAssessmentsWorkflow;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
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
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.persistence.jdbi.AdvisoryLocks.tryAcquire;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AssessmentSyncRelayTest extends PersistenceCapableTest {

    private static final long POLL_INTERVAL_MILLIS = 30;
    private static final int BATCH_SIZE = 2;

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    private final AtomicBoolean expandFailsTerminally = new AtomicBoolean();
    private SimpleMeterRegistry meterRegistry;
    private AssessmentSyncRelay relay;

    @BeforeEach
    void beforeEach() {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, AssessmentSyncMode.ACTIVE.name());
        meterRegistry = new SimpleMeterRegistry();
        relay = new AssessmentSyncRelay(
                workflowTest.getEngine(),
                meterRegistry,
                new AssessmentSyncSettings(
                        POLL_INTERVAL_MILLIS, BATCH_SIZE, /* maxBackoffMillis */ 5_000, 100, 200, 50));
    }

    @AfterEach
    void afterEach() {
        if (relay != null) {
            relay.close();
        }
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
        dropBookkeepingTrigger();
        meterRegistry.close();
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
        expandFailsTerminally.set(true);
        startEngine(true);
        final long outboxId = insertProjectOutbox();
        final String instanceId = ExpandAssessmentChangesWorkflow.instanceId(outboxId);

        relay.executeCycle();
        final UUID failedRunId = runId(instanceId);
        workflowTest.awaitRunStatus(failedRunId, WorkflowRunStatus.FAILED);
        assertThat(outbox(outboxId)).isNotNull();

        expandFailsTerminally.set(false);
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
    void shutdownDoesNotWaitForTheNextDelayedPoll() throws Exception {
        relay.close();
        relay = new AssessmentSyncRelay(
                workflowTest.getEngine(),
                meterRegistry,
                new AssessmentSyncSettings(60_000, BATCH_SIZE, 60_000, 100, 200, 50));
        relay.start();
        try (final var closer = Executors.newVirtualThreadPerTaskExecutor()) {
            final var closed = closer.submit(relay::close);
            try {
                closed.get(1, TimeUnit.SECONDS);
            } finally {
                // Also release a buggy executor that waits for its delayed task, so a red test is bounded.
                closed.cancel(true);
            }
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void rejectedWorkflowSubmissionIsRetriedByTheScheduler(final boolean acceptedBeforeRejection) throws Exception {
        startEngine(false);
        final long outboxId = insertProjectOutbox();
        final var engine = mock(DexEngine.class);
        final var calls = new AtomicInteger();
        when(engine.createRuns(any())).thenAnswer(invocation -> {
            if (calls.incrementAndGet() == 1) {
                if (acceptedBeforeRejection) {
                    workflowTest.getEngine().createRuns(invocation.getArgument(0));
                }
                throw new RejectedExecutionException("temporary workflow submission rejection");
            }
            return workflowTest.getEngine().createRuns(invocation.getArgument(0));
        });
        relay.close();
        relay = new AssessmentSyncRelay(
                engine,
                meterRegistry,
                new AssessmentSyncSettings(POLL_INTERVAL_MILLIS, BATCH_SIZE, 5_000, 100, 200, 50));
        relay.start();
        await("polling resumes after a rejected workflow submission")
                .atMost(Duration.ofSeconds(3))
                .untilAsserted(
                        () -> assertThat(outbox(outboxId).dispatchAttempts()).isPositive());
        assertThat(calls.get()).isGreaterThanOrEqualTo(2);
        assertThat(runStatuses(ExpandAssessmentChangesWorkflow.instanceId(outboxId)))
                .containsExactly("CREATED");
    }

    @Test
    void interruptionSkipsTheCycleAndRecordsMatchingCounterAndTimer() {
        Thread.currentThread().interrupt();
        try {
            assertThatThrownBy(relay::executeCycle).isInstanceOf(InterruptedException.class);
        } finally {
            Thread.interrupted();
        }
        assertThat(meterRegistry
                        .get("dt.assessment_sync.relay.cycles")
                        .tag("outcome", "SKIPPED")
                        .counter()
                        .count())
                .isEqualTo(1);
        assertThat(meterRegistry
                        .get("dt.assessment_sync.relay.cycle.latency")
                        .tag("outcome", "SKIPPED")
                        .timer()
                        .count())
                .isEqualTo(1);
        assertThat(runCount()).isZero();
    }

    @Test
    void anotherRelayHoldingTheClusterLockSkipsBothScopesWithoutBookkeeping() throws Exception {
        final long id = insertProjectOutbox();
        final var target = UUID.randomUUID();
        useJdbiTransaction(h -> new AssessmentSyncWorkDao(h).requestFull(target));
        try (final var holder = openJdbiHandle()) {
            holder.begin();
            assertThat(tryAcquire(holder, 418263950172846531L)).isTrue();
            relay.executeCycle();
            assertThat(outbox(id).dispatchAttempts()).isZero();
            assertThat(work(target).dispatchAttempts()).isZero();
            assertThat(runCount()).isZero();
            assertThat(meterRegistry
                            .get("dt.assessment_sync.relay.cycles")
                            .tag("outcome", "SKIPPED")
                            .counter()
                            .count())
                    .isEqualTo(1);
            holder.rollback();
        }
    }

    @Test
    void mixedCreatedAndActiveOutboxBatchKeepsBothRowsAndCountsEachOutcome() throws Exception {
        startEngine(false);
        final long active = insertProjectOutbox();
        final long created = insertProjectOutbox();
        final String instanceId = ExpandAssessmentChangesWorkflow.instanceId(active);
        workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ExpandAssessmentChangesWorkflow.class)
                        .withWorkflowInstanceId(instanceId)
                        .withConcurrencyKey(instanceId)
                        .withArgument(ExpandAssessmentChangesArg.newBuilder()
                                .setOutboxId(active)
                                .build()));
        relay.executeCycle();
        for (final long id : List.of(active, created)) {
            assertThat(outbox(id).dispatchAttempts()).isEqualTo(1);
            assertThat(runStatuses(ExpandAssessmentChangesWorkflow.instanceId(id)))
                    .containsExactly("CREATED");
        }
        for (final String outcome : List.of("CREATED", "ACTIVE")) {
            assertThat(meterRegistry
                            .get("dt.assessment_sync.relay.dispatches")
                            .tag("scope", "OUTBOX")
                            .tag("outcome", outcome)
                            .counter()
                            .count())
                    .isEqualTo(1);
        }
    }

    @Test
    void shutdownInterruptsAnActiveSubmissionAndDoesNotRetryIt() throws Exception {
        final long id = insertProjectOutbox();
        final var engine = mock(DexEngine.class);
        final var entered = new CountDownLatch(1);
        final var release = new CountDownLatch(1);
        final var calls = new AtomicInteger();
        when(engine.createRuns(any())).thenAnswer(invocation -> {
            calls.incrementAndGet();
            entered.countDown();
            try {
                release.await();
                return List.of();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IllegalStateException("submission interrupted", e);
            }
        });
        relay.close();
        relay = new AssessmentSyncRelay(
                engine,
                meterRegistry,
                new AssessmentSyncSettings(POLL_INTERVAL_MILLIS, BATCH_SIZE, 5_000, 100, 200, 50));
        relay.start();
        try {
            assertThat(entered.await(3, TimeUnit.SECONDS)).isTrue();
            try (final var closer = Executors.newVirtualThreadPerTaskExecutor()) {
                final var closed = closer.submit(relay::close);
                try {
                    closed.get(2, TimeUnit.SECONDS);
                } finally {
                    release.countDown();
                    closed.cancel(true);
                }
            }
        } finally {
            release.countDown();
        }
        assertThat(calls).hasValue(1);
        assertThat(outbox(id).dispatchAttempts()).isZero();
        assertThat(runCount()).isZero();
        assertThat(meterRegistry
                        .get("dt.assessment_sync.relay.cycles")
                        .tag("outcome", "SKIPPED")
                        .counter()
                        .count())
                .isEqualTo(1);
        assertThat(meterRegistry
                        .find("dt.assessment_sync.relay.cycles")
                        .tag("outcome", "FAILED")
                        .counter())
                .isNull();
    }

    @Test
    void startingTwiceIsRejectedAndClosingTwiceIsHarmless() {
        relay.close();
        relay = new AssessmentSyncRelay(
                workflowTest.getEngine(),
                meterRegistry,
                new AssessmentSyncSettings(60_000, BATCH_SIZE, 60_000, 100, 200, 50));
        relay.start();
        assertThatThrownBy(relay::start)
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Already started");
        relay.close();
        relay.close();
    }

    @Test
    void busyOutboxRowsUseIncreasingDispatchBackoff() throws Exception {
        startEngine(false);
        final long id = insertProjectOutbox();
        Instant before = Instant.now();
        for (int i = 0; i < 6; i++) {
            makeDue(id);
            before = Instant.now();
            relay.executeCycle();
        }
        assertThat(outbox(id).dispatchAttempts()).isEqualTo(6);
        assertThat(Duration.between(before, outbox(id).nextDispatchAt())).isGreaterThan(Duration.ofMillis(100));
        assertThat(runStatuses(ExpandAssessmentChangesWorkflow.instanceId(id))).containsExactly("CREATED");
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
    void captureAndOffDispatchNothing() throws Exception {
        startEngine(false);
        final long outboxId = insertProjectOutbox();
        final UUID targetUuid = UUID.randomUUID();
        useJdbiTransaction(handle -> {
            final var workDao = new AssessmentSyncWorkDao(handle);
            workDao.requestFull(targetUuid);
            workDao.requestRefresh(targetUuid);
        });
        for (final AssessmentSyncMode mode : List.of(AssessmentSyncMode.CAPTURE, AssessmentSyncMode.OFF)) {
            MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, mode.name());
            relay.executeCycle();
        }
        assertThat(outbox(outboxId).dispatchAttempts()).isZero();
        assertThat(work(targetUuid).dispatchAttempts()).isZero();
        assertThat(runCount()).isZero();
    }

    @Test
    void withdrawalDispatchesOnlyTargetsWithARefreshPending() throws Exception {
        startEngine(false);
        final long outboxId = insertProjectOutbox();
        final UUID refreshTarget = UUID.randomUUID();
        final UUID reconcileTarget = UUID.randomUUID();
        useJdbiTransaction(handle -> {
            final var workDao = new AssessmentSyncWorkDao(handle);
            workDao.requestRefresh(refreshTarget);
            workDao.requestFull(reconcileTarget);
        });
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, AssessmentSyncMode.WITHDRAW.name());

        relay.executeCycle();

        assertThat(runStatuses(SynchronizeProjectAssessmentsWorkflow.instanceId(refreshTarget)))
                .containsExactly("CREATED");
        assertThat(runStatuses(SynchronizeProjectAssessmentsWorkflow.instanceId(reconcileTarget)))
                .isEmpty();
        assertThat(outbox(outboxId).dispatchAttempts()).isZero();
    }

    @Test
    void redispatchingABusyTargetCreatesNoSecondRun() throws Exception {
        startEngine(false);
        final UUID targetUuid = UUID.randomUUID();
        useJdbiTransaction(handle -> new AssessmentSyncWorkDao(handle).requestFull(targetUuid));
        relay.executeCycle();
        useJdbiTransaction(handle -> new AssessmentSyncWorkDao(handle).scheduleDispatch(targetUuid, Instant.now()));

        relay.executeCycle();

        assertThat(runStatuses(SynchronizeProjectAssessmentsWorkflow.instanceId(targetUuid)))
                .containsExactly("CREATED");
        assertThat(work(targetUuid).dispatchAttempts()).isEqualTo(2);
    }

    private static long runCount() {
        return withJdbiHandle(
                handle -> handle.createQuery("""
                        SELECT COUNT(*) FROM dex_workflow_run
                        """).mapTo(long.class).one());
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
    void workWithOnlyARefreshPendingIsDispatched() throws Exception {
        startEngine(false);
        final UUID targetUuid = UUID.randomUUID();
        useJdbiTransaction(handle -> new AssessmentSyncWorkDao(handle).requestRefresh(targetUuid));

        relay.executeCycle();

        assertThat(runStatuses(SynchronizeProjectAssessmentsWorkflow.instanceId(targetUuid)))
                .containsExactly("CREATED");
    }

    @Test
    void finishedWorkIsNotDispatched() throws Exception {
        startEngine(false);
        final UUID targetUuid = UUID.randomUUID();
        useJdbiTransaction(handle -> {
            final var workDao = new AssessmentSyncWorkDao(handle);
            workDao.requestFull(targetUuid);
            workDao.requestRefresh(targetUuid);
            workDao.acknowledgeCancellation(targetUuid);
        });

        relay.executeCycle();

        assertThat(runStatuses(SynchronizeProjectAssessmentsWorkflow.instanceId(targetUuid)))
                .isEmpty();
    }

    @Test
    void targetWhoseRunsKeepEndingWithoutProgressIsDispatchedLessOften() throws Exception {
        startEngine(true);
        final UUID targetUuid = UUID.randomUUID();
        useJdbiTransaction(handle -> new AssessmentSyncWorkDao(handle).requestFull(targetUuid));

        final Duration delay = dispatchAndEndWithoutProgress(targetUuid, 6);

        assertThat(runStatuses(SynchronizeProjectAssessmentsWorkflow.instanceId(targetUuid)))
                .hasSize(6);
        // Six runs at 1.5x from a 30 ms base, minus at most half for jitter, wait at least 113 ms.
        assertThat(delay).isGreaterThan(Duration.ofMillis(100));
    }

    @Test
    void progressResetsTheDispatchDelayOfATarget() throws Exception {
        startEngine(true);
        final UUID targetUuid = UUID.randomUUID();
        useJdbiTransaction(handle -> new AssessmentSyncWorkDao(handle).requestFull(targetUuid));
        dispatchAndEndWithoutProgress(targetUuid, 6);
        useJdbiTransaction(handle -> {
            final var workDao = new AssessmentSyncWorkDao(handle);
            workDao.acknowledgeCancellation(targetUuid);
            workDao.requestFull(targetUuid);
        });

        relay.executeCycle();
        final Instant afterCycle = Instant.now();

        final WorkRow work = work(targetUuid);
        assertThat(work.dispatchAttempts()).isEqualTo(1);
        // One first step from a 30 ms base with at most 50% jitter, counted from the dispatch inside the cycle.
        assertThat(work.nextDispatchAt()).isBefore(afterCycle.plusMillis(45));
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
                new ExpandAssessmentChangesActivity(100, 200, () -> {
                    if (expandFailsTerminally.get()) {
                        throw new TerminalApplicationFailureException("assessment expansion failed");
                    }
                }),
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
                .recordAll(List.of(new AssessmentChange(
                        Scope.PROJECT, UUID.randomUUID(), null, null, Reason.PROJECT_UPDATED, List.of())))
                .getFirst());
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

    /**
     * Each run fails because the reconcile activity is not registered.
     * Returns how long the relay waits after the last dispatch.
     */
    private Duration dispatchAndEndWithoutProgress(final UUID targetUuid, final int runs) throws Exception {
        final String instanceId = SynchronizeProjectAssessmentsWorkflow.instanceId(targetUuid);
        Duration delay = Duration.ZERO;
        for (int i = 0; i < runs; i++) {
            makeWorkDue(targetUuid);
            final Instant before = Instant.now();
            relay.executeCycle();
            delay = Duration.between(before, work(targetUuid).nextDispatchAt());
            workflowTest.awaitRunStatus(latestRunId(instanceId), WorkflowRunStatus.FAILED);
        }
        return delay;
    }

    private static WorkRow work(final UUID targetUuid) {
        return withJdbiHandle(handle -> new AssessmentSyncWorkDao(handle).find(targetUuid));
    }

    private static void makeWorkDue(final UUID targetUuid) {
        useJdbiTransaction(handle ->
                handle.createUpdate("""
                        UPDATE "ASSESSMENT_SYNC_WORK"
                           SET "NEXT_DISPATCH_AT" = clock_timestamp() - INTERVAL '1 second'
                         WHERE "TARGET_UUID" = :targetUuid
                        """).bind("targetUuid", targetUuid).execute());
    }

    private static UUID latestRunId(final String instanceId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT id
                          FROM dex_workflow_run
                         WHERE workflow_instance_id = :instanceId
                         ORDER BY created_at DESC
                         LIMIT 1
                        """)
                .bind("instanceId", instanceId)
                .mapTo(UUID.class)
                .one());
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
