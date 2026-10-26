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
import io.micrometer.core.instrument.Meter.MeterProvider;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.binder.jvm.ExecutorServiceMetrics;
import org.apache.commons.lang3.concurrent.BasicThreadFactory;
import org.dependencytrack.assessmentsync.AssessmentSyncOutboxDao.OutboxEntry;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao.WorkRow;
import org.dependencytrack.assessmentsync.workflow.ExpandAssessmentChangesWorkflow;
import org.dependencytrack.assessmentsync.workflow.SynchronizeProjectAssessmentsWorkflow;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.response.CreateWorkflowRunResponse;
import org.dependencytrack.persistence.jdbi.AdvisoryLocks;
import org.dependencytrack.proto.internal.workflow.v1.ExpandAssessmentChangesArg;
import org.dependencytrack.proto.internal.workflow.v1.SynchronizeProjectAssessmentsArg;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static io.github.resilience4j.core.IntervalFunction.ofExponentialRandomBackoff;
import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;

/// Dispatches due outbox rows and unfinished target work. Rows stay until activities finish them.
final class AssessmentSyncRelay implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(AssessmentSyncRelay.class);
    private static final String EXECUTOR_NAME = "AssessmentSyncRelay";
    private static final String OUTCOME_TAG = "outcome";
    private static final String SCOPE_TAG = "scope";

    private final DexEngine dexEngine;
    private final MeterRegistry meterRegistry;
    private final long pollIntervalMillis;
    private final int batchSize;
    private final IntervalFunction backoffIntervalFunction;
    private final MeterProvider<Timer> cycleLatencyTimer;
    private final MeterProvider<Counter> cycleCounter;
    private final MeterProvider<Counter> dispatchCounter;
    private @Nullable ScheduledExecutorService executorService;

    AssessmentSyncRelay(
            final DexEngine dexEngine,
            final MeterRegistry meterRegistry,
            final long pollIntervalMillis,
            final int batchSize,
            final long maxBackoffMillis) {
        this.dexEngine = requireNonNull(dexEngine, "dexEngine must not be null");
        this.meterRegistry = requireNonNull(meterRegistry, "meterRegistry must not be null");
        if (pollIntervalMillis <= 0) {
            throw new IllegalArgumentException("pollIntervalMillis must be positive");
        }
        if (batchSize <= 0) {
            throw new IllegalArgumentException("batchSize must be positive");
        }
        if (maxBackoffMillis <= 0) {
            throw new IllegalArgumentException("maxBackoffMillis must be positive");
        }
        if (maxBackoffMillis < pollIntervalMillis) {
            throw new IllegalArgumentException("maxBackoffMillis must be greater than or equal to pollIntervalMillis");
        }
        this.pollIntervalMillis = pollIntervalMillis;
        this.batchSize = batchSize;
        this.backoffIntervalFunction = ofExponentialRandomBackoff(pollIntervalMillis, 1.5, maxBackoffMillis);
        this.cycleLatencyTimer = Timer.builder("dt.assessment_sync.relay.cycle.latency")
                .description("Latency of an assessment sync relay cycle")
                .withRegistry(meterRegistry);
        this.cycleCounter = Counter.builder("dt.assessment_sync.relay.cycles")
                .description("Number of assessment sync relay cycles")
                .withRegistry(meterRegistry);
        this.dispatchCounter = Counter.builder("dt.assessment_sync.relay.dispatches")
                .description("Assessment sync workflow runs submitted by the relay")
                .withRegistry(meterRegistry);
    }

    void start() {
        if (executorService != null) {
            throw new IllegalStateException("Already started");
        }
        executorService = Executors.newSingleThreadScheduledExecutor(BasicThreadFactory.builder()
                .uncaughtExceptionHandler((thread, throwable) ->
                        LOGGER.error("Uncaught exception in thread {}", thread.getName(), throwable))
                .namingPattern(EXECUTOR_NAME + "-%d")
                .build());
        new ExecutorServiceMetrics(executorService, EXECUTOR_NAME, List.of()).bindTo(meterRegistry);
        var _ = executorService.schedule(() -> run(0), pollIntervalMillis, TimeUnit.MILLISECONDS);
    }

    @Override
    public void close() {
        if (executorService != null) {
            executorService.close();
            executorService = null;
        }
    }

    /// One poll. Visible to tests so a cycle can run without waiting for the scheduler.
    void executeCycle() throws InterruptedException {
        final Timer.Sample cycleLatencySample = Timer.start();
        CycleOutcome outcome = CycleOutcome.FAILED;
        try {
            outcome = dispatchBoth();
        } catch (InterruptedException e) {
            cycleLatencySample.stop(cycleLatencyTimer.withTag(OUTCOME_TAG, CycleOutcome.SKIPPED.name()));
            throw e;
        } catch (RuntimeException e) {
            recordCycle(CycleOutcome.FAILED, cycleLatencySample);
            throw e;
        }
        recordCycle(outcome, cycleLatencySample);
    }

    private void run(final int failureBackoffCount) {
        final ScheduledExecutorService executor = this.executorService;
        if (executor == null) {
            LOGGER.debug("Relay was closed; skipping cycle");
            return;
        }

        try {
            executeCycle();
            var _ = executor.schedule(() -> run(0), pollIntervalMillis, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            LOGGER.debug("Assessment sync relay interrupted");
            Thread.currentThread().interrupt();
        } catch (RejectedExecutionException e) {
            LOGGER.debug("Next poll could not be scheduled, likely because the executor was shut down", e);
        } catch (Throwable t) {
            if (Thread.currentThread().isInterrupted()) {
                LOGGER.debug("Assessment sync relay interrupted", t);
                Thread.currentThread().interrupt();
                return;
            }
            final long backoffDelayMillis = backoffIntervalFunction.apply(failureBackoffCount + 1);
            LOGGER.error("Failed to relay assessment sync work, backing off for {}ms", backoffDelayMillis, t);
            var _ = executor.schedule(() -> run(failureBackoffCount + 1), backoffDelayMillis, TimeUnit.MILLISECONDS);
        }
    }

    private CycleOutcome dispatchBoth() throws InterruptedException {
        throwIfInterrupted();
        if (AssessmentSyncMode.current() != AssessmentSyncMode.ACTIVE) {
            LOGGER.debug("Assessment sync relay skipped because mode is {}", AssessmentSyncMode.current());
            return CycleOutcome.SKIPPED;
        }
        final Scan outbox = dispatchOutbox();
        recordDispatches(DispatchScope.OUTBOX, outbox);
        throwIfInterrupted();
        final Scan work = dispatchWork();
        recordDispatches(DispatchScope.WORK, work);
        if (outbox.skippedLock() && work.skippedLock()) {
            return CycleOutcome.SKIPPED;
        }
        return CycleOutcome.COMPLETED;
    }

    private void recordCycle(final CycleOutcome outcome, final Timer.Sample cycleLatencySample) {
        cycleCounter.withTag(OUTCOME_TAG, outcome.name()).increment();
        cycleLatencySample.stop(cycleLatencyTimer.withTag(OUTCOME_TAG, outcome.name()));
    }

    private Scan dispatchOutbox() {
        return inJdbiTransaction(handle -> {
            if (!AdvisoryLocks.tryAcquire(handle, AssessmentSyncSettings.RELAY_ADVISORY_LOCK_ID)) {
                LOGGER.debug("Assessment sync relay lock is already held");
                return Scan.skipped();
            }
            final var outboxDao = new AssessmentSyncOutboxDao(handle);
            final List<OutboxEntry> due = outboxDao.pollDue(batchSize);
            final var requests = new ArrayList<CreateWorkflowRunRequest<?>>(due.size());
            final var pending = new ArrayList<OutboxDispatch>(due.size());
            var blocked = 0;
            for (final OutboxEntry entry : due) {
                if (entry.schemaVersion() != AssessmentSyncSettings.SUPPORTED_SCHEMA_VERSION) {
                    outboxDao.recordDispatchAttempt(
                            entry.id(),
                            nextDispatchAt(entry.dispatchAttempts()),
                            AssessmentSyncSettings.UNKNOWN_SCHEMA_VERSION);
                    LOGGER.warn(
                            "Retaining assessment outbox row {} with unsupported schema version {}",
                            entry.id(),
                            entry.schemaVersion());
                    blocked++;
                    continue;
                }
                final String instanceId = ExpandAssessmentChangesWorkflow.instanceId(entry.id());
                final var request = new CreateWorkflowRunRequest<>(ExpandAssessmentChangesWorkflow.class)
                        .withWorkflowInstanceId(instanceId)
                        .withConcurrencyKey(instanceId)
                        .withArgument(ExpandAssessmentChangesArg.newBuilder()
                                .setOutboxId(entry.id())
                                .setSchemaVersion(entry.schemaVersion())
                                .build());
                requests.add(request);
                pending.add(new OutboxDispatch(entry.id(), entry.dispatchAttempts(), request.requestId()));
            }
            final Set<UUID> createdRequestIds = createdRequestIds(requests);
            var created = 0;
            var active = 0;
            for (final OutboxDispatch dispatch : pending) {
                outboxDao.recordDispatchAttempt(dispatch.id(), nextDispatchAt(dispatch.attempts()), null);
                if (createdRequestIds.contains(dispatch.requestId())) {
                    created++;
                } else {
                    active++;
                }
            }
            return Scan.completed(created, active, blocked);
        });
    }

    private Scan dispatchWork() {
        return inJdbiTransaction(handle -> {
            if (!AdvisoryLocks.tryAcquire(handle, AssessmentSyncSettings.RELAY_ADVISORY_LOCK_ID)) {
                LOGGER.debug("Assessment sync relay lock is already held");
                return Scan.skipped();
            }
            final var workDao = new AssessmentSyncWorkDao(handle);
            final List<WorkRow> due = workDao.pollDue(batchSize);
            final var requests = new ArrayList<CreateWorkflowRunRequest<?>>(due.size());
            final var pending = new ArrayList<WorkDispatch>(due.size());
            for (final WorkRow row : due) {
                final String instanceId = SynchronizeProjectAssessmentsWorkflow.instanceId(row.targetUuid());
                final var request = new CreateWorkflowRunRequest<>(SynchronizeProjectAssessmentsWorkflow.class)
                        .withWorkflowInstanceId(instanceId)
                        .withConcurrencyKey(instanceId)
                        .withArgument(SynchronizeProjectAssessmentsArg.newBuilder()
                                .setProjectUuid(row.targetUuid().toString())
                                .build());
                requests.add(request);
                pending.add(new WorkDispatch(row.targetUuid(), request.requestId()));
            }
            final Set<UUID> createdRequestIds = createdRequestIds(requests);
            var created = 0;
            var active = 0;
            for (final WorkDispatch dispatch : pending) {
                // The run being accepted is not acknowledgement. Task 7 completes the work row.
                workDao.scheduleDispatch(dispatch.targetUuid(), nextDispatchAt(0), null);
                if (createdRequestIds.contains(dispatch.requestId())) {
                    created++;
                } else {
                    active++;
                }
            }
            return Scan.completed(created, active, 0);
        });
    }

    private Set<UUID> createdRequestIds(final List<CreateWorkflowRunRequest<?>> requests) {
        if (requests.isEmpty()) {
            return Set.of();
        }
        final List<CreateWorkflowRunResponse> created = dexEngine.createRuns(requests);
        final var createdRequestIds = new HashSet<UUID>(created.size());
        for (final CreateWorkflowRunResponse response : created) {
            createdRequestIds.add(response.requestId());
        }
        return createdRequestIds;
    }

    private Instant nextDispatchAt(final int attemptsSoFar) {
        return Instant.now().plusMillis(backoffIntervalFunction.apply(attemptsSoFar + 1));
    }

    private void recordDispatches(final DispatchScope scope, final Scan scan) {
        increment(DispatchOutcome.CREATED, scope, scan.created());
        increment(DispatchOutcome.ACTIVE, scope, scan.active());
        increment(DispatchOutcome.BLOCKED, scope, scan.blocked());
    }

    private void increment(final DispatchOutcome outcome, final DispatchScope scope, final int count) {
        if (count <= 0) {
            return;
        }
        dispatchCounter
                .withTags(List.of(Tag.of(OUTCOME_TAG, outcome.name()), Tag.of(SCOPE_TAG, scope.name())))
                .increment(count);
    }

    private static void throwIfInterrupted() throws InterruptedException {
        if (Thread.interrupted()) {
            throw new InterruptedException("Assessment sync relay interrupted");
        }
    }

    private enum CycleOutcome {
        COMPLETED,
        FAILED,
        SKIPPED
    }

    private enum DispatchOutcome {
        CREATED,
        ACTIVE,
        BLOCKED
    }

    private enum DispatchScope {
        OUTBOX,
        WORK
    }

    private record Scan(boolean skippedLock, int created, int active, int blocked) {

        private static Scan skipped() {
            return new Scan(true, 0, 0, 0);
        }

        private static Scan completed(final int created, final int active, final int blocked) {
            return new Scan(false, created, active, blocked);
        }
    }

    private record OutboxDispatch(long id, int attempts, UUID requestId) {}

    private record WorkDispatch(UUID targetUuid, UUID requestId) {}
}
