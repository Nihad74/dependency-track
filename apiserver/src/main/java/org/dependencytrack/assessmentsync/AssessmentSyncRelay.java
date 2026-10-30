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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

import static io.github.resilience4j.core.IntervalFunction.ofExponentialRandomBackoff;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;

/// Dispatches due outbox rows and unfinished target work. Rows stay until activities finish them.
final class AssessmentSyncRelay implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(AssessmentSyncRelay.class);
    private static final String EXECUTOR_NAME = "AssessmentSyncRelay";
    private static final String OUTCOME_TAG = "outcome";
    private static final String SCOPE_TAG = "scope";

    /// Distinct from the notification relay lock.
    private static final long RELAY_ADVISORY_LOCK_ID = 418263950172846531L;

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
            final DexEngine dexEngine, final MeterRegistry meterRegistry, final AssessmentSyncSettings settings) {
        this.dexEngine = dexEngine;
        this.meterRegistry = meterRegistry;
        this.pollIntervalMillis = settings.pollIntervalMillis();
        this.batchSize = settings.relayBatchSize();
        this.backoffIntervalFunction =
                ofExponentialRandomBackoff(settings.pollIntervalMillis(), 1.5, settings.maxBackoffMillis());
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
        final CycleOutcome outcome;
        try {
            outcome = dispatchDue();
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

    /// Active mode dispatches outbox rows and all target work. Withdrawal dispatches only targets with a
    /// refresh pending, so policy and metrics catch up with withdrawn rows. Other modes dispatch nothing.
    private CycleOutcome dispatchDue() throws InterruptedException {
        throwIfInterrupted();
        final AssessmentSyncMode mode = AssessmentSyncMode.current();
        final boolean active = mode.appliesAssessments();
        if (!active && mode != AssessmentSyncMode.WITHDRAW) {
            LOGGER.debug("Assessment sync relay skipped because mode is {}", mode);
            return CycleOutcome.SKIPPED;
        }
        final DispatchResult outbox = active ? dispatchOutbox() : DispatchResult.skipped();
        recordDispatches(DispatchScope.OUTBOX, outbox);
        throwIfInterrupted();
        final DispatchResult work = dispatchWork(active);
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

    private DispatchResult dispatchOutbox() {
        return inJdbiTransaction(handle -> {
            if (!AdvisoryLocks.tryAcquire(handle, RELAY_ADVISORY_LOCK_ID)) {
                LOGGER.debug("Assessment sync relay lock is already held");
                return DispatchResult.skipped();
            }
            final var outboxDao = new AssessmentSyncOutboxDao(handle);
            final List<OutboxEntry> due = outboxDao.pollDue(batchSize);
            final var requests = new ArrayList<CreateWorkflowRunRequest<?>>(due.size());
            final var pending = new ArrayList<Dispatch<Long>>(due.size());
            for (final OutboxEntry entry : due) {
                final String instanceId = ExpandAssessmentChangesWorkflow.instanceId(entry.id());
                final var request = new CreateWorkflowRunRequest<>(ExpandAssessmentChangesWorkflow.class)
                        .withWorkflowInstanceId(instanceId)
                        .withConcurrencyKey(instanceId)
                        .withArgument(ExpandAssessmentChangesArg.newBuilder()
                                .setOutboxId(entry.id())
                                .build());
                requests.add(request);
                pending.add(new Dispatch<>(entry.id(), entry.dispatchAttempts(), request.requestId()));
            }
            final Set<UUID> createdRequestIds = createdRequestIds(requests);
            final var nextDispatchAts = new LinkedHashMap<Long, Instant>(pending.size());
            var created = 0;
            for (final Dispatch<Long> dispatch : pending) {
                nextDispatchAts.put(dispatch.key(), nextDispatchAt(dispatch.attempts()));
                if (createdRequestIds.contains(dispatch.requestId())) {
                    created++;
                }
            }
            outboxDao.recordDispatchAttempts(nextDispatchAts);
            return DispatchResult.completed(created, pending.size() - created);
        });
    }

    private DispatchResult dispatchWork(final boolean includeReconciliation) {
        return inJdbiTransaction(handle -> {
            if (!AdvisoryLocks.tryAcquire(handle, RELAY_ADVISORY_LOCK_ID)) {
                LOGGER.debug("Assessment sync relay lock is already held");
                return DispatchResult.skipped();
            }
            final var workDao = new AssessmentSyncWorkDao(handle);
            final List<WorkRow> due = workDao.pollDue(batchSize, includeReconciliation);
            final var requests = new ArrayList<CreateWorkflowRunRequest<?>>(due.size());
            final var pending = new ArrayList<Dispatch<UUID>>(due.size());
            for (final WorkRow row : due) {
                final String instanceId = SynchronizeProjectAssessmentsWorkflow.instanceId(row.targetUuid());
                final var request = new CreateWorkflowRunRequest<>(SynchronizeProjectAssessmentsWorkflow.class)
                        .withWorkflowInstanceId(instanceId)
                        .withConcurrencyKey(instanceId)
                        .withArgument(SynchronizeProjectAssessmentsArg.newBuilder()
                                .setProjectUuid(row.targetUuid().toString())
                                .build());
                requests.add(request);
                pending.add(new Dispatch<>(row.targetUuid(), row.dispatchAttempts(), request.requestId()));
            }
            final Set<UUID> createdRequestIds = createdRequestIds(requests);
            final var nextDispatchAts = new LinkedHashMap<UUID, Instant>(pending.size());
            var created = 0;
            for (final Dispatch<UUID> dispatch : pending) {
                nextDispatchAts.put(dispatch.key(), nextDispatchAt(dispatch.attempts()));
                if (createdRequestIds.contains(dispatch.requestId())) {
                    created++;
                }
            }
            // The run being accepted is not acknowledgement. Reconciliation completes the work row.
            workDao.recordDispatchAttempts(nextDispatchAts);
            return DispatchResult.completed(created, pending.size() - created);
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

    private void recordDispatches(final DispatchScope scope, final DispatchResult scan) {
        increment(DispatchOutcome.CREATED, scope, scan.created());
        increment(DispatchOutcome.ACTIVE, scope, scan.active());
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
        ACTIVE
    }

    private enum DispatchScope {
        OUTBOX,
        WORK
    }

    private record DispatchResult(boolean skippedLock, int created, int active) {

        private static DispatchResult skipped() {
            return new DispatchResult(true, 0, 0);
        }

        private static DispatchResult completed(final int created, final int active) {
            return new DispatchResult(false, created, active);
        }
    }

    /// One submitted run. {@code key} is the outbox id or the target UUID.
    private record Dispatch<K>(K key, int attempts, UUID requestId) {}
}
