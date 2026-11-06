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
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.analysis.AnalyzeProjectWorkflow;
import org.dependencytrack.assessmentsync.AssessmentMutationGuard;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao.WorkRow;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRunMetadata;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.engine.api.request.ListWorkflowRunsRequest;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.metrics.MetricsDao;
import org.dependencytrack.metrics.UpdateProjectMetricsActivity;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.policy.EvalProjectPoliciesActivity;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.dependencytrack.proto.internal.workflow.v1.AssessmentSyncPendingRes;
import org.dependencytrack.proto.internal.workflow.v1.EvalProjectPoliciesArg;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileProjectAssessmentsRes;
import org.dependencytrack.proto.internal.workflow.v1.RefreshSynchronizedAssessmentsArg;
import org.dependencytrack.proto.internal.workflow.v1.SynchronizeProjectAssessmentsArg;
import org.dependencytrack.proto.internal.workflow.v1.UpdateProjectMetricsArg;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.jdbi.v3.core.Handle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;

class AssessmentRefreshWorkflowTest extends PersistenceCapableTest {

    private static final ActivityContext CONTEXT = () -> UUID.randomUUID();

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    @BeforeEach
    void enableActiveMode() {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "ACTIVE");
    }

    @AfterEach
    void clearMode() {
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_WORKFLOW_MAX_BATCHES);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void policyOrMetricsFailureKeepsRefreshPendingAndAFreshRunRecovers(final boolean failMetrics) throws Exception {
        final UUID project = projectUuid();
        useJdbiTransaction(h -> new AssessmentSyncWorkDao(h).requestRefresh(project));
        final var policy = mock(CelPolicyEngine.class);
        final var metrics = mock(UpdateProjectMetricsActivity.class);
        final var actualPolicy = new CelPolicyEngine();
        final var actualMetrics = new UpdateProjectMetricsActivity();
        final var stages = new CopyOnWriteArrayList<String>();
        final var failed = new java.util.concurrent.atomic.AtomicBoolean();
        doAnswer(invocation -> {
                    stages.add("policy");
                    if (!failMetrics && failed.compareAndSet(false, true)) {
                        throw new TerminalApplicationFailureException("forced policy failure");
                    }
                    actualPolicy.evaluateProject(project);
                    return null;
                })
                .when(policy)
                .evaluateProject(project);
        doAnswer(invocation -> {
                    stages.add("metrics");
                    if (failMetrics && failed.compareAndSet(false, true)) {
                        throw new TerminalApplicationFailureException("forced metrics failure");
                    }
                    actualMetrics.execute(invocation.getArgument(0), invocation.getArgument(1));
                    assertThat(ReconcileFixture.work(project).refreshCompleted())
                            .isZero();
                    return null;
                })
                .when(metrics)
                .execute(any(), any());
        start(1, policy, metrics);
        final UUID first = workflowTest.getEngine().createRun(refreshRun(project, 1));
        workflowTest.awaitRunStatus(first, WorkflowRunStatus.FAILED);
        assertThat(stages).containsExactlyElementsOf(failMetrics ? List.of("policy", "metrics") : List.of("policy"));
        assertThat(ReconcileFixture.work(project).refreshCompleted()).isZero();
        final long rows = withJdbiHandle(h -> h.createQuery(
                        "SELECT count(*) FROM \"PROJECTMETRICS\" WHERE \"PROJECT_ID\" = (SELECT \"ID\" FROM \"PROJECT\" WHERE \"UUID\" = :uuid)")
                .bind("uuid", project)
                .mapTo(long.class)
                .one());
        assertThat(rows).isZero();
        stages.clear();
        final UUID retried = workflowTest.getEngine().createRun(refreshRun(project, 1));
        workflowTest.awaitRunStatus(retried, WorkflowRunStatus.COMPLETED);
        assertThat(stages).containsExactly("policy", "metrics");
        assertThat(ReconcileFixture.work(project).refreshCompleted()).isEqualTo(1);
        assertThat(ReconcileFixture.work(project).refreshRequested()).isEqualTo(1);
    }

    @Test
    void refreshesSharingTheProjectAnalysisKeyWaitForTheActiveRefresh() throws Exception {
        final UUID project = projectUuid();
        useJdbiTransaction(h -> {
            new AssessmentSyncWorkDao(h).requestRefresh(project);
            new AssessmentSyncWorkDao(h).requestRefresh(project);
        });
        final var entered = new CountDownLatch(1);
        final var release = new CountDownLatch(1);
        final var evaluations = new AtomicInteger();
        final var policy = mock(CelPolicyEngine.class);
        doAnswer(invocation -> {
                    if (evaluations.incrementAndGet() == 1) {
                        entered.countDown();
                        assertThat(release.await(10, TimeUnit.SECONDS)).isTrue();
                    }
                    return null;
                })
                .when(policy)
                .evaluateProject(project);
        start(1, policy, new UpdateProjectMetricsActivity());
        final UUID first = workflowTest.getEngine().createRun(refreshRun(project, 1));
        final UUID second;
        try {
            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            second = workflowTest.getEngine().createRun(refreshRun(project, 2));
            final UUID contender = second;
            await().during(Duration.ofMillis(250))
                    .atMost(Duration.ofSeconds(5))
                    .untilAsserted(() -> assertThat(workflowTest
                                    .getEngine()
                                    .getRunMetadataById(contender)
                                    .status())
                            .isEqualTo(WorkflowRunStatus.CREATED));
            assertThat(evaluations.get()).isEqualTo(1);
        } finally {
            release.countDown();
        }
        workflowTest.awaitRunStatus(first, WorkflowRunStatus.COMPLETED);
        workflowTest.awaitRunStatus(second, WorkflowRunStatus.COMPLETED);
        assertThat(evaluations.get()).isEqualTo(2);
        assertThat(ReconcileFixture.work(project).refreshCompleted()).isEqualTo(2);
    }

    @Test
    void refreshRequestedBetweenMetricsAndAcknowledgmentIsDrainedByTheParent() throws Exception {
        final UUID project = projectUuid();
        useJdbiTransaction(h -> new AssessmentSyncWorkDao(h).requestRefresh(project));
        final var metrics = mock(UpdateProjectMetricsActivity.class);
        final var actualMetrics = new UpdateProjectMetricsActivity();
        final var updates = new AtomicInteger();
        doAnswer(invocation -> {
                    actualMetrics.execute(invocation.getArgument(0), invocation.getArgument(1));
                    if (updates.incrementAndGet() == 1) {
                        useJdbiTransaction(h -> assertThat(new AssessmentSyncWorkDao(h).requestRefresh(project))
                                .isEqualTo(2));
                    }
                    return null;
                })
                .when(metrics)
                .execute(any(), any());
        start(1, new CelPolicyEngine(), metrics);
        final UUID run = workflowTest.getEngine().createRun(parentRun(project));
        workflowTest.awaitRunStatus(run, WorkflowRunStatus.COMPLETED);
        assertThat(updates.get()).isEqualTo(2);
        assertThat(ReconcileFixture.work(project).refreshRequested()).isEqualTo(2);
        assertThat(ReconcileFixture.work(project).refreshCompleted()).isEqualTo(2);
        assertThat(runs(RefreshSynchronizedAssessmentsWorkflow.instanceId(project, 1)))
                .hasSize(1);
        assertThat(runs(RefreshSynchronizedAssessmentsWorkflow.instanceId(project, 2)))
                .hasSize(1);
        final int generation = withJdbiHandle(
                h -> h.createQuery("SELECT continued_as_new_generation FROM dex_workflow_run WHERE id = :id")
                        .bind("id", run)
                        .mapTo(int.class)
                        .one());
        assertThat(generation).isEqualTo(1);
    }

    @Test
    void childAcksOnlyTheCapturedRevision() throws Exception {
        final UUID projectUuid = projectUuid();
        useJdbiTransaction(handle -> {
            final var dao = new AssessmentSyncWorkDao(handle);
            assertThat(dao.requestRefresh(projectUuid)).isEqualTo(1);
            assertThat(dao.requestRefresh(projectUuid)).isEqualTo(2);
        });
        start(1);

        final String instanceId = RefreshSynchronizedAssessmentsWorkflow.instanceId(projectUuid, 1);
        final String concurrencyKey = AnalyzeProjectWorkflow.concurrencyKeyForProject(projectUuid);
        assertThat(instanceId).isEqualTo("assessment-refresh:" + projectUuid + ":1");
        assertThat(concurrencyKey).isEqualTo("analyze-project:" + projectUuid);

        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(RefreshSynchronizedAssessmentsWorkflow.class)
                        .withWorkflowInstanceId(instanceId)
                        .withConcurrencyKey(concurrencyKey)
                        .withArgument(refreshArgument(projectUuid, 1)));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final WorkRow work = ReconcileFixture.work(projectUuid);
        assertThat(work).isNotNull();
        assertThat(work.refreshCompleted()).isEqualTo(1);
        assertThat(work.refreshRequested()).isEqualTo(2);
        assertThat(runs(instanceId)).singleElement().satisfies(run -> {
            assertThat(run.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
            assertThat(run.concurrencyKey()).isEqualTo(concurrencyKey);
        });
    }

    @Test
    void oneRunAcksOnlyTheHighestRefreshAfterBothBatches() throws Exception {
        start(1);
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 2);
        ReconcileFixture.requestFull(fixture.target.getUuid());
        final UUID targetUuid = fixture.target.getUuid();

        final UUID runId = workflowTest.getEngine().createRun(parentRun(targetUuid));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(ReconcileFixture.state(fixture.libraries.get(0).getId(), fixture.vulnerability.getId()))
                .isEqualTo("EXPLOITABLE");
        assertThat(ReconcileFixture.state(fixture.libraries.get(1).getId(), fixture.vulnerability.getId()))
                .isEqualTo("EXPLOITABLE");
        assertThat(ReconcileFixture.owner(fixture.libraries.get(0).getId(), fixture.vulnerability.getId()))
                .isEqualTo("INHERITED");
        assertThat(ReconcileFixture.owner(fixture.libraries.get(1).getId(), fixture.vulnerability.getId()))
                .isEqualTo("INHERITED");
        final WorkRow work = ReconcileFixture.work(targetUuid);
        assertThat(work).isNotNull();
        assertThat(work.refreshRequested()).isEqualTo(2);
        assertThat(work.refreshCompleted()).isEqualTo(2);
        assertThat(runs(RefreshSynchronizedAssessmentsWorkflow.instanceId(targetUuid, 1)))
                .isEmpty();
        assertThat(runs(RefreshSynchronizedAssessmentsWorkflow.instanceId(targetUuid, 2)))
                .singleElement()
                .satisfies(run -> {
                    assertThat(run.status()).isEqualTo(WorkflowRunStatus.COMPLETED);
                    assertThat(run.concurrencyKey())
                            .isEqualTo(AnalyzeProjectWorkflow.concurrencyKeyForProject(targetUuid));
                });
        assertThat(runs(SynchronizeProjectAssessmentsWorkflow.instanceId(targetUuid)))
                .isNotEmpty()
                .allSatisfy(run -> assertThat(run.concurrencyKey()).isEqualTo("assessment-sync:" + targetUuid));
    }

    @Test
    void deletedTargetAcknowledgementCompletes() throws Exception {
        final UUID projectUuid = projectUuid();
        useJdbiTransaction(handle -> {
            final var dao = new AssessmentSyncWorkDao(handle);
            assertThat(dao.requestRefresh(projectUuid)).isEqualTo(1);
            assertThat(dao.requestRefresh(projectUuid)).isEqualTo(2);
        });
        useJdbiTransaction(handle -> handle.attach(ProjectDao.class).deleteProject(projectUuid));

        new CompleteAssessmentRefreshActivity().execute(CONTEXT, refreshArgument(projectUuid, 1));

        final WorkRow work = ReconcileFixture.work(projectUuid);
        assertThat(work).isNotNull();
        assertThat(work.refreshCompleted()).isEqualTo(1);
        assertThat(work.refreshRequested()).isEqualTo(2);
    }

    @Test
    void deletedTargetSkipsTheRefreshChild() throws Exception {
        final UUID projectUuid = projectUuid();
        ReconcileFixture.requestFull(projectUuid);
        useJdbiTransaction(handle -> handle.attach(ProjectDao.class).deleteProject(projectUuid));
        start(1);

        final UUID runId = workflowTest.getEngine().createRun(parentRun(projectUuid));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(runs(RefreshSynchronizedAssessmentsWorkflow.instanceId(projectUuid, 1)))
                .isEmpty();
    }

    @Test
    void updateProjectMetricsOutsideATransactionThrows() {
        try (Handle handle = openJdbiHandle()) {
            assertThatThrownBy(() -> handle.attach(MetricsDao.class).updateProjectMetrics(UUID.randomUUID()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("active transaction");
        }
    }

    @Test
    void secondMetricsUpdateWaitsForTheAssessmentSyncLock() throws Exception {
        final UUID projectUuid = projectUuid();
        final Handle first = openJdbiHandle();
        final Handle second = openJdbiHandle();
        final int secondPid =
                second.createQuery("SELECT pg_backend_pid()").mapTo(int.class).one();
        second.execute("SET statement_timeout = '8s'");
        final ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            first.begin();
            AssessmentMutationGuard.lockProject(first, projectUuid);
            final Future<?> blocked = executor.submit(() -> {
                second.begin();
                second.attach(MetricsDao.class).updateProjectMetrics(projectUuid);
                second.commit();
            });

            final var deadline = System.nanoTime() + Duration.ofSeconds(2).toNanos();
            var waiting = 0;
            while (System.nanoTime() < deadline && waiting == 0) {
                waiting = waitingForAssessmentLock(secondPid, projectUuid);
                if (waiting == 0) {
                    Thread.sleep(20);
                }
            }
            assertThat(waiting).isPositive();
            assertThat(blocked.isDone()).isFalse();

            first.rollback();
            blocked.get(10, TimeUnit.SECONDS);
        } finally {
            if (first.isInTransaction()) {
                first.rollback();
            }
            if (second.isInTransaction()) {
                second.rollback();
            }
            executor.shutdownNow();
            assertThat(executor.awaitTermination(15, TimeUnit.SECONDS)).isTrue();
            first.close();
            second.close();
        }
    }

    private void start(final int reconcileBatchSize) {
        start(reconcileBatchSize, new CelPolicyEngine(), new UpdateProjectMetricsActivity());
    }

    private void start(
            final int reconcileBatchSize,
            final CelPolicyEngine policyEngine,
            final UpdateProjectMetricsActivity metricsActivity) {
        final DexEngine engine = workflowTest.getEngine();
        engine.registerWorkflow(
                new SynchronizeProjectAssessmentsWorkflow(),
                protoConverter(SynchronizeProjectAssessmentsArg.class),
                voidConverter(),
                Duration.ofSeconds(15));
        engine.registerWorkflow(
                new RefreshSynchronizedAssessmentsWorkflow(),
                protoConverter(RefreshSynchronizedAssessmentsArg.class),
                voidConverter(),
                Duration.ofSeconds(15));
        engine.registerActivity(
                new ReconcileProjectAssessmentsActivity(reconcileBatchSize, Duration.ofMinutes(10)),
                protoConverter(SynchronizeProjectAssessmentsArg.class),
                protoConverter(ReconcileProjectAssessmentsRes.class));
        engine.registerActivity(
                new CompleteAssessmentRefreshActivity(),
                protoConverter(RefreshSynchronizedAssessmentsArg.class),
                voidConverter());
        engine.registerActivity(
                new ReadAssessmentSyncPendingActivity(),
                protoConverter(SynchronizeProjectAssessmentsArg.class),
                protoConverter(AssessmentSyncPendingRes.class));
        engine.registerActivity(
                new EvalProjectPoliciesActivity(policyEngine),
                protoConverter(EvalProjectPoliciesArg.class),
                voidConverter());
        engine.registerActivity(metricsActivity, protoConverter(UpdateProjectMetricsArg.class), voidConverter());
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 10));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 10));
        engine.createTaskQueue(
                new CreateTaskQueueRequest(TaskType.ACTIVITY, ReconcileProjectAssessmentsActivity.QUEUE_NAME, 10));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "policy-evaluations", 10));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "metrics-updates", 10));
        engine.registerTaskWorker(new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 2)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(new TaskWorkerOptions(
                        TaskType.ACTIVITY, "assessment-sync", ReconcileProjectAssessmentsActivity.QUEUE_NAME, 2)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "policy-evaluations", "policy-evaluations", 2)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(new TaskWorkerOptions(TaskType.ACTIVITY, "metrics-updates", "metrics-updates", 2)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.start();
    }

    private UUID projectUuid() {
        final var project = new Project();
        project.setName("refresh-" + UUID.randomUUID());
        project.setVersion("1");
        return qm.persist(project).getUuid();
    }

    private java.util.List<WorkflowRunMetadata> runs(final String instanceId) {
        return workflowTest
                .getEngine()
                .listRuns(new ListWorkflowRunsRequest()
                        .withWorkflowInstanceId(instanceId)
                        .withLimit(20))
                .items();
    }

    private static CreateWorkflowRunRequest<SynchronizeProjectAssessmentsArg> parentRun(final UUID targetUuid) {
        final String instanceId = SynchronizeProjectAssessmentsWorkflow.instanceId(targetUuid);
        return new CreateWorkflowRunRequest<>(SynchronizeProjectAssessmentsWorkflow.class)
                .withWorkflowInstanceId(instanceId)
                .withConcurrencyKey(instanceId)
                .withArgument(SynchronizeProjectAssessmentsArg.newBuilder()
                        .setProjectUuid(targetUuid.toString())
                        .build());
    }

    private static CreateWorkflowRunRequest<RefreshSynchronizedAssessmentsArg> refreshRun(
            final UUID project, final long revision) {
        return new CreateWorkflowRunRequest<>(RefreshSynchronizedAssessmentsWorkflow.class)
                .withWorkflowInstanceId(RefreshSynchronizedAssessmentsWorkflow.instanceId(project, revision))
                .withConcurrencyKey(AnalyzeProjectWorkflow.concurrencyKeyForProject(project))
                .withArgument(refreshArgument(project, revision));
    }

    private static RefreshSynchronizedAssessmentsArg refreshArgument(
            final UUID projectUuid, final long refreshRevision) {
        return RefreshSynchronizedAssessmentsArg.newBuilder()
                .setProjectUuid(projectUuid.toString())
                .setRefreshRevision(refreshRevision)
                .build();
    }

    private static int waitingForAssessmentLock(final int pid, final UUID projectUuid) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        WITH key AS (
                          SELECT hashtextextended('assessment-sync:' || CAST(:projectUuid AS text), 0) AS k
                        )
                        SELECT COUNT(*)::int
                          FROM pg_locks, key
                         WHERE locktype = 'advisory'
                           AND pid = :pid
                           AND NOT granted
                           AND classid = ((key.k >> 32) & x'ffffffff'::bigint)::oid
                           AND objid = (key.k & x'ffffffff'::bigint)::oid
                           AND objsubid = 1
                        """)
                .bind("pid", pid)
                .bind("projectUuid", projectUuid)
                .mapTo(int.class)
                .one());
    }
}
