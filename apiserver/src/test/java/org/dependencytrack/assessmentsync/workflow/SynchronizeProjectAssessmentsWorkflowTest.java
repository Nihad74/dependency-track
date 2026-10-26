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
import org.dependencytrack.dex.engine.api.response.CreateWorkflowRunResponse;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.metrics.UpdateProjectMetricsActivity;
import org.dependencytrack.model.FindingKey;
import org.dependencytrack.policy.EvalProjectPoliciesActivity;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.dependencytrack.proto.internal.workflow.v1.AssessmentSyncPendingRes;
import org.dependencytrack.proto.internal.workflow.v1.EvalProjectPoliciesArg;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileProjectAssessmentsRes;
import org.dependencytrack.proto.internal.workflow.v1.RefreshSynchronizedAssessmentsArg;
import org.dependencytrack.proto.internal.workflow.v1.SynchronizeProjectAssessmentsArg;
import org.dependencytrack.proto.internal.workflow.v1.UpdateProjectMetricsArg;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Duration;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class SynchronizeProjectAssessmentsWorkflowTest extends PersistenceCapableTest {

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

    @Test
    void twoBatchesRunInOrderAndTheSecondSeesTheFirstCommit() throws Exception {
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 2);
        ReconcileFixture.requestFull(fixture.target.getUuid());
        final long firstComponentId = Math.min(
                fixture.libraries.get(0).getId(), fixture.libraries.get(1).getId());
        final long vulnerabilityId = fixture.vulnerability.getId();
        final var activity = new ReconcileProjectAssessmentsActivity(1, Duration.ofMinutes(10));

        final ReconcileProjectAssessmentsRes first = activity.execute(CONTEXT, argument(fixture.target.getUuid()));
        assertThat(first.getApplied()).isEqualTo(1);
        assertThat(first.getHasMore()).isTrue();
        assertThat(ReconcileFixture.state(firstComponentId, vulnerabilityId)).isEqualTo("EXPLOITABLE");

        final ReconcileProjectAssessmentsRes second = activity.execute(CONTEXT, argument(fixture.target.getUuid()));

        assertThat(second.getApplied()).isEqualTo(1);
        assertThat(second.getHasMore()).isFalse();
        assertThat(ReconcileFixture.state(firstComponentId, vulnerabilityId)).isEqualTo("EXPLOITABLE");
        assertThat(ReconcileFixture.state(fixture.libraries.get(0).getId(), vulnerabilityId))
                .isEqualTo("EXPLOITABLE");
        assertThat(ReconcileFixture.state(fixture.libraries.get(1).getId(), vulnerabilityId))
                .isEqualTo("EXPLOITABLE");
        assertThat(ReconcileFixture.owner(firstComponentId, vulnerabilityId)).isEqualTo("INHERITED");
    }

    @Test
    void differentTargetsBothComplete() throws Exception {
        start(50);
        final ReconcileFixture first = ReconcileFixture.oneSource(qm, 1);
        final ReconcileFixture second = ReconcileFixture.oneSource(qm, 1);
        ReconcileFixture.requestFull(first.target.getUuid());
        ReconcileFixture.requestFull(second.target.getUuid());

        final List<CreateWorkflowRunResponse> created =
                workflowTest.getEngine().createRuns(List.of(run(first.target.getUuid()), run(second.target.getUuid())));
        assertThat(created).hasSize(2);
        workflowTest.awaitRunStatus(created.get(0).runId(), WorkflowRunStatus.COMPLETED);
        workflowTest.awaitRunStatus(created.get(1).runId(), WorkflowRunStatus.COMPLETED);

        assertThat(ReconcileFixture.state(first.library().getId(), first.vulnerability.getId()))
                .isEqualTo("EXPLOITABLE");
        assertThat(ReconcileFixture.state(second.library().getId(), second.vulnerability.getId()))
                .isEqualTo("EXPLOITABLE");
        assertThat(ReconcileFixture.work(first.target.getUuid()).completedRevision())
                .isEqualTo(1);
        assertThat(ReconcileFixture.work(second.target.getUuid()).completedRevision())
                .isEqualTo(1);
    }

    @Test
    void sameTargetDoesNotRunTwoActiveWorkflows() throws Exception {
        start(50);
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 1);
        ReconcileFixture.requestFull(fixture.target.getUuid());
        final String instanceId = SynchronizeProjectAssessmentsWorkflow.instanceId(fixture.target.getUuid());
        assertThat(instanceId).isEqualTo("assessment-sync:" + fixture.target.getUuid());

        final List<CreateWorkflowRunResponse> created = workflowTest
                .getEngine()
                .createRuns(List.of(run(fixture.target.getUuid()), run(fixture.target.getUuid())));

        assertThat(created).hasSize(1);
        workflowTest.awaitRunStatus(created.getFirst().runId(), WorkflowRunStatus.COMPLETED);
        assertThat(ReconcileFixture.state(fixture.library().getId(), fixture.vulnerability.getId()))
                .isEqualTo("EXPLOITABLE");
    }

    @Test
    void repeatingTheSameRevisionDoesNotDuplicateContributions() throws Exception {
        start(50);
        final ReconcileFixture fixture = ReconcileFixture.twoSources(qm);
        ReconcileFixture.requestFull(fixture.target.getUuid());
        final UUID firstRun = workflowTest.getEngine().createRun(run(fixture.target.getUuid()));
        workflowTest.awaitRunStatus(firstRun, WorkflowRunStatus.COMPLETED);
        assertThat(ReconcileFixture.contributionCount(fixture.library().getId(), fixture.vulnerability.getId()))
                .isEqualTo(2);

        ReconcileFixture.requestFindings(
                fixture.target.getUuid(),
                List.of(new FindingKey(fixture.library().getId(), fixture.vulnerability.getId())));
        final UUID secondRun = workflowTest.getEngine().createRun(run(fixture.target.getUuid()));
        workflowTest.awaitRunStatus(secondRun, WorkflowRunStatus.COMPLETED);

        assertThat(ReconcileFixture.contributionDetails(fixture.library().getId(), fixture.vulnerability.getId()))
                .containsExactly(ReconcileFixture.ALPINE_DETAILS, ReconcileFixture.DEBIAN_DETAILS);
        assertThat(ReconcileFixture.state(fixture.library().getId(), fixture.vulnerability.getId()))
                .isEqualTo("EXPLOITABLE");
    }

    @Test
    void findingRevisionRequestedAfterTheSnapshotStaysPending() throws Exception {
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 3);
        final long vulnerabilityId = fixture.vulnerability.getId();
        final long firstId = fixture.libraries.get(0).getId();
        final long secondId = fixture.libraries.get(1).getId();
        final long thirdId = fixture.libraries.get(2).getId();
        ReconcileFixture.requestFindings(
                fixture.target.getUuid(),
                List.of(new FindingKey(firstId, vulnerabilityId), new FindingKey(secondId, vulnerabilityId)));
        final var activity = new ReconcileProjectAssessmentsActivity(1, Duration.ofMinutes(10));

        final ReconcileProjectAssessmentsRes first = activity.execute(CONTEXT, argument(fixture.target.getUuid()));
        assertThat(first.getHasMore()).isTrue();
        ReconcileFixture.requestFindings(fixture.target.getUuid(), List.of(new FindingKey(thirdId, vulnerabilityId)));

        final ReconcileProjectAssessmentsRes acknowledged =
                activity.execute(CONTEXT, argument(fixture.target.getUuid()));

        assertThat(acknowledged.getHasMore()).isTrue();
        final WorkRow work = ReconcileFixture.work(fixture.target.getUuid());
        assertThat(work).isNotNull();
        assertThat(work.completedRevision()).isEqualTo(1);
        assertThat(work.requestedRevision()).isEqualTo(2);
        assertThat(pendingComponentIds(fixture.target.getUuid())).containsExactly(thirdId);
        assertThat(ReconcileFixture.state(thirdId, vulnerabilityId)).isNull();

        start(50);
        final UUID runId = workflowTest.getEngine().createRun(run(fixture.target.getUuid()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(ReconcileFixture.state(thirdId, vulnerabilityId)).isEqualTo("EXPLOITABLE");
        assertThat(ReconcileFixture.work(fixture.target.getUuid()).completedRevision())
                .isEqualTo(2);
        assertThat(pendingComponentIds(fixture.target.getUuid())).isEmpty();
    }

    @Test
    void continueAsNewDrainsABacklogLargerThanMaxBatches() throws Exception {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_WORKFLOW_MAX_BATCHES, "1");
        start(1);
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 2);
        ReconcileFixture.requestFull(fixture.target.getUuid());

        final UUID runId = workflowTest.getEngine().createRun(run(fixture.target.getUuid()));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(ReconcileFixture.state(fixture.libraries.get(0).getId(), fixture.vulnerability.getId()))
                .isEqualTo("EXPLOITABLE");
        assertThat(ReconcileFixture.state(fixture.libraries.get(1).getId(), fixture.vulnerability.getId()))
                .isEqualTo("EXPLOITABLE");
        final WorkRow work = ReconcileFixture.work(fixture.target.getUuid());
        assertThat(work).isNotNull();
        assertThat(work.completedRevision()).isEqualTo(1);
        assertThat(work.requestedRevision()).isEqualTo(1);
    }

    private void start(final int reconcileBatchSize) {
        final DexEngine engine = workflowTest.getEngine();
        final var activity = new ReconcileProjectAssessmentsActivity(reconcileBatchSize, Duration.ofMinutes(10));
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
                activity,
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
                new EvalProjectPoliciesActivity(new CelPolicyEngine()),
                protoConverter(EvalProjectPoliciesArg.class),
                voidConverter());
        engine.registerActivity(
                new UpdateProjectMetricsActivity(), protoConverter(UpdateProjectMetricsArg.class), voidConverter());
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

    private static CreateWorkflowRunRequest<SynchronizeProjectAssessmentsArg> run(final UUID targetUuid) {
        final String instanceId = SynchronizeProjectAssessmentsWorkflow.instanceId(targetUuid);
        return new CreateWorkflowRunRequest<>(SynchronizeProjectAssessmentsWorkflow.class)
                .withWorkflowInstanceId(instanceId)
                .withConcurrencyKey(instanceId)
                .withArgument(argument(targetUuid));
    }

    private static SynchronizeProjectAssessmentsArg argument(final UUID targetUuid) {
        return SynchronizeProjectAssessmentsArg.newBuilder()
                .setProjectUuid(targetUuid.toString())
                .build();
    }

    private static List<Long> pendingComponentIds(final UUID targetUuid) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "COMPONENT_ID"
                          FROM "ASSESSMENT_SYNC_FINDING"
                         WHERE "TARGET_UUID" = :targetUuid
                         ORDER BY "COMPONENT_ID"
                        """)
                .bind("targetUuid", targetUuid)
                .mapTo(long.class)
                .list());
    }
}
