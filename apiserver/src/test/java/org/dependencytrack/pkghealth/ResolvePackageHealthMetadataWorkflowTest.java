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
package org.dependencytrack.pkghealth;

import com.github.packageurl.PackageURL;
import io.github.resilience4j.core.IntervalFunction;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.datasource.DataSourceRegistry;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.dex.engine.api.TaskType;
import org.dependencytrack.dex.engine.api.TaskWorkerOptions;
import org.dependencytrack.dex.engine.api.WorkflowRunStatus;
import org.dependencytrack.dex.engine.api.request.CreateTaskQueueRequest;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.dex.testing.WorkflowTestExtension;
import org.dependencytrack.metrics.UpdateProjectMetricsActivity;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.model.Policy;
import org.dependencytrack.model.PolicyCondition;
import org.dependencytrack.model.PolicyViolation;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.PackageHealthMetadataDao;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.dependencytrack.pkghealth.analyzer.PackageHealthAnalyzer;
import org.dependencytrack.pkghealth.model.AnalyzedPackageHealth;
import org.dependencytrack.policy.EvalProjectPoliciesActivity;
import org.dependencytrack.policy.EvalProjectPoliciesWorkflow;
import org.dependencytrack.policy.cel.CelPolicyEngine;
import org.dependencytrack.proto.internal.workflow.v1.EvalProjectPoliciesArg;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageHealthMetadataCandidatesArg;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageHealthMetadataCandidatesRes;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataActivityArg;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataActivityRes;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataWorkflowArg;
import org.dependencytrack.proto.internal.workflow.v1.ScheduleHealthPolicyEvaluationsArg;
import org.dependencytrack.proto.internal.workflow.v1.UpdateProjectMetricsArg;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class ResolvePackageHealthMetadataWorkflowTest extends PersistenceCapableTest {

    private static final Instant NOW = Instant.parse("2026-09-24T12:00:00Z");

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    private PackageHealthService packageHealthService;

    @BeforeEach
    void beforeEach() {
        packageHealthService = mock(PackageHealthService.class);

        final DexEngine engine = workflowTest.getEngine();

        engine.registerWorkflow(
                new ResolvePackageHealthMetadataWorkflow(),
                protoConverter(ResolvePackageHealthMetadataWorkflowArg.class),
                voidConverter(),
                Duration.ofSeconds(10));

        engine.registerActivity(
                new FetchPackageHealthMetadataCandidatesActivity(packageHealthService, 2),
                protoConverter(FetchPackageHealthMetadataCandidatesArg.class),
                protoConverter(FetchPackageHealthMetadataCandidatesRes.class));

        engine.registerActivity(
                new ResolvePackageHealthMetadataActivity(packageHealthService, Clock.fixed(NOW, ZoneOffset.UTC)),
                protoConverter(ResolvePackageHealthMetadataActivityArg.class),
                protoConverter(ResolvePackageHealthMetadataActivityRes.class));
        engine.registerActivity(
                new ScheduleHealthPolicyEvaluationsActivity(engine),
                protoConverter(ScheduleHealthPolicyEvaluationsArg.class),
                voidConverter());
        engine.registerWorkflow(
                new EvalProjectPoliciesWorkflow(),
                protoConverter(EvalProjectPoliciesArg.class),
                voidConverter(),
                Duration.ofSeconds(10));
        engine.registerActivity(
                new EvalProjectPoliciesActivity(new CelPolicyEngine()),
                protoConverter(EvalProjectPoliciesArg.class),
                voidConverter());
        engine.registerActivity(
                new UpdateProjectMetricsActivity(), protoConverter(UpdateProjectMetricsArg.class), voidConverter());

        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "package-health-metadata-resolutions", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "policy-evaluations", 1));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "metrics-updates", 1));

        engine.registerTaskWorker(new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 1)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.registerTaskWorker(new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-default", "default", 1)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.registerTaskWorker(new TaskWorkerOptions(
                        TaskType.ACTIVITY, "activity-worker-package-health", "package-health-metadata-resolutions", 1)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-policy-evaluations", "policy-evaluations", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(
                new TaskWorkerOptions(TaskType.ACTIVITY, "activity-worker-metrics-updates", "metrics-updates", 1)
                        .withMinPollInterval(Duration.ofMillis(25))
                        .withPollBackoffFunction(IntervalFunction.of(25)));

        engine.start();
    }

    @Test
    void shouldCompleteWhenNoCandidates() {
        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ResolvePackageHealthMetadataWorkflow.class));

        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        verifyNoInteractions(packageHealthService);
    }

    @Test
    void shouldResolveAllCandidatesAcrossMultiplePages() throws Exception {
        final var firstPurl = new PackageURL("pkg:npm/a");
        final var secondPurl = new PackageURL("pkg:npm/b");
        final var thirdPurl = new PackageURL("pkg:npm/c");

        createPackageMetadata(firstPurl, secondPurl, thirdPurl);

        final var firstModel = new AnalyzedPackageHealth(firstPurl);
        firstModel.setStars(10L);

        final var secondModel = new AnalyzedPackageHealth(secondPurl);
        secondModel.setStars(20L);

        final var thirdModel = new AnalyzedPackageHealth(thirdPurl);
        thirdModel.setStars(30L);

        when(packageHealthService.supports(firstPurl)).thenReturn(true);
        when(packageHealthService.supports(secondPurl)).thenReturn(true);
        when(packageHealthService.supports(thirdPurl)).thenReturn(true);

        when(packageHealthService.fetch(firstPurl))
                .thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(firstModel));
        when(packageHealthService.fetch(secondPurl))
                .thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(secondModel));
        when(packageHealthService.fetch(thirdPurl))
                .thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(thirdModel));

        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ResolvePackageHealthMetadataWorkflow.class));

        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        final var persisted = withJdbiHandle(handle -> {
            final var dao = new PackageHealthMetadataDao(handle);

            return List.of(dao.get(firstPurl), dao.get(secondPurl), dao.get(thirdPurl));
        });

        assertThat(persisted)
                .satisfiesExactly(
                        metadata -> {
                            assertThat(metadata).isNotNull();
                            assertThat(metadata.stars()).isEqualTo(10L);
                            assertThat(metadata.lastFetch()).isEqualTo(NOW);
                        },
                        metadata -> {
                            assertThat(metadata).isNotNull();
                            assertThat(metadata.stars()).isEqualTo(20L);
                            assertThat(metadata.lastFetch()).isEqualTo(NOW);
                        },
                        metadata -> {
                            assertThat(metadata).isNotNull();
                            assertThat(metadata.stars()).isEqualTo(30L);
                            assertThat(metadata.lastFetch()).isEqualTo(NOW);
                        });
    }

    @Test
    void shouldEvaluatePoliciesWhenHealthFieldsChange() throws Exception {
        final var packagePurl = new PackageURL("pkg:npm/react");
        createPackageMetadata(packagePurl);

        final var policy = qm.createPolicy("health-policy", Policy.Operator.ANY, Policy.ViolationState.FAIL);
        qm.createPolicyCondition(
                policy,
                PolicyCondition.Subject.EXPRESSION,
                PolicyCondition.Operator.MATCHES,
                "has(health.stars) && health.stars < 5",
                PolicyViolation.Type.OPERATIONAL);

        final var project = new Project();
        project.setName("acme-app");
        qm.persist(project);

        final var component = new Component();
        component.setProject(project);
        component.setName("react");
        component.setPurl("pkg:npm/react@18.3.1");
        component.setPurlCoordinates("pkg:npm/react@18.3.1");
        qm.persist(component);

        final var model = new AnalyzedPackageHealth(packagePurl);
        model.setStars(10L);
        when(packageHealthService.supports(packagePurl)).thenReturn(true);
        when(packageHealthService.fetch(packagePurl))
                .thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(model));

        final DexEngine engine = workflowTest.getEngine();
        final UUID firstRunId =
                engine.createRun(new CreateWorkflowRunRequest<>(ResolvePackageHealthMetadataWorkflow.class));
        workflowTest.awaitRunStatus(firstRunId, WorkflowRunStatus.COMPLETED);
        await().atMost(Duration.ofSeconds(30)).until(() -> policyEvaluationCount(engine), count -> count == 1);

        final UUID secondRunId =
                engine.createRun(new CreateWorkflowRunRequest<>(ResolvePackageHealthMetadataWorkflow.class));
        workflowTest.awaitRunStatus(secondRunId, WorkflowRunStatus.COMPLETED);

        assertThat(policyEvaluationCount(engine)).isEqualTo(1);
    }

    private static long policyEvaluationCount(final DexEngine engine) {
        return engine.countRuns(new org.dependencytrack.dex.engine.api.request.CountWorkflowRunsRequest(
                EvalProjectPoliciesWorkflow.class, null, null, 10));
    }

    private static void createPackageMetadata(final PackageURL... purls) {
        final var metadata = List.of(purls).stream()
                .map(purl -> new PackageMetadata(purl, "1.0.0", null, NOW, "test", "test"))
                .toList();

        withJdbiHandle(handle -> new PackageMetadataDao(handle).upsertAll(metadata));
    }
}
