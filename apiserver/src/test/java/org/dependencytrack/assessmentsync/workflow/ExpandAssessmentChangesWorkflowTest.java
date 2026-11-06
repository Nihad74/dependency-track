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
import org.dependencytrack.assessmentsync.AssessmentChange;
import org.dependencytrack.assessmentsync.AssessmentChange.LookupKey;
import org.dependencytrack.assessmentsync.AssessmentChange.Reason;
import org.dependencytrack.assessmentsync.AssessmentChange.Scope;
import org.dependencytrack.assessmentsync.AssessmentEmbeddingDao;
import org.dependencytrack.assessmentsync.AssessmentEmbeddingDao.MarkerMembership;
import org.dependencytrack.assessmentsync.AssessmentSyncOutboxDao;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao.PendingFinding;
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
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.proto.internal.workflow.v1.ExpandAssessmentChangesArg;
import org.dependencytrack.proto.internal.workflow.v1.ExpandAssessmentChangesRes;
import org.dependencytrack.proto.internal.workflow.v1.SynchronizeProjectAssessmentsArg;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.jdbi.v3.core.statement.SqlLogger;
import org.jdbi.v3.core.statement.SqlStatements;
import org.jdbi.v3.core.statement.StatementContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.time.Duration;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.dex.api.payload.PayloadConverters.protoConverter;
import static org.dependencytrack.dex.api.payload.PayloadConverters.voidConverter;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.createJdbi;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class ExpandAssessmentChangesWorkflowTest extends PersistenceCapableTest {

    private static final ActivityContext ACTIVITY_CONTEXT = () -> UUID.randomUUID();

    private static final UUID TARGET_A = UUID.fromString("10000000-0000-4000-8000-000000000001");
    private static final UUID TARGET_B = UUID.fromString("20000000-0000-4000-8000-000000000001");
    private static final UUID TARGET_C = UUID.fromString("30000000-0000-4000-8000-000000000001");
    private static final UUID LATE_TARGET = UUID.fromString("00000000-0000-4000-8000-000000000001");

    @RegisterExtension
    private final WorkflowTestExtension workflowTest =
            new WorkflowTestExtension(DataSourceRegistry.getInstance().getDefault());

    private ExpandAssessmentChangesActivity activity;

    @AfterEach
    void afterEach() {
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_WORKFLOW_MAX_BATCHES);
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
    }

    @Test
    void fanoutCursorResumesAndIgnoresATargetBehindTheCursor() throws Exception {
        start(2, 200);
        final UUID sourceUuid = UUID.fromString("40000000-0000-4000-8000-000000000099");
        final Project targetA = project("target-a", "1.0.0", TARGET_A);
        final Project targetB = project("target-b", "1.0.0", TARGET_B);
        final Project targetC = project("target-c", "1.0.0", TARGET_C);
        embed(targetA, sourceUuid, "marker-a", "1");
        embed(targetB, sourceUuid, "marker-b", "1");
        embed(targetC, sourceUuid, "marker-c", "1");
        final long outboxId =
                record(new AssessmentChange(Scope.PROJECT, sourceUuid, null, null, Reason.PROJECT_UPDATED, List.of()));

        final ExpandAssessmentChangesRes firstPage = activity.execute(ACTIVITY_CONTEXT, argument(outboxId));

        assertThat(firstPage.getHasMore()).isTrue();
        assertThat(firstPage.getAlreadyCompleted()).isFalse();
        assertThat(firstPage.getTargetsRequested()).isEqualTo(2);
        assertThat(cursor(outboxId)).isEqualTo(TARGET_B);
        assertThat(work(TARGET_A).requestedRevision()).isEqualTo(1);
        assertThat(work(TARGET_B).requestedRevision()).isEqualTo(1);
        assertThat(work(TARGET_C)).isNull();

        final Project late = project("late", "1.0.0", LATE_TARGET);
        embed(late, sourceUuid, "marker-late", "1");
        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ExpandAssessmentChangesWorkflow.class)
                        .withWorkflowInstanceId(ExpandAssessmentChangesWorkflow.instanceId(outboxId))
                        .withConcurrencyKey(ExpandAssessmentChangesWorkflow.instanceId(outboxId))
                        .withArgument(argument(outboxId)));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(outboxCount()).isZero();
        assertThat(work(TARGET_A).requestedRevision()).isEqualTo(1);
        assertThat(work(TARGET_A).completedRevision()).isZero();
        assertThat(work(TARGET_B).requestedRevision()).isEqualTo(1);
        assertThat(work(TARGET_C)).isNotNull();
        assertThat(work(TARGET_C).requestedRevision()).isEqualTo(1);
        assertThat(work(TARGET_C).fullRevision()).isEqualTo(1);
        assertThat(work(LATE_TARGET)).isNull();
    }

    @Test
    void lastPageDeletesTheOutboxRowAndLeavesTargetWorkPending() throws Exception {
        start(100, 200);
        final Project source = project("source-app", "9.9.9", null);
        embed(source, null, "base-os", "1");
        final long outboxId = record(new AssessmentChange(
                Scope.PROJECT,
                source.getUuid(),
                null,
                null,
                Reason.PROJECT_UPDATED,
                List.of(new LookupKey("source-app", "9.9.9"))));

        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ExpandAssessmentChangesWorkflow.class)
                        .withArgument(argument(outboxId)));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(outboxCount()).isZero();
        final WorkRow pending = work(source.getUuid());
        assertThat(pending).isNotNull();
        assertThat(pending.fullRevision()).isEqualTo(1);
        assertThat(pending.completedRevision()).isZero();
        assertThat(pending.requestedRevision()).isEqualTo(1);
    }

    @Test
    void deletedSourceProjectStillEnqueuesContributionTargets() throws Exception {
        start(100, 200);
        final Project source = project("gone-source", "1.0.0", null);
        final Project target = project("consumer", "1.0.0", null);
        final long analysisId = analysis(target, "lib", "1.0.0");
        contribute(analysisId, source.getUuid(), UUID.randomUUID(), UUID.randomUUID());
        useJdbiTransaction(handle -> handle.attach(ProjectDao.class).deleteProject(source.getUuid()));
        final long outboxId = record(
                new AssessmentChange(Scope.PROJECT, source.getUuid(), null, null, Reason.PROJECT_DELETED, List.of()));

        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ExpandAssessmentChangesWorkflow.class)
                        .withArgument(argument(outboxId)));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(outboxCount()).isZero();
        assertThat(work(source.getUuid())).isNull();
        assertThat(work(target.getUuid())).isNotNull();
        assertThat(work(target.getUuid()).fullRevision()).isEqualTo(1);
        assertThat(work(target.getUuid()).completedRevision()).isZero();
    }

    @Test
    void oldAndNewLookupKeysBothMatchMarkers() throws Exception {
        start(100, 200);
        final Project source = project("renamed-source", "2.0.0", null);
        final Project oldMarker = project("old-consumer", "1.0.0", null);
        final Project newMarker = project("new-consumer", "1.0.0", null);
        final Project resolved = project("resolved-consumer", "1.0.0", null);
        final Project unrelated = project("unrelated-consumer", "1.0.0", null);
        embed(oldMarker, null, "old-name", "1.0.0");
        embed(newMarker, null, "new-name", "2.0.0");
        embed(resolved, source.getUuid(), "other-name", "8.0.0");
        embed(unrelated, null, "someone-else", "1.0.0");
        final long outboxId = record(new AssessmentChange(
                Scope.PROJECT,
                source.getUuid(),
                null,
                null,
                Reason.PROJECT_UPDATED,
                List.of(new LookupKey("old-name", "1.0.0"), new LookupKey("new-name", "2.0.0"))));

        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ExpandAssessmentChangesWorkflow.class)
                        .withArgument(argument(outboxId)));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(outboxCount()).isZero();
        assertThat(work(source.getUuid())).isNull();
        assertThat(work(oldMarker.getUuid())).isNotNull();
        assertThat(work(newMarker.getUuid())).isNotNull();
        assertThat(work(resolved.getUuid())).isNotNull();
        assertThat(work(unrelated.getUuid())).isNull();
        assertThat(List.of(oldMarker, newMarker, resolved))
                .allSatisfy(project ->
                        assertThat(work(project.getUuid()).completedRevision()).isZero());
    }

    @Test
    void findingOverTheReconcileBatchRequestsAFullPass() throws Exception {
        start(100, 2);
        final UUID sourceProject = UUID.randomUUID();
        final UUID sourceComponent = UUID.randomUUID();
        final UUID sourceVulnerability = UUID.randomUUID();
        final Project target = project("wide-consumer", "1.0.0", null);
        final Vulnerability vulnerability = vulnerability();
        for (int i = 0; i < 3; i++) {
            final long analysisId = analysis(target, vulnerability, "lib-" + i);
            contribute(analysisId, sourceProject, sourceComponent, sourceVulnerability);
        }
        final long outboxId = record(new AssessmentChange(
                Scope.FINDING, sourceProject, sourceComponent, sourceVulnerability, Reason.AUTHORED, List.of()));

        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ExpandAssessmentChangesWorkflow.class)
                        .withArgument(argument(outboxId)));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(outboxCount()).isZero();
        final WorkRow pending = work(target.getUuid());
        assertThat(pending).isNotNull();
        assertThat(pending.fullRevision()).isEqualTo(1);
        assertThat(pending.completedRevision()).isZero();
        assertThat(pendingFindings(target.getUuid())).isEmpty();
    }

    @Test
    void copiedFindingAndEmbeddingMemberAreEnqueued() throws Exception {
        start(100, 200);
        final Project source = project("source-product", "1.0.0", null);
        final Component sourceComponent = component(source, "openssl", "3.0.0", Classifier.LIBRARY);
        final Vulnerability vulnerability = vulnerability();
        final Project copied = project("copied-consumer", "1.0.0", null);
        final long copiedAnalysis = analysis(copied, vulnerability, "openssl");
        contribute(copiedAnalysis, source.getUuid(), sourceComponent.getUuid(), vulnerability.getUuid());
        final Component decoy = component(copied, "decoy", "1.0.0", Classifier.LIBRARY);
        qm.makeAnalysis(new MakeAnalysisCommand(decoy, vulnerability)
                .withState(org.dependencytrack.model.AnalysisState.IN_TRIAGE));

        final Project embedded = project("embedded-consumer", "1.0.0", null);
        final Component marker = component(embedded, "os", "1", Classifier.OPERATING_SYSTEM);
        final Component member = component(embedded, "openssl", "3.0.0", Classifier.LIBRARY);
        qm.makeAnalysis(new MakeAnalysisCommand(member, vulnerability)
                .withState(org.dependencytrack.model.AnalysisState.IN_TRIAGE));
        useJdbiTransaction(handle -> new AssessmentEmbeddingDao(handle)
                .replaceMembership(
                        embedded.getId(),
                        List.of(new MarkerMembership(
                                marker.getId(), "os", "1", source.getUuid(), List.of(member.getId())))));
        clearOutbox();
        final long outboxId = record(new AssessmentChange(
                Scope.FINDING,
                source.getUuid(),
                sourceComponent.getUuid(),
                vulnerability.getUuid(),
                Reason.AUTHORED,
                List.of(new LookupKey(source.getName(), source.getVersion()))));

        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ExpandAssessmentChangesWorkflow.class)
                        .withArgument(argument(outboxId)));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(outboxCount()).isZero();
        assertThat(work(source.getUuid())).isNull();
        assertThat(pendingFindings(copied.getUuid()))
                .extracting(PendingFinding::componentId)
                .containsExactly(componentId(copiedAnalysis));
        assertThat(pendingFindings(embedded.getUuid()))
                .extracting(PendingFinding::componentId)
                .containsExactly(member.getId());
        assertThat(pendingFindings(copied.getUuid()))
                .extracting(PendingFinding::componentId)
                .doesNotContain(decoy.getId());
        assertThat(work(copied.getUuid()).fullRevision()).isZero();
        assertThat(work(embedded.getUuid()).fullRevision()).isZero();
    }

    @Test
    void embeddedMemberWithoutTheChangedFindingIsNotEnqueued() throws Exception {
        start(100, 200);
        final Project source = project("source-without-reach", "1.0.0", null);
        final Component sourceComponent = component(source, "zlib", "1.3.0", Classifier.LIBRARY);
        final Vulnerability vulnerability = vulnerability();
        final Project embedded = project("unaffected-consumer", "1.0.0", null);
        final Component marker = component(embedded, "os", "1", Classifier.OPERATING_SYSTEM);
        final Component member = component(embedded, "zlib", "1.3.0", Classifier.LIBRARY);
        useJdbiTransaction(handle -> new AssessmentEmbeddingDao(handle)
                .replaceMembership(
                        embedded.getId(),
                        List.of(new MarkerMembership(
                                marker.getId(), "os", "1", source.getUuid(), List.of(member.getId())))));
        final long outboxId = record(new AssessmentChange(
                Scope.FINDING,
                source.getUuid(),
                sourceComponent.getUuid(),
                vulnerability.getUuid(),
                Reason.AUTHORED,
                List.of()));

        activity.execute(ACTIVITY_CONTEXT, argument(outboxId));

        assertThat(outboxCount()).isZero();
        assertThat(work(embedded.getUuid())).isNull();
    }

    @Test
    void projectChangeOfAProjectThatEmbedsNothingRequestsNoWorkForIt() throws Exception {
        start(100, 200);
        final Project project = project("standalone", "1.0.0", null);
        analysis(project, "lib", "1.0.0");
        final long outboxId = record(
                new AssessmentChange(Scope.PROJECT, project.getUuid(), null, null, Reason.BOM_IMPORT, List.of()));

        activity.execute(ACTIVITY_CONTEXT, argument(outboxId));

        assertThat(outboxCount()).isZero();
        assertThat(work(project.getUuid())).isNull();
    }

    @Test
    void projectChangeOfAnEmbeddingProjectRequestsAFullPassForIt() throws Exception {
        start(100, 200);
        final Project project = project("product", "1.0.0", null);
        embed(project, null, "base-os", "1");
        final long outboxId = record(
                new AssessmentChange(Scope.PROJECT, project.getUuid(), null, null, Reason.BOM_IMPORT, List.of()));

        activity.execute(ACTIVITY_CONTEXT, argument(outboxId));

        assertThat(work(project.getUuid())).isNotNull();
        assertThat(work(project.getUuid()).fullRevision()).isEqualTo(1);
    }

    @Test
    void projectChangeOfAProjectWithInheritedRowsRequestsAFullPassForIt() throws Exception {
        start(100, 200);
        final Project project = project("former-product", "1.0.0", null);
        inherit(analysis(project, "lib", "1.0.0"));
        final long outboxId = record(
                new AssessmentChange(Scope.PROJECT, project.getUuid(), null, null, Reason.BOM_IMPORT, List.of()));

        activity.execute(ACTIVITY_CONTEXT, argument(outboxId));

        assertThat(work(project.getUuid())).isNotNull();
        assertThat(work(project.getUuid()).fullRevision()).isEqualTo(1);
    }

    @Test
    void ownFindingOutsideAnyEmbeddingRequestsNoWorkForTheProject() throws Exception {
        start(100, 200);
        final Project project = project("product", "1.0.0", null);
        embed(project, null, "base-os", "1");
        final Component component = component(project, "app-lib", "1.0.0", Classifier.LIBRARY);
        final Vulnerability vulnerability = vulnerability();
        final long outboxId = record(new AssessmentChange(
                Scope.FINDING,
                project.getUuid(),
                component.getUuid(),
                vulnerability.getUuid(),
                Reason.AUTHORED,
                List.of()));

        activity.execute(ACTIVITY_CONTEXT, argument(outboxId));

        assertThat(work(project.getUuid())).isNull();
    }

    @Test
    void ownFindingOnAMemberRequestsWorkAndOneOnTheMarkerDoesNot() throws Exception {
        start(100, 200);
        final Project project = project("product", "1.0.0", null);
        final Component marker = component(project, "os", "1", Classifier.OPERATING_SYSTEM);
        final Component member = component(project, "openssl", "3.0.0", Classifier.LIBRARY);
        useJdbiTransaction(handle -> new AssessmentEmbeddingDao(handle)
                .replaceMembership(
                        project.getId(),
                        List.of(new MarkerMembership(marker.getId(), "os", "1", null, List.of(member.getId())))));
        final Vulnerability vulnerability = vulnerability();

        for (final Component component : List.of(marker, member)) {
            final long outboxId = record(new AssessmentChange(
                    Scope.FINDING,
                    project.getUuid(),
                    component.getUuid(),
                    vulnerability.getUuid(),
                    Reason.AUTHORED,
                    List.of()));
            activity.execute(ACTIVITY_CONTEXT, argument(outboxId));
        }

        assertThat(pendingFindings(project.getUuid()))
                .extracting(PendingFinding::componentId)
                .containsExactly(member.getId());
    }

    @Test
    void ownInheritedFindingRequestsWorkForTheProject() throws Exception {
        start(100, 200);
        final Project project = project("former-product", "1.0.0", null);
        final Vulnerability vulnerability = vulnerability();
        final long analysisId = analysis(project, vulnerability, "lib");
        inherit(analysisId);
        final UUID componentUuid = withJdbiHandle(handle ->
                handle.createQuery("""
                        SELECT c."UUID"
                          FROM "COMPONENT" AS c
                          JOIN "ANALYSIS" AS a
                            ON a."COMPONENT_ID" = c."ID"
                         WHERE a."ID" = :id
                        """).bind("id", analysisId).mapTo(UUID.class).one());
        final long outboxId = record(new AssessmentChange(
                Scope.FINDING, project.getUuid(), componentUuid, vulnerability.getUuid(), Reason.AUTHORED, List.of()));

        activity.execute(ACTIVITY_CONTEXT, argument(outboxId));

        assertThat(pendingFindings(project.getUuid()))
                .extracting(PendingFinding::componentId)
                .containsExactly(componentId(analysisId));
    }

    @Test
    void continueAsNewFinishesTargetsBeyondTheBatchLimit() throws Exception {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_WORKFLOW_MAX_BATCHES, "1");
        start(1, 200);
        final UUID sourceUuid = UUID.fromString("41000000-0000-4000-8000-000000000099");
        final Project first = project("page-one", "1.0.0", TARGET_A);
        final Project second = project("page-two", "1.0.0", TARGET_B);
        embed(first, sourceUuid, "page-one", "1");
        embed(second, sourceUuid, "page-two", "1");
        final long outboxId =
                record(new AssessmentChange(Scope.PROJECT, sourceUuid, null, null, Reason.PROJECT_UPDATED, List.of()));

        final UUID runId = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ExpandAssessmentChangesWorkflow.class)
                        .withArgument(argument(outboxId)));
        workflowTest.awaitRunStatus(runId, WorkflowRunStatus.COMPLETED);

        assertThat(outboxCount()).isZero();
        assertThat(work(TARGET_A)).isNotNull();
        assertThat(work(TARGET_B)).isNotNull();
        final int generation = withJdbiHandle(
                h -> h.createQuery("SELECT continued_as_new_generation FROM dex_workflow_run WHERE id = :id")
                        .bind("id", runId)
                        .mapTo(int.class)
                        .one());
        assertThat(generation)
                .as("the batch limit actually caused continuation")
                .isEqualTo(1);
    }

    @Test
    void concurrentMixedPagesLockAllTargetsInTheSameOrder() throws Exception {
        start(100, 2);
        final var first = project("first", "1", TARGET_A);
        final var second = project("second", "1", TARGET_B);
        final var vulnerability = vulnerability();
        final UUID sourceOne = UUID.randomUUID();
        final UUID sourceTwo = UUID.randomUUID();
        final UUID componentOne = UUID.randomUUID();
        final UUID componentTwo = UUID.randomUUID();
        contribute(analysis(first, vulnerability, "one-small"), sourceOne, componentOne, vulnerability.getUuid());
        contribute(analysis(second, vulnerability, "two-small"), sourceTwo, componentTwo, vulnerability.getUuid());
        for (int i = 0; i < 3; i++) {
            contribute(
                    analysis(second, vulnerability, "one-large-" + i),
                    sourceOne,
                    componentOne,
                    vulnerability.getUuid());
            contribute(
                    analysis(first, vulnerability, "two-large-" + i), sourceTwo, componentTwo, vulnerability.getUuid());
        }
        clearOutbox();
        final var ids = inJdbiTransaction(h -> {
            new AssessmentSyncWorkDao(h).requestFull(List.of(TARGET_A, TARGET_B));
            return new AssessmentSyncOutboxDao(h)
                    .recordAll(List.of(
                            new AssessmentChange(
                                    Scope.FINDING,
                                    sourceOne,
                                    componentOne,
                                    vulnerability.getUuid(),
                                    Reason.AUTHORED,
                                    List.of()),
                            new AssessmentChange(
                                    Scope.FINDING,
                                    sourceTwo,
                                    componentTwo,
                                    vulnerability.getUuid(),
                                    Reason.AUTHORED,
                                    List.of())));
        });
        final var jdbi = createJdbi();
        final var previous = jdbi.getConfig(SqlStatements.class).getSqlLogger();
        final var firstWrites = ConcurrentHashMap.<Thread>newKeySet();
        final var bothWriting = new CountDownLatch(2);
        jdbi.setSqlLogger(new SqlLogger() {
            @Override
            public void logAfterExecution(final StatementContext context) {
                if (context.getRenderedSql().contains("INSERT INTO \"ASSESSMENT_SYNC_WORK\"")
                        && firstWrites.add(Thread.currentThread())) {
                    bothWriting.countDown();
                    try {
                        // Permit either concurrent first writes or proper serialization of the whole page.
                        bothWriting.await(2, TimeUnit.SECONDS);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IllegalStateException(e);
                    }
                }
            }
        });
        try (final var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            final var one = executor.submit(() -> activity.execute(ACTIVITY_CONTEXT, argument(ids.getFirst())));
            final var two = executor.submit(() -> activity.execute(ACTIVITY_CONTEXT, argument(ids.getLast())));
            assertThat(one.get(15, TimeUnit.SECONDS).getTargetsRequested()).isEqualTo(2);
            assertThat(two.get(15, TimeUnit.SECONDS).getTargetsRequested()).isEqualTo(2);
        } finally {
            jdbi.setSqlLogger(previous);
        }
        assertThat(outboxCount()).isZero();
        for (final var uuid : List.of(TARGET_A, TARGET_B)) {
            assertThat(work(uuid).requestedRevision()).isEqualTo(3);
            assertThat(work(uuid).fullRevision()).isBetween(2L, 3L);
            assertThat(pendingFindings(uuid)).hasSize(1);
        }
    }

    @Test
    void pageRequestsRollBackWithTheirCursorUpdateOrFinalDeletion() throws Exception {
        start(1, 2);
        final var source = UUID.randomUUID();
        embed(project("a", "1", TARGET_A), source, "a", "1");
        embed(project("b", "1", TARGET_B), source, "b", "1");
        final long id =
                record(new AssessmentChange(Scope.PROJECT, source, null, null, Reason.PROJECT_UPDATED, List.of()));
        try {
            failOutboxProgress(true);
            assertThatThrownBy(() -> activity.execute(ACTIVITY_CONTEXT, argument(id)))
                    .isInstanceOf(RuntimeException.class);
            assertThat(cursor(id)).isNull();
            assertThat(work(TARGET_A)).isNull();
            assertThat(work(TARGET_B)).isNull();
            failOutboxProgress(false);
            assertThat(activity.execute(ACTIVITY_CONTEXT, argument(id)).getHasMore())
                    .isTrue();
            assertThat(cursor(id)).isEqualTo(TARGET_A);
            assertThat(work(TARGET_A).requestedRevision()).isEqualTo(1);

            failOutboxProgress(true);
            assertThatThrownBy(() -> activity.execute(ACTIVITY_CONTEXT, argument(id)))
                    .isInstanceOf(RuntimeException.class);
            assertThat(cursor(id)).isEqualTo(TARGET_A);
            assertThat(work(TARGET_A).requestedRevision()).isEqualTo(1);
            assertThat(work(TARGET_B)).isNull();
            failOutboxProgress(false);
            final var last = activity.execute(ACTIVITY_CONTEXT, argument(id));
            assertThat(last.getHasMore()).isFalse();
            assertThat(last.getTargetsRequested()).isEqualTo(1);
            assertThat(outboxCount()).isZero();
            assertThat(work(TARGET_A).requestedRevision()).isEqualTo(1);
            assertThat(work(TARGET_B).requestedRevision()).isEqualTo(1);
        } finally {
            failOutboxProgress(false);
        }
    }

    @Test
    void findingPaginationKeepsTheThresholdBoundaryAndDeduplicatesDiscoveryPaths() throws Exception {
        start(2, 2);
        final UUID source = UUID.randomUUID();
        final UUID sourceComponent = UUID.randomUUID();
        final var vulnerability = vulnerability();
        final var a = project("a", "1", TARGET_A);
        final var b = project("b", "1", TARGET_B);
        final var c = project("c", "1", TARGET_C);
        final var members = new java.util.ArrayList<Long>();
        for (int i = 0; i < 2; i++) {
            final long analysis = analysis(a, vulnerability, "a-" + i);
            members.add(componentId(analysis));
            contribute(analysis, source, sourceComponent, vulnerability.getUuid());
        }
        final var marker = component(a, "source", "1", Classifier.OPERATING_SYSTEM);
        useJdbiTransaction(h -> new AssessmentEmbeddingDao(h)
                .replaceMembership(
                        a.getId(), List.of(new MarkerMembership(marker.getId(), "source", "1", source, members))));
        for (int i = 0; i < 3; i++) {
            contribute(analysis(b, vulnerability, "b-" + i), source, sourceComponent, vulnerability.getUuid());
        }
        contribute(analysis(c, vulnerability, "c"), source, sourceComponent, vulnerability.getUuid());
        final long id = record(new AssessmentChange(
                Scope.FINDING, source, sourceComponent, vulnerability.getUuid(), Reason.AUTHORED, List.of()));
        final var first = activity.execute(ACTIVITY_CONTEXT, argument(id));
        assertThat(first.getHasMore()).isTrue();
        assertThat(first.getTargetsRequested()).isEqualTo(2);
        assertThat(cursor(id)).isEqualTo(TARGET_B);
        assertThat(work(TARGET_A).fullRevision()).isZero();
        assertThat(pendingFindings(TARGET_A))
                .extracting(PendingFinding::componentId)
                .containsExactlyElementsOf(members);
        assertThat(work(TARGET_B).fullRevision()).isEqualTo(1);
        assertThat(pendingFindings(TARGET_B)).isEmpty();
        assertThat(work(TARGET_C)).isNull();
        final var last = activity.execute(ACTIVITY_CONTEXT, argument(id));
        assertThat(last.getHasMore()).isFalse();
        assertThat(last.getTargetsRequested()).isEqualTo(1);
        assertThat(outboxCount()).isZero();
        assertThat(work(TARGET_A).requestedRevision()).isEqualTo(1);
        assertThat(work(TARGET_B).requestedRevision()).isEqualTo(1);
        assertThat(pendingFindings(TARGET_C)).hasSize(1);
    }

    @ParameterizedTest
    @EnumSource(Scope.class)
    void emptyPagesCompleteAndWorkflowReplayOfADeletedRowIsHarmless(final Scope scope) throws Exception {
        start(2, 2);
        final var source = UUID.randomUUID();
        final long id = record(
                scope == Scope.PROJECT
                        ? new AssessmentChange(scope, source, null, null, Reason.PROJECT_UPDATED, List.of())
                        : new AssessmentChange(
                                scope, source, UUID.randomUUID(), UUID.randomUUID(), Reason.AUTHORED, List.of()));
        final var result = activity.execute(ACTIVITY_CONTEXT, argument(id));
        assertThat(result.getHasMore()).isFalse();
        assertThat(result.getAlreadyCompleted()).isFalse();
        assertThat(result.getTargetsRequested()).isZero();
        assertThat(outboxCount()).isZero();
        final var replay = activity.execute(ACTIVITY_CONTEXT, argument(id));
        assertThat(replay.getAlreadyCompleted()).isTrue();
        assertThat(replay.getTargetsRequested()).isZero();
        final var run = workflowTest
                .getEngine()
                .createRun(new CreateWorkflowRunRequest<>(ExpandAssessmentChangesWorkflow.class)
                        .withArgument(argument(id)));
        workflowTest.awaitRunStatus(run, WorkflowRunStatus.COMPLETED);
    }

    private static void failOutboxProgress(final boolean enabled) {
        useJdbiTransaction(h -> {
            h.execute("DROP TRIGGER IF EXISTS fail_expansion_progress ON \"ASSESSMENT_SYNC_OUTBOX\"");
            if (enabled) {
                h.execute("""
                        CREATE OR REPLACE FUNCTION fail_expansion_progress() RETURNS trigger LANGUAGE plpgsql AS $$
                        BEGIN RAISE EXCEPTION 'expansion progress failed'; END; $$
                        """);
                h.execute("""
                        CREATE TRIGGER fail_expansion_progress BEFORE UPDATE OF "FANOUT_CURSOR" OR DELETE
                        ON "ASSESSMENT_SYNC_OUTBOX" FOR EACH ROW EXECUTE FUNCTION fail_expansion_progress()
                        """);
            } else {
                h.execute("DROP FUNCTION IF EXISTS fail_expansion_progress()");
            }
        });
    }

    private void start(final int fanoutBatchSize, final int reconcileBatchSize) {
        final DexEngine engine = workflowTest.getEngine();
        activity = new ExpandAssessmentChangesActivity(fanoutBatchSize, reconcileBatchSize);
        engine.registerWorkflow(
                new ExpandAssessmentChangesWorkflow(),
                protoConverter(ExpandAssessmentChangesArg.class),
                voidConverter(),
                Duration.ofSeconds(15));
        engine.registerWorkflow(
                new SynchronizeProjectAssessmentsWorkflow(),
                protoConverter(SynchronizeProjectAssessmentsArg.class),
                voidConverter(),
                Duration.ofSeconds(15));
        engine.registerActivity(
                activity,
                protoConverter(ExpandAssessmentChangesArg.class),
                protoConverter(ExpandAssessmentChangesRes.class));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.WORKFLOW, "default", 10));
        engine.createTaskQueue(new CreateTaskQueueRequest(TaskType.ACTIVITY, "default", 10));
        engine.createTaskQueue(
                new CreateTaskQueueRequest(TaskType.ACTIVITY, ExpandAssessmentChangesActivity.QUEUE_NAME, 10));
        engine.registerTaskWorker(new TaskWorkerOptions(TaskType.WORKFLOW, "workflow-worker", "default", 2)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.registerTaskWorker(new TaskWorkerOptions(
                        TaskType.ACTIVITY, "assessment-sync", ExpandAssessmentChangesActivity.QUEUE_NAME, 2)
                .withMinPollInterval(Duration.ofMillis(25))
                .withPollBackoffFunction(IntervalFunction.of(25)));
        engine.start();
    }

    private Project project(final String name, final String version, final UUID uuid) {
        final var project = new Project();
        project.setName(name);
        project.setVersion(version);
        final Project persisted = qm.persist(project);
        if (uuid == null) {
            return persisted;
        }
        useJdbiTransaction(handle -> handle.createUpdate("""
                        UPDATE "PROJECT"
                           SET "UUID" = :uuid
                         WHERE "ID" = :id
                        """)
                .bind("uuid", uuid)
                .bind("id", persisted.getId())
                .execute());
        persisted.setUuid(uuid);
        return persisted;
    }

    private void embed(final Project target, final UUID sourceUuid, final String name, final String version) {
        final Component marker = component(target, name, version, Classifier.OPERATING_SYSTEM);
        useJdbiTransaction(handle -> new AssessmentEmbeddingDao(handle)
                .replaceMembership(
                        target.getId(),
                        List.of(new MarkerMembership(marker.getId(), name, version, sourceUuid, List.of()))));
    }

    private Component component(
            final Project project, final String name, final String version, final Classifier classifier) {
        final var component = new Component();
        component.setProject(project);
        component.setName(name);
        component.setVersion(version);
        component.setClassifier(classifier);
        return qm.persist(component);
    }

    private long analysis(final Project project, final String componentName, final String componentVersion) {
        return analysis(project, vulnerability(), componentName, componentVersion);
    }

    private long analysis(final Project project, final Vulnerability vulnerability, final String componentName) {
        return analysis(project, vulnerability, componentName, "1.0.0");
    }

    private long analysis(
            final Project project,
            final Vulnerability vulnerability,
            final String componentName,
            final String componentVersion) {
        final Component component = component(project, componentName, componentVersion, Classifier.LIBRARY);
        return qm.makeAnalysis(new MakeAnalysisCommand(component, vulnerability)
                .withState(org.dependencytrack.model.AnalysisState.IN_TRIAGE));
    }

    private Vulnerability vulnerability() {
        final var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-" + UUID.randomUUID());
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        return qm.persist(vulnerability);
    }

    private static void contribute(
            final long analysisId,
            final UUID sourceProject,
            final UUID sourceComponent,
            final UUID sourceVulnerability) {
        useJdbiTransaction(handle -> handle.createUpdate("""
                        INSERT INTO "ASSESSMENT_SOURCE_CONTRIBUTION" (
                          "TARGET_ANALYSIS_ID", "SOURCE_PROJECT_UUID", "SOURCE_COMPONENT_UUID"
                        , "SOURCE_VULNERABILITY_UUID", "SOURCE_ANALYSIS_ID"
                        ) VALUES (
                          :analysisId, :sourceProject, :sourceComponent, :sourceVulnerability, 1
                        )
                        """)
                .bind("analysisId", analysisId)
                .bind("sourceProject", sourceProject)
                .bind("sourceComponent", sourceComponent)
                .bind("sourceVulnerability", sourceVulnerability)
                .execute());
    }

    private static void inherit(final long analysisId) {
        useJdbiTransaction(handle ->
                handle.createUpdate("""
                        INSERT INTO "ASSESSMENT_ORIGIN" ("ANALYSIS_ID", "OWNER")
                        VALUES (:analysisId, 'INHERITED')
                        ON CONFLICT ("ANALYSIS_ID") DO UPDATE
                        SET "OWNER" = 'INHERITED'
                        """).bind("analysisId", analysisId).execute());
    }

    private static long record(final AssessmentChange change) {
        clearOutbox();
        return inJdbiTransaction(handle ->
                new AssessmentSyncOutboxDao(handle).recordAll(List.of(change)).getFirst());
    }

    private static void clearOutbox() {
        useJdbiTransaction(handle -> handle.execute("""
                DELETE FROM "ASSESSMENT_SYNC_OUTBOX"
                """));
    }

    private static ExpandAssessmentChangesArg argument(final long outboxId) {
        return ExpandAssessmentChangesArg.newBuilder().setOutboxId(outboxId).build();
    }

    private static WorkRow work(final UUID targetUuid) {
        return withJdbiHandle(handle -> new AssessmentSyncWorkDao(handle).find(targetUuid));
    }

    private static List<PendingFinding> pendingFindings(final UUID targetUuid) {
        return withJdbiHandle(handle -> new AssessmentSyncWorkDao(handle).pendingFindings(targetUuid));
    }

    private static long componentId(final long analysisId) {
        return withJdbiHandle(handle ->
                handle.createQuery("""
                        SELECT "COMPONENT_ID"
                          FROM "ANALYSIS"
                         WHERE "ID" = :id
                        """).bind("id", analysisId).mapTo(long.class).one());
    }

    private static UUID cursor(final long outboxId) {
        return withJdbiHandle(handle ->
                handle.createQuery("""
                        SELECT "FANOUT_CURSOR"
                          FROM "ASSESSMENT_SYNC_OUTBOX"
                         WHERE "ID" = :id
                        """).bind("id", outboxId).mapTo(UUID.class).one());
    }

    private static int outboxCount() {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT COUNT(*)::int
                          FROM "ASSESSMENT_SYNC_OUTBOX"
                        """).mapTo(int.class).one());
    }
}
