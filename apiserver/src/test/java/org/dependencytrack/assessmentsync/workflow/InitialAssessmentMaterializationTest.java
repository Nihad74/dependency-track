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

import org.cyclonedx.proto.v1_7.Bom;
import org.cyclonedx.proto.v1_7.Property;
import org.cyclonedx.proto.v1_7.Source;
import org.cyclonedx.proto.v1_7.VulnerabilityAffects;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.filestorage.memory.MemoryFileStorage;
import org.dependencytrack.filestorage.proto.v1.FileMetadata;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.NotificationSubjectDao;
import org.dependencytrack.notification.proto.v1.NewVulnerabilitySubject;
import org.dependencytrack.notification.proto.v1.VulnerabilityAnalysisDecisionChangeSubject;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.plugin.runtime.PluginManager;
import org.dependencytrack.policy.cel.CelVulnerabilityPolicyEvaluator;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicy;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyAnalysis;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyDao;
import org.dependencytrack.policy.vulnerability.VulnerabilityPolicyOperation;
import org.dependencytrack.proto.internal.workflow.v1.AnalysisTrigger;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileVulnAnalysisResultsArg;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.dependencytrack.vulnanalysis.ReconcileVulnAnalysisResultsActivity;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.notification.NotificationTestUtil.createCatchAllNotificationRule;
import static org.dependencytrack.notification.NotificationTestUtil.getNotificationOutbox;
import static org.dependencytrack.notification.NotificationTestUtil.truncateNotificationOutbox;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_NEW_VULNERABILITY;
import static org.dependencytrack.notification.proto.v1.Group.GROUP_PROJECT_AUDIT_CHANGE;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.mockito.Mockito.mock;

class InitialAssessmentMaterializationTest extends PersistenceCapableTest {

    private static final ActivityContext CONTEXT = () -> UUID.randomUUID();

    private final MemoryFileStorage fileStorage = new MemoryFileStorage();
    private final PluginManager pluginManager = mock(PluginManager.class);

    @BeforeEach
    void subscribe() {
        createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);
    }

    @AfterEach
    void clearMode() {
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
    }

    @Test
    void inheritedSuppressionExcludesTheNewVulnerabilitySubject() throws Exception {
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 1);
        suppressSource(fixture.alpineAnalysisId);
        dropTargetFinding(fixture.library().getId(), fixture.vulnerability.getId());
        dropEmbedding(fixture.target.getId());
        truncateNotificationOutbox();
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "ACTIVE");
        try {
            reconcile(fixture);

            assertThat(ReconcileFixture.owner(fixture.library().getId(), fixture.vulnerability.getId()))
                    .isEqualTo("INHERITED");
            assertThat(ReconcileFixture.state(fixture.library().getId(), fixture.vulnerability.getId()))
                    .isEqualTo("EXPLOITABLE");
            assertThat(suppressed(fixture.library().getId(), fixture.vulnerability.getId()))
                    .isTrue();
            assertThat(embeddingCount(fixture.target.getId())).isPositive();
            assertThat(newVulnerabilitySubjects(fixture.library().getId(), fixture.vulnerability.getId()))
                    .isEmpty();
            assertThat(getNotificationOutbox())
                    .extracting(org.dependencytrack.notification.proto.v1.Notification::getGroup)
                    .doesNotContain(GROUP_NEW_VULNERABILITY)
                    .contains(GROUP_PROJECT_AUDIT_CHANGE);
        } finally {
            MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
        }
    }

    @Test
    void replacedPolicyOutcomeEmitsOneFinalAuditNotification() throws Exception {
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 1);
        useJdbiTransaction(handle -> handle.createUpdate("""
                        UPDATE "ANALYSIS"
                           SET "STATE" = 'FALSE_POSITIVE'
                             , "SUPPRESSED" = TRUE
                         WHERE "ID" = :analysisId
                        """)
                .bind("analysisId", fixture.alpineAnalysisId)
                .execute());
        final long targetAnalysisId = qm.makeAnalysis(new MakeAnalysisCommand(fixture.library(), fixture.vulnerability)
                .withState(AnalysisState.NOT_AFFECTED)
                .withOptions(Set.of(
                        MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL, MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        useJdbiTransaction(handle -> {
            final var analysis = new VulnerabilityPolicyAnalysis();
            analysis.setState(VulnerabilityPolicyAnalysis.State.NOT_AFFECTED);
            final var policy = new VulnerabilityPolicy();
            policy.setName("stale-" + fixture.target.getUuid());
            policy.setCondition("component.name == \"definitely-not-libfoo\"");
            policy.setAnalysis(analysis);
            policy.setOperationMode(VulnerabilityPolicyOperation.APPLY);
            final var created = handle.attach(VulnerabilityPolicyDao.class).create(policy);
            assertThat(created).isNotNull();
            handle.createUpdate("""
                            UPDATE "ANALYSIS"
                               SET "VULNERABILITY_POLICY_ID" = :policyId
                             WHERE "ID" = :analysisId
                            """)
                    .bind("policyId", created.id())
                    .bind("analysisId", targetAnalysisId)
                    .execute();
            handle.createUpdate("""
                            UPDATE "ASSESSMENT_ORIGIN"
                               SET "OWNER" = 'POLICY'
                             WHERE "ANALYSIS_ID" = :analysisId
                            """).bind("analysisId", targetAnalysisId).execute();
        });
        dropEmbedding(fixture.target.getId());
        truncateNotificationOutbox();
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "ACTIVE");
        try {
            reconcile(fixture);

            assertThat(ReconcileFixture.owner(fixture.library().getId(), fixture.vulnerability.getId()))
                    .isEqualTo("INHERITED");
            assertThat(ReconcileFixture.state(fixture.library().getId(), fixture.vulnerability.getId()))
                    .isEqualTo("FALSE_POSITIVE");
            assertThat(suppressed(fixture.library().getId(), fixture.vulnerability.getId()))
                    .isTrue();
            assertThat(getNotificationOutbox()).singleElement().satisfies(notification -> {
                assertThat(notification.getGroup()).isEqualTo(GROUP_PROJECT_AUDIT_CHANGE);
                final var subject = notification.getSubject().unpack(VulnerabilityAnalysisDecisionChangeSubject.class);
                assertThat(subject.getAnalysis().getState()).isEqualTo("FALSE_POSITIVE");
                assertThat(subject.getAnalysis().getSuppressed()).isTrue();
            });
        } finally {
            MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
        }
    }

    @Test
    void captureModeDoesNotWriteAnInheritedRow() throws Exception {
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 1);
        suppressSource(fixture.alpineAnalysisId);
        dropTargetFinding(fixture.library().getId(), fixture.vulnerability.getId());
        dropEmbedding(fixture.target.getId());
        truncateNotificationOutbox();
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        try {
            reconcile(fixture);

            assertThat(ReconcileFixture.owner(fixture.library().getId(), fixture.vulnerability.getId()))
                    .isNull();
            assertThat(embeddingCount(fixture.target.getId())).isZero();
            assertThat(newVulnerabilitySubjects(fixture.library().getId(), fixture.vulnerability.getId()))
                    .hasSize(1);
            assertThat(getNotificationOutbox())
                    .extracting(org.dependencytrack.notification.proto.v1.Notification::getGroup)
                    .contains(GROUP_NEW_VULNERABILITY);
        } finally {
            MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
        }
    }

    private void reconcile(final ReconcileFixture fixture) throws Exception {
        final Bom vdr = Bom.newBuilder()
                .addVulnerabilities(org.cyclonedx.proto.v1_7.Vulnerability.newBuilder()
                        .setId(fixture.vulnerability.getVulnId())
                        .setSource(Source.newBuilder().setName("INTERNAL").build())
                        .addProperties(Property.newBuilder()
                                .setName("dependencytrack:internal:vulnerability-id")
                                .setValue(Long.toString(fixture.vulnerability.getId()))
                                .build())
                        .addAffects(VulnerabilityAffects.newBuilder()
                                .setRef(Long.toString(fixture.library().getId()))
                                .build())
                        .build())
                .build();
        final FileMetadata metadata = fileStorage.store(
                "vuln-analysis/vdr/" + fixture.target.getUuid() + ".proto",
                "application/protobuf",
                new ByteArrayInputStream(vdr.toByteArray()));
        final var activity = new ReconcileVulnAnalysisResultsActivity(
                fileStorage, pluginManager, new CelVulnerabilityPolicyEvaluator());
        activity.execute(
                CONTEXT,
                ReconcileVulnAnalysisResultsArg.newBuilder()
                        .setProjectUuid(fixture.target.getUuid().toString())
                        .setAnalysisTrigger(AnalysisTrigger.ANALYSIS_TRIGGER_MANUAL)
                        .addAnalyzerResults(ReconcileVulnAnalysisResultsArg.AnalyzerResult.newBuilder()
                                .setAnalyzerName("internal")
                                .setSuccessful(true)
                                .setVdrFileMetadata(metadata)
                                .build())
                        .build());
    }

    private static void suppressSource(final long analysisId) {
        useJdbiTransaction(handle ->
                handle.createUpdate("""
                        UPDATE "ANALYSIS"
                           SET "SUPPRESSED" = TRUE
                         WHERE "ID" = :analysisId
                        """).bind("analysisId", analysisId).execute());
    }

    private static void dropTargetFinding(final long componentId, final long vulnerabilityId) {
        useJdbiTransaction(handle -> {
            handle.createUpdate("""
                            DELETE FROM "FINDINGATTRIBUTION"
                             WHERE "COMPONENT_ID" = :componentId
                               AND "VULNERABILITY_ID" = :vulnerabilityId
                            """)
                    .bind("componentId", componentId)
                    .bind("vulnerabilityId", vulnerabilityId)
                    .execute();
            handle.createUpdate("""
                            DELETE FROM "COMPONENTS_VULNERABILITIES"
                             WHERE "COMPONENT_ID" = :componentId
                               AND "VULNERABILITY_ID" = :vulnerabilityId
                            """)
                    .bind("componentId", componentId)
                    .bind("vulnerabilityId", vulnerabilityId)
                    .execute();
        });
    }

    private static void dropEmbedding(final long projectId) {
        useJdbiTransaction(
                handle -> handle.createUpdate("""
                        DELETE FROM "ASSESSMENT_EMBEDDING"
                         WHERE "TARGET_PROJECT_ID" = :projectId
                        """).bind("projectId", projectId).execute());
    }

    private static int embeddingCount(final long projectId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT COUNT(*)::int
                          FROM "ASSESSMENT_EMBEDDING"
                         WHERE "TARGET_PROJECT_ID" = :projectId
                        """)
                .bind("projectId", projectId)
                .mapTo(int.class)
                .one());
    }

    private static boolean suppressed(final long componentId, final long vulnerabilityId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "SUPPRESSED"
                          FROM "ANALYSIS"
                         WHERE "COMPONENT_ID" = :componentId
                           AND "VULNERABILITY_ID" = :vulnerabilityId
                        """)
                .bind("componentId", componentId)
                .bind("vulnerabilityId", vulnerabilityId)
                .mapTo(boolean.class)
                .one());
    }

    private static List<NewVulnerabilitySubject> newVulnerabilitySubjects(
            final long componentId, final long vulnerabilityId) {
        return withJdbiHandle(handle -> handle.attach(NotificationSubjectDao.class)
                .getForNewVulnerabilities(List.of(componentId), List.of(vulnerabilityId), false));
    }
}
