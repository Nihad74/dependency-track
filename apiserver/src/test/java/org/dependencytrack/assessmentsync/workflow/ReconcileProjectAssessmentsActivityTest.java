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

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao.WorkRow;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.FindingKey;
import org.dependencytrack.notification.NotificationScope;
import org.dependencytrack.notification.NotificationTestUtil;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileProjectAssessmentsRes;
import org.dependencytrack.proto.internal.workflow.v1.SynchronizeProjectAssessmentsArg;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class ReconcileProjectAssessmentsActivityTest extends PersistenceCapableTest {

    private static final ActivityContext CONTEXT = () -> UUID.randomUUID();

    @BeforeEach
    void enableActiveMode() {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "ACTIVE");
    }

    @AfterEach
    void clearMode() {
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
        ReconcileProjectAssessmentsActivity.failAfterWriteForTest(false);
    }

    @Test
    void agreeingSourcesCopyOneTupleAndBothExplanations() throws Exception {
        final ReconcileFixture fixture = ReconcileFixture.twoSources(qm);
        NotificationTestUtil.createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);
        ReconcileFixture.requestFull(fixture.target.getUuid());

        final ReconcileProjectAssessmentsRes result = reconcile(fixture.target.getUuid(), 50);

        final long componentId = fixture.library().getId();
        final long vulnerabilityId = fixture.vulnerability.getId();
        assertThat(result.getApplied()).isEqualTo(1);
        assertThat(result.getWithdrawn()).isZero();
        assertThat(result.getRefreshRevision()).isEqualTo(1);
        assertThat(result.getHasMore()).isFalse();
        assertThat(ReconcileFixture.state(componentId, vulnerabilityId)).isEqualTo("EXPLOITABLE");
        assertThat(ReconcileFixture.owner(componentId, vulnerabilityId)).isEqualTo("INHERITED");
        assertThat(ReconcileFixture.details(componentId, vulnerabilityId)).isNull();
        assertThat(ReconcileFixture.contributionDetails(componentId, vulnerabilityId))
                .containsExactly(ReconcileFixture.ALPINE_DETAILS, ReconcileFixture.DEBIAN_DETAILS);
        assertThat(ReconcileFixture.copiedCommentTimestamp(componentId, vulnerabilityId))
                .isEqualTo(ReconcileFixture.ALPINE_NOTE_AT);
        assertThat(notificationGroups()).containsExactly("PROJECT_AUDIT_CHANGE");
    }

    @Test
    void conflictingSourcesWithdrawAnInheritedRow() throws Exception {
        final ReconcileFixture fixture = ReconcileFixture.twoSources(qm);
        ReconcileFixture.requestFull(fixture.target.getUuid());
        reconcile(fixture.target.getUuid(), 50);
        qm.makeAnalysis(new MakeAnalysisCommand(fixture.debianLibrary, fixture.vulnerability)
                .withState(AnalysisState.NOT_AFFECTED)
                .withDetails("from-debian-disagrees")
                .withOptions(Set.of(
                        MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL, MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        ReconcileFixture.requestFull(fixture.target.getUuid());

        final ReconcileProjectAssessmentsRes result = reconcile(fixture.target.getUuid(), 50);

        final long componentId = fixture.library().getId();
        final long vulnerabilityId = fixture.vulnerability.getId();
        assertThat(result.getWithdrawn()).isEqualTo(1);
        assertThat(result.getApplied()).isZero();
        assertThat(ReconcileFixture.state(componentId, vulnerabilityId)).isEqualTo("NOT_SET");
        assertThat(ReconcileFixture.owner(componentId, vulnerabilityId)).isEqualTo("NEUTRAL");
        assertThat(ReconcileFixture.details(componentId, vulnerabilityId)).isNull();
        assertThat(ReconcileFixture.contributionCount(componentId, vulnerabilityId))
                .isZero();
    }

    @Test
    void analysisWithoutOriginIsUnchanged() throws Exception {
        final ReconcileFixture fixture = ReconcileFixture.twoSources(qm);
        qm.makeAnalysis(new MakeAnalysisCommand(fixture.library(), fixture.vulnerability)
                .withState(AnalysisState.IN_TRIAGE)
                .withDetails("keep-me")
                .withOptions(Set.of(
                        MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL, MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        useJdbiTransaction(handle -> handle.createUpdate("""
                        DELETE FROM "ASSESSMENT_ORIGIN"
                         WHERE "ANALYSIS_ID" IN (
                           SELECT "ID" FROM "ANALYSIS"
                            WHERE "COMPONENT_ID" = :componentId
                              AND "VULNERABILITY_ID" = :vulnerabilityId
                         )
                        """)
                .bind("componentId", fixture.library().getId())
                .bind("vulnerabilityId", fixture.vulnerability.getId())
                .execute());
        ReconcileFixture.requestFull(fixture.target.getUuid());

        final ReconcileProjectAssessmentsRes result = reconcile(fixture.target.getUuid(), 50);

        assertThat(result.getApplied()).isZero();
        assertThat(result.getWithdrawn()).isZero();
        assertThat(result.getSkipped()).isEqualTo(1);
        assertThat(ReconcileFixture.state(fixture.library().getId(), fixture.vulnerability.getId()))
                .isEqualTo("IN_TRIAGE");
        assertThat(ReconcileFixture.details(fixture.library().getId(), fixture.vulnerability.getId()))
                .isEqualTo("keep-me");
        assertThat(ReconcileFixture.owner(fixture.library().getId(), fixture.vulnerability.getId()))
                .isNull();
        assertThat(ReconcileFixture.contributionCount(fixture.library().getId(), fixture.vulnerability.getId()))
                .isZero();
    }

    @Test
    void localRowStaysWhenTheSourceChanges() throws Exception {
        final ReconcileFixture fixture = ReconcileFixture.twoSources(qm);
        qm.makeAnalysis(new MakeAnalysisCommand(fixture.library(), fixture.vulnerability)
                .withState(AnalysisState.FALSE_POSITIVE)
                .withOptions(Set.of(
                        MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL, MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        ReconcileFixture.requestFull(fixture.target.getUuid());

        final ReconcileProjectAssessmentsRes result = reconcile(fixture.target.getUuid(), 50);

        assertThat(result.getApplied()).isZero();
        assertThat(result.getRefreshRevision()).isZero();
        assertThat(ReconcileFixture.state(fixture.library().getId(), fixture.vulnerability.getId()))
                .isEqualTo("FALSE_POSITIVE");
        assertThat(ReconcileFixture.owner(fixture.library().getId(), fixture.vulnerability.getId()))
                .isEqualTo("LOCAL");
        assertThat(ReconcileFixture.contributionCount(fixture.library().getId(), fixture.vulnerability.getId()))
                .isZero();
    }

    @Test
    void localCommentRemains() throws Exception {
        final ReconcileFixture fixture = ReconcileFixture.twoSources(qm);
        qm.makeAnalysis(new MakeAnalysisCommand(fixture.library(), fixture.vulnerability)
                .withDecisionAction(MakeAnalysisCommand.DecisionAction.COMMENT_ONLY)
                .withComment("local-only")
                .withCommenter("pat")
                .withOptions(Set.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        ReconcileFixture.requestFull(fixture.target.getUuid());

        reconcile(fixture.target.getUuid(), 50);

        assertThat(ReconcileFixture.state(fixture.library().getId(), fixture.vulnerability.getId()))
                .isEqualTo("EXPLOITABLE");
        assertThat(ReconcileFixture.owner(fixture.library().getId(), fixture.vulnerability.getId()))
                .isEqualTo("INHERITED");
        assertThat(ReconcileFixture.localComments(fixture.library().getId(), fixture.vulnerability.getId()))
                .contains("local-only");
    }

    @Test
    void removingOneAgreeingSourceDropsOnlyThatContribution() throws Exception {
        final ReconcileFixture fixture = ReconcileFixture.twoSources(qm);
        ReconcileFixture.requestFull(fixture.target.getUuid());
        reconcile(fixture.target.getUuid(), 50);
        useJdbiTransaction(handle -> handle.createUpdate("""
                        DELETE FROM "ANALYSIS" WHERE "ID" = :analysisId
                        """)
                .bind("analysisId", fixture.debianAnalysisId)
                .execute());
        ReconcileFixture.requestFull(fixture.target.getUuid());

        final ReconcileProjectAssessmentsRes result = reconcile(fixture.target.getUuid(), 50);

        assertThat(result.getRefreshRevision()).isZero();
        assertThat(ReconcileFixture.state(fixture.library().getId(), fixture.vulnerability.getId()))
                .isEqualTo("EXPLOITABLE");
        assertThat(ReconcileFixture.owner(fixture.library().getId(), fixture.vulnerability.getId()))
                .isEqualTo("INHERITED");
        assertThat(ReconcileFixture.contributionDetails(fixture.library().getId(), fixture.vulnerability.getId()))
                .containsExactly(ReconcileFixture.ALPINE_DETAILS);
    }

    @Test
    void fullPassAndFindingPassBothMoveTheCursor() throws Exception {
        final ReconcileFixture full = ReconcileFixture.oneSource(qm, 2);
        ReconcileFixture.requestFull(full.target.getUuid());
        final long firstComponentId =
                Math.min(full.libraries.get(0).getId(), full.libraries.get(1).getId());
        final long vulnerabilityId = full.vulnerability.getId();

        final ReconcileProjectAssessmentsRes firstPage = reconcile(full.target.getUuid(), 1);

        assertThat(firstPage.getHasMore()).isTrue();
        assertThat(firstPage.getApplied()).isEqualTo(1);
        WorkRow afterFirst = ReconcileFixture.work(full.target.getUuid());
        assertThat(afterFirst).isNotNull();
        assertThat(afterFirst.cursorComponentId()).isEqualTo(firstComponentId);
        assertThat(afterFirst.cursorVulnerabilityId()).isEqualTo(vulnerabilityId);
        assertThat(afterFirst.completedRevision()).isZero();

        final ReconcileProjectAssessmentsRes secondPage = reconcile(full.target.getUuid(), 1);

        assertThat(secondPage.getHasMore()).isFalse();
        assertThat(secondPage.getApplied()).isEqualTo(1);
        final WorkRow afterFull = ReconcileFixture.work(full.target.getUuid());
        assertThat(afterFull).isNotNull();
        assertThat(afterFull.cursorComponentId()).isNull();
        assertThat(afterFull.completedRevision()).isEqualTo(1);
        assertThat(ReconcileFixture.state(full.libraries.get(0).getId(), vulnerabilityId))
                .isEqualTo("EXPLOITABLE");
        assertThat(ReconcileFixture.state(full.libraries.get(1).getId(), vulnerabilityId))
                .isEqualTo("EXPLOITABLE");

        final ReconcileFixture finding = ReconcileFixture.oneSource(qm, 2);
        final long findingVulnerabilityId = finding.vulnerability.getId();
        final long lowerFindingComponentId = Math.min(
                finding.libraries.get(0).getId(), finding.libraries.get(1).getId());
        ReconcileFixture.requestFindings(
                finding.target.getUuid(),
                List.of(
                        new FindingKey(finding.libraries.get(0).getId(), findingVulnerabilityId),
                        new FindingKey(finding.libraries.get(1).getId(), findingVulnerabilityId)));

        final ReconcileProjectAssessmentsRes findingPage = reconcile(finding.target.getUuid(), 1);

        assertThat(findingPage.getHasMore()).isTrue();
        final WorkRow findingCursor = ReconcileFixture.work(finding.target.getUuid());
        assertThat(findingCursor).isNotNull();
        assertThat(findingCursor.activeFull()).isFalse();
        assertThat(findingCursor.cursorComponentId()).isEqualTo(lowerFindingComponentId);
        assertThat(findingCursor.completedRevision()).isZero();

        final ReconcileProjectAssessmentsRes findingDone = reconcile(finding.target.getUuid(), 1);

        assertThat(findingDone.getHasMore()).isFalse();
        final WorkRow findingWork = ReconcileFixture.work(finding.target.getUuid());
        assertThat(findingWork).isNotNull();
        assertThat(findingWork.completedRevision()).isEqualTo(findingWork.requestedRevision());
        assertThat(findingWork.cursorComponentId()).isNull();
    }

    @Test
    void deletedTargetAcknowledgesWork() throws Exception {
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 1);
        ReconcileFixture.requestFull(fixture.target.getUuid());
        useJdbiTransaction(handle -> handle.attach(ProjectDao.class).deleteProject(fixture.target.getUuid()));

        final ReconcileProjectAssessmentsRes result = reconcile(fixture.target.getUuid(), 50);

        assertThat(result.getTargetDeleted()).isTrue();
        assertThat(result.getHasMore()).isFalse();
        final WorkRow work = ReconcileFixture.work(fixture.target.getUuid());
        assertThat(work).isNotNull();
        assertThat(work.completedRevision()).isEqualTo(1);
        assertThat(work.requestedRevision()).isEqualTo(1);
        assertThat(work.refreshCompleted()).isEqualTo(work.refreshRequested());
    }

    @Test
    void captureModeAppliesNothingAndLeavesTheRevisionPending() throws Exception {
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 1);
        ReconcileFixture.requestFull(fixture.target.getUuid());
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        final Instant before = Instant.now();
        try {
            final ReconcileProjectAssessmentsRes result = reconcile(fixture.target.getUuid(), 50);

            assertThat(result.getHasMore()).isFalse();
            assertThat(result.getApplied()).isZero();
            assertThat(result.getTargetDeleted()).isFalse();
            assertThat(ReconcileFixture.state(fixture.library().getId(), fixture.vulnerability.getId()))
                    .isNull();
            final WorkRow work = ReconcileFixture.work(fixture.target.getUuid());
            assertThat(work).isNotNull();
            assertThat(work.requestedRevision()).isEqualTo(1);
            assertThat(work.completedRevision()).isZero();
            assertThat(work.nextDispatchAt()).isAfter(before.plus(Duration.ofMinutes(9)));
        } finally {
            MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
        }
    }

    @Test
    void projectionWriteRollsBackWithTheBatch() {
        final ReconcileFixture fixture = ReconcileFixture.twoSources(qm);
        NotificationTestUtil.createCatchAllNotificationRule(qm, NotificationScope.PORTFOLIO);
        ReconcileFixture.requestFull(fixture.target.getUuid());
        ReconcileProjectAssessmentsActivity.failAfterWriteForTest(true);
        try {
            assertThatThrownBy(() -> reconcile(fixture.target.getUuid(), 50))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessage("forced assessment reconciliation failure");
        } finally {
            ReconcileProjectAssessmentsActivity.failAfterWriteForTest(false);
        }

        assertThat(ReconcileFixture.state(fixture.library().getId(), fixture.vulnerability.getId()))
                .isNull();
        assertThat(ReconcileFixture.contributionCount(fixture.library().getId(), fixture.vulnerability.getId()))
                .isZero();
        assertThat(notificationGroups()).isEmpty();
        final WorkRow work = ReconcileFixture.work(fixture.target.getUuid());
        assertThat(work).isNotNull();
        assertThat(work.completedRevision()).isZero();
        assertThat(work.activeRevision()).isNull();
        assertThat(work.cursorComponentId()).isNull();
        assertThat(work.refreshRequested()).isZero();
    }

    private static ReconcileProjectAssessmentsRes reconcile(final UUID targetUuid, final int batchSize)
            throws Exception {
        final var activity = new ReconcileProjectAssessmentsActivity(batchSize, Duration.ofMinutes(10));
        return activity.execute(
                CONTEXT,
                SynchronizeProjectAssessmentsArg.newBuilder()
                        .setProjectUuid(targetUuid.toString())
                        .build());
    }

    private static List<String> notificationGroups() {
        return withJdbiHandle(
                handle -> handle.createQuery("""
                        SELECT "GROUP"
                          FROM "NOTIFICATION_OUTBOX"
                         ORDER BY "GROUP"
                        """).mapTo(String.class).list());
    }
}
