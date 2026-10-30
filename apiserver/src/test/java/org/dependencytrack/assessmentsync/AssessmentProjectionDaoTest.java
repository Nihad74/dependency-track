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

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.assessmentsync.AssessmentConsensus.Contributor;
import org.dependencytrack.assessmentsync.AssessmentOriginDao.Origin;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao.SourceCommentWrite;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao.SourceContributionWrite;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao.StoredComment;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao.StoredContribution;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao.StoredProjection;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao.WorkerWrite;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao.WorkerWriteResult;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao.WorkerWriteStatus;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class AssessmentProjectionDaoTest extends PersistenceCapableTest {

    private static final Instant ORIGINAL_TIMESTAMP = Instant.parse("2020-01-02T03:04:05Z");
    private static final Instant REPLACEMENT_TIMESTAMP = Instant.parse("2024-05-06T07:08:09Z");

    @Test
    void shouldUpsertWholeTupleAndResetToNeutral() {
        final long analysisId = persistAnalysis(AnalysisState.NOT_SET, null);
        final long policyId = insertPolicy();
        useJdbiTransaction(handle -> handle.createUpdate("""
                        UPDATE "ANALYSIS"
                           SET "VULNERABILITY_POLICY_ID" = :policyId
                         WHERE "ID" = :analysisId
                        """)
                .bind("policyId", policyId)
                .bind("analysisId", analysisId)
                .execute());
        useJdbiTransaction(
                handle -> new AssessmentOriginDao(handle).upsertOrigin(analysisId, AssessmentOwnership.NEUTRAL, false));
        assertThat(originVersion(analysisId)).isZero();

        final WorkerWriteResult applied = inJdbiTransaction(handle -> new AssessmentProjectionDao(handle)
                .applyWorkerWrite(write(analysisId, AssessmentOwnership.INHERITED, richDecision(), "kept details", 0)));
        assertThat(applied.status()).isEqualTo(WorkerWriteStatus.APPLIED);
        assertThat(applied.decisionVersion()).isEqualTo(1);

        final StoredProjection stored =
                inJdbiTransaction(handle -> new AssessmentProjectionDao(handle).load(analysisId));
        assertThat(stored.origin()).isEqualTo(new Origin(AssessmentOwnership.INHERITED, 1, null));
        assertThat(stored.details()).isEqualTo("kept details");
        assertThat(stored.policyId()).isNull();
        assertThat(stored.decision().state()).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(stored.decision().justification()).isEqualTo(AnalysisJustification.CODE_NOT_PRESENT);
        assertThat(stored.decision().response()).isEqualTo(AnalysisResponse.WILL_NOT_FIX);
        assertThat(stored.decision().suppressed()).isTrue();
        assertThat(stored.decision().severity()).isEqualTo(Severity.MEDIUM);
        assertThat(stored.decision().cvssV2Vector()).isEqualTo("AV:L/AC:L/Au:N/C:N/I:N/A:N");
        assertThat(stored.decision().cvssV2Score()).isEqualByComparingTo("4.0");
        assertThat(stored.decision().cvssV3Score()).isEqualByComparingTo("0");
        assertThat(stored.decision().cvssV3Vector()).isNull();
        assertThat(stored.decision().cvssV4Score()).isNull();
        assertThat(stored.decision().owaspScore()).isNull();

        final WorkerWriteResult reset = inJdbiTransaction(handle -> new AssessmentProjectionDao(handle)
                .applyWorkerWrite(
                        write(analysisId, AssessmentOwnership.NEUTRAL, AssessmentDecision.neutral(), null, 1)));
        assertThat(reset.status()).isEqualTo(WorkerWriteStatus.APPLIED);
        assertThat(reset.decisionVersion()).isEqualTo(2);

        final StoredProjection cleared =
                inJdbiTransaction(handle -> new AssessmentProjectionDao(handle).load(analysisId));
        assertThat(cleared.origin()).isEqualTo(new Origin(AssessmentOwnership.NEUTRAL, 2, null));
        assertThat(cleared.decision()).isEqualTo(AssessmentDecision.neutral());
        assertThat(cleared.details()).isNull();
        assertThat(cleared.policyId()).isNull();
        assertThat(cleared.contributions()).isEmpty();
    }

    @Test
    void shouldTreatNullAndZeroScoresAsDifferent() {
        final long analysisId = persistAnalysis(AnalysisState.NOT_SET, null);
        useJdbiTransaction(
                handle -> new AssessmentOriginDao(handle).upsertOrigin(analysisId, AssessmentOwnership.NEUTRAL, false));

        final WorkerWriteResult zero = inJdbiTransaction(handle -> new AssessmentProjectionDao(handle)
                .applyWorkerWrite(write(analysisId, AssessmentOwnership.NEUTRAL, score(BigDecimal.ZERO), null, 0)));
        assertThat(zero.status()).isEqualTo(WorkerWriteStatus.APPLIED);
        assertThat(zero.decisionVersion()).isEqualTo(1);
        assertThat(inJdbiTransaction(handle -> new AssessmentProjectionDao(handle).load(analysisId))
                        .decision()
                        .cvssV2Score())
                .isEqualByComparingTo("0");

        final WorkerWriteResult sameZero = inJdbiTransaction(handle -> new AssessmentProjectionDao(handle)
                .applyWorkerWrite(
                        write(analysisId, AssessmentOwnership.NEUTRAL, score(new BigDecimal("0.00")), null, 1)));
        assertThat(sameZero.status()).isEqualTo(WorkerWriteStatus.APPLIED);
        assertThat(sameZero.decisionVersion()).isEqualTo(1);

        final WorkerWriteResult cleared = inJdbiTransaction(handle -> new AssessmentProjectionDao(handle)
                .applyWorkerWrite(write(analysisId, AssessmentOwnership.NEUTRAL, score(null), null, 1)));
        assertThat(cleared.status()).isEqualTo(WorkerWriteStatus.APPLIED);
        assertThat(cleared.decisionVersion()).isEqualTo(2);
        assertThat(inJdbiTransaction(handle -> new AssessmentProjectionDao(handle).load(analysisId))
                        .decision()
                        .cvssV2Score())
                .isNull();
    }

    @Test
    void shouldStoreContributorDetailsAndDropRemovedSources() {
        final long analysisId = persistAnalysis(AnalysisState.NOT_SET, null);
        useJdbiTransaction(
                handle -> new AssessmentOriginDao(handle).upsertOrigin(analysisId, AssessmentOwnership.NEUTRAL, false));
        final Contributor kernel = contributor("kernel");
        final Contributor firmware = contributor("firmware");

        final WorkerWriteResult applied = inJdbiTransaction(handle -> new AssessmentProjectionDao(handle)
                .applyWorkerWrite(new WorkerWrite(
                        analysisId,
                        AssessmentOwnership.INHERITED,
                        richDecision(),
                        null,
                        null,
                        null,
                        0,
                        List.of(
                                new SourceContributionWrite(kernel, "from kernel", List.of()),
                                new SourceContributionWrite(firmware, "from firmware", List.of())))));
        assertThat(applied.decisionVersion()).isEqualTo(1);

        final WorkerWriteResult removed = inJdbiTransaction(handle -> new AssessmentProjectionDao(handle)
                .applyWorkerWrite(new WorkerWrite(
                        analysisId,
                        AssessmentOwnership.INHERITED,
                        richDecision(),
                        null,
                        null,
                        AssessmentReason.SOURCE_CONFLICT,
                        1,
                        List.of(new SourceContributionWrite(kernel, "from kernel", List.of())))));
        assertThat(removed.status()).isEqualTo(WorkerWriteStatus.APPLIED);
        assertThat(removed.decisionVersion()).isEqualTo(1);

        final StoredProjection stored =
                inJdbiTransaction(handle -> new AssessmentProjectionDao(handle).load(analysisId));
        assertThat(stored.origin().lastReason()).isEqualTo(AssessmentReason.SOURCE_CONFLICT);
        assertThat(stored.contributions()).hasSize(1);
        assertThat(stored.contributions().getFirst().contributor()).isEqualTo(kernel);
        assertThat(stored.contributions().getFirst().sourceDetails()).isEqualTo("from kernel");
    }

    @Test
    void shouldPreserveSourceCommentIdentityAndOriginalTimestamp() {
        final long analysisId = persistAnalysis(AnalysisState.NOT_SET, null);
        useJdbiTransaction(handle ->
                new AssessmentOriginDao(handle).upsertOrigin(analysisId, AssessmentOwnership.INHERITED, false));
        final long originVersion = originVersion(analysisId);
        final Contributor source = contributor("kernel");

        final WorkerWriteResult applied = inJdbiTransaction(handle -> new AssessmentProjectionDao(handle)
                .applyWorkerWrite(new WorkerWrite(
                        analysisId,
                        AssessmentOwnership.INHERITED,
                        richDecision(),
                        null,
                        null,
                        null,
                        originVersion,
                        List.of(new SourceContributionWrite(
                                source,
                                "from kernel",
                                List.of(
                                        new SourceCommentWrite(17, "first text", "alice", ORIGINAL_TIMESTAMP),
                                        new SourceCommentWrite(18, "temporary note", null, ORIGINAL_TIMESTAMP)))))));
        assertThat(applied.status()).isEqualTo(WorkerWriteStatus.APPLIED);

        final WorkerWriteResult revised = inJdbiTransaction(handle -> new AssessmentProjectionDao(handle)
                .applyWorkerWrite(new WorkerWrite(
                        analysisId,
                        AssessmentOwnership.INHERITED,
                        richDecision(),
                        null,
                        null,
                        null,
                        applied.decisionVersion(),
                        List.of(new SourceContributionWrite(
                                source,
                                "from kernel",
                                List.of(new SourceCommentWrite(
                                        17, "revised text", "alice", REPLACEMENT_TIMESTAMP)))))));
        assertThat(revised.status()).isEqualTo(WorkerWriteStatus.APPLIED);
        assertThat(revised.decisionVersion()).isEqualTo(applied.decisionVersion());

        final StoredProjection stored =
                inJdbiTransaction(handle -> new AssessmentProjectionDao(handle).load(analysisId));
        assertThat(stored.contributions()).hasSize(1);
        assertThat(stored.contributions().getFirst().comments()).hasSize(1);
        assertThat(stored.contributions().getFirst().comments().getFirst().sourceCommentId())
                .isEqualTo(17);
        assertThat(stored.contributions().getFirst().comments().getFirst().comment())
                .isEqualTo("revised text");
        assertThat(stored.contributions().getFirst().comments().getFirst().commenter())
                .isEqualTo("alice");
        assertThat(stored.contributions().getFirst().comments().getFirst().originalTimestamp())
                .isEqualTo(ORIGINAL_TIMESTAMP);
    }

    @Test
    void shouldKeepLocalAnalysisCommentsWhenReplacingContributions() {
        final long analysisId = persistAnalysis(AnalysisState.NOT_SET, "keep this local note");
        useJdbiTransaction(
                handle -> new AssessmentOriginDao(handle).upsertOrigin(analysisId, AssessmentOwnership.NEUTRAL, false));
        inJdbiTransaction(handle -> new AssessmentProjectionDao(handle)
                .applyWorkerWrite(new WorkerWrite(
                        analysisId,
                        AssessmentOwnership.INHERITED,
                        richDecision(),
                        null,
                        null,
                        null,
                        0,
                        List.of(new SourceContributionWrite(
                                contributor("kernel"),
                                "from kernel",
                                List.of(new SourceCommentWrite(
                                        17, "copied source note", "alice", ORIGINAL_TIMESTAMP)))))));

        assertThat(localComments(analysisId)).containsExactly("keep this local note");
        final StoredProjection stored =
                inJdbiTransaction(handle -> new AssessmentProjectionDao(handle).load(analysisId));
        assertThat(stored.contributions().getFirst().comments().getFirst().comment())
                .isEqualTo("copied source note");
    }

    @Test
    void shouldRejectWorkerWriteWhenOriginIsLocalOrVersionMoved() {
        final long localAnalysisId = persistAnalysis(AnalysisState.EXPLOITABLE, null);
        useJdbiTransaction(handle ->
                new AssessmentOriginDao(handle).upsertOrigin(localAnalysisId, AssessmentOwnership.LOCAL, false));
        assertThat(originVersion(localAnalysisId)).isEqualTo(1);
        final WorkerWriteResult rejectedLocal = inJdbiTransaction(handle -> new AssessmentProjectionDao(handle)
                .applyWorkerWrite(new WorkerWrite(
                        localAnalysisId,
                        AssessmentOwnership.INHERITED,
                        richDecision(),
                        null,
                        null,
                        AssessmentReason.NO_AUTHORED_SOURCE,
                        1,
                        List.of(new SourceContributionWrite(contributor("kernel"), "from kernel", List.of())))));
        assertThat(rejectedLocal.status()).isEqualTo(WorkerWriteStatus.REJECTED_OWNERSHIP);
        assertThat(rejectedLocal.decisionVersion()).isEqualTo(1);
        final StoredProjection local =
                inJdbiTransaction(handle -> new AssessmentProjectionDao(handle).load(localAnalysisId));
        assertThat(local.origin()).isEqualTo(new Origin(AssessmentOwnership.LOCAL, 1, null));
        assertThat(local.decision().state()).isEqualTo(AnalysisState.EXPLOITABLE);
        assertThat(local.contributions()).isEmpty();

        final long inheritedAnalysisId = persistAnalysis(AnalysisState.NOT_SET, null);
        useJdbiTransaction(handle -> new AssessmentOriginDao(handle)
                .upsertOrigin(inheritedAnalysisId, AssessmentOwnership.INHERITED, false));
        final long inheritedVersion = originVersion(inheritedAnalysisId);
        final WorkerWriteResult first = inJdbiTransaction(handle -> new AssessmentProjectionDao(handle)
                .applyWorkerWrite(write(
                        inheritedAnalysisId, AssessmentOwnership.INHERITED, richDecision(), null, inheritedVersion)));
        assertThat(first.status()).isEqualTo(WorkerWriteStatus.APPLIED);
        assertThat(first.decisionVersion()).isEqualTo(inheritedVersion + 1);

        final WorkerWriteResult stale = inJdbiTransaction(handle -> new AssessmentProjectionDao(handle)
                .applyWorkerWrite(write(
                        inheritedAnalysisId,
                        AssessmentOwnership.NEUTRAL,
                        AssessmentDecision.neutral(),
                        null,
                        inheritedVersion)));
        assertThat(stale.status()).isEqualTo(WorkerWriteStatus.REJECTED_VERSION);
        assertThat(stale.decisionVersion()).isEqualTo(first.decisionVersion());
        final StoredProjection current =
                inJdbiTransaction(handle -> new AssessmentProjectionDao(handle).load(inheritedAnalysisId));
        assertThat(current.origin().owner()).isEqualTo(AssessmentOwnership.INHERITED);
        assertThat(current.origin().decisionVersion()).isEqualTo(first.decisionVersion());
        assertThat(current.decision().state()).isEqualTo(AnalysisState.NOT_AFFECTED);
    }

    @Test
    void shouldKeepContributionAfterSourceProjectDeletion() {
        final Project sourceProject = persistProject("mrt.base.linux", "5.14.121");
        final Component sourceComponent = persistComponent(sourceProject, "libc6", "2.36");
        final Vulnerability vulnerability = persistVulnerability("CVE-2099-1210");
        final long sourceAnalysisId = qm.makeAnalysis(new MakeAnalysisCommand(sourceComponent, vulnerability)
                .withState(AnalysisState.NOT_AFFECTED)
                .withOptions(EnumSet.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));

        final Project targetProject = persistProject("cmx500", "1.0.0");
        final Component targetComponent = persistComponent(targetProject, "libc6", "2.36");
        final long targetAnalysisId = qm.makeAnalysis(new MakeAnalysisCommand(targetComponent, vulnerability)
                .withState(AnalysisState.NOT_SET)
                .withOptions(EnumSet.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        final Contributor contributor = new Contributor(
                sourceProject.getUuid(), sourceComponent.getUuid(), vulnerability.getUuid(), sourceAnalysisId);
        useJdbiTransaction(handle ->
                new AssessmentOriginDao(handle).upsertOrigin(targetAnalysisId, AssessmentOwnership.NEUTRAL, false));
        inJdbiTransaction(handle -> new AssessmentProjectionDao(handle)
                .applyWorkerWrite(new WorkerWrite(
                        targetAnalysisId,
                        AssessmentOwnership.INHERITED,
                        richDecision(),
                        null,
                        null,
                        null,
                        0,
                        List.of(new SourceContributionWrite(
                                contributor,
                                "from kernel",
                                List.of(new SourceCommentWrite(
                                        17, "copied source note", "alice", ORIGINAL_TIMESTAMP)))))));

        useJdbiTransaction(handle -> handle.attach(ProjectDao.class).deleteProject(sourceProject.getUuid()));

        assertThat(analysisCount(sourceAnalysisId)).isZero();
        final StoredProjection stored =
                inJdbiTransaction(handle -> new AssessmentProjectionDao(handle).load(targetAnalysisId));
        assertThat(stored.contributions()).hasSize(1);
        assertThat(stored.contributions().getFirst().contributor()).isEqualTo(contributor);
        assertThat(stored.contributions().getFirst().sourceDetails()).isEqualTo("from kernel");
        assertThat(stored.contributions().getFirst().comments().getFirst().comment())
                .isEqualTo("copied source note");
        assertThat(stored.contributions().getFirst().comments().getFirst().originalTimestamp())
                .isEqualTo(ORIGINAL_TIMESTAMP);
    }

    @Test
    void shouldBackfillPolicyAndLocalOriginsWithoutOverwritingInherited() {
        final Project policyProject = persistProject("policy-product", "1.0.0");
        final Project localProject = persistProject("local-product", "1.0.0");
        final Project inheritedProject = persistProject("inherited-product", "1.0.0");
        final Vulnerability vulnerability = persistVulnerability("CVE-2099-1210");
        final long policyAnalysisId =
                qm.makeAnalysis(new MakeAnalysisCommand(persistComponent(policyProject, "libc6", "2.36"), vulnerability)
                        .withState(AnalysisState.NOT_AFFECTED)
                        .withOptions(EnumSet.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        final long localAnalysisId = qm.makeAnalysis(
                new MakeAnalysisCommand(persistComponent(localProject, "libssl", "3.0.11"), vulnerability)
                        .withState(AnalysisState.NOT_SET)
                        .withOptions(EnumSet.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        final long inheritedAnalysisId = qm.makeAnalysis(
                new MakeAnalysisCommand(persistComponent(inheritedProject, "busybox", "1.36.1"), vulnerability)
                        .withState(AnalysisState.IN_TRIAGE)
                        .withOptions(EnumSet.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        final long policyId = insertPolicy();
        useJdbiTransaction(handle -> {
            handle.createUpdate("""
                            UPDATE "ANALYSIS"
                               SET "VULNERABILITY_POLICY_ID" = :policyId
                             WHERE "ID" = :analysisId
                            """)
                    .bind("policyId", policyId)
                    .bind("analysisId", policyAnalysisId)
                    .execute();
            handle.createUpdate("""
                            DELETE FROM "ASSESSMENT_ORIGIN"
                             WHERE "ANALYSIS_ID" IN (:policyAnalysisId, :localAnalysisId)
                            """)
                    .bind("policyAnalysisId", policyAnalysisId)
                    .bind("localAnalysisId", localAnalysisId)
                    .execute();
            handle.createUpdate("""
                            UPDATE "ASSESSMENT_ORIGIN"
                               SET "OWNER" = 'INHERITED'
                                 , "DECISION_VERSION" = 4
                                 , "LAST_REASON" = 'SOURCE_CONFLICT'
                             WHERE "ANALYSIS_ID" = :analysisId
                            """).bind("analysisId", inheritedAnalysisId).execute();
        });

        for (final Project project : List.of(policyProject, localProject, inheritedProject)) {
            useJdbiTransaction(handle -> new AssessmentOriginDao(handle).backfillProjectOrigins(project.getUuid()));
        }

        final StoredProjection policy =
                inJdbiTransaction(handle -> new AssessmentProjectionDao(handle).load(policyAnalysisId));
        final StoredProjection local =
                inJdbiTransaction(handle -> new AssessmentProjectionDao(handle).load(localAnalysisId));
        final StoredProjection inherited =
                inJdbiTransaction(handle -> new AssessmentProjectionDao(handle).load(inheritedAnalysisId));
        assertThat(policy.origin()).isEqualTo(new Origin(AssessmentOwnership.POLICY, 0, null));
        assertThat(local.origin()).isEqualTo(new Origin(AssessmentOwnership.LOCAL, 0, null));
        assertThat(inherited.origin())
                .isEqualTo(new Origin(AssessmentOwnership.INHERITED, 4, AssessmentReason.SOURCE_CONFLICT));
        assertThat(inherited.decision().state()).isEqualTo(AnalysisState.IN_TRIAGE);

        final int relabeled = inJdbiTransaction(
                handle -> new AssessmentOriginDao(handle).backfillProjectOrigins(inheritedProject.getUuid()));
        assertThat(relabeled).isZero();
        assertThat(inJdbiTransaction(handle -> new AssessmentProjectionDao(handle).load(inheritedAnalysisId))
                        .origin())
                .isEqualTo(new Origin(AssessmentOwnership.INHERITED, 4, AssessmentReason.SOURCE_CONFLICT));
        assertThat(inJdbiTransaction(handle -> new AssessmentProjectionDao(handle).load(policyAnalysisId))
                        .origin()
                        .decisionVersion())
                .isEqualTo(0);
    }

    @Test
    void shouldApplyABatchAndReportEachRowSeparately() {
        final long first = persistAnalysis(AnalysisState.NOT_SET, null);
        final long second = persistAnalysis(AnalysisState.NOT_SET, null);
        final long stale = persistAnalysis(AnalysisState.NOT_SET, null);
        final long local = persistAnalysis(AnalysisState.EXPLOITABLE, null);
        final long missing = Long.MAX_VALUE;
        final Contributor kernel = contributor("kernel");
        final Contributor firmware = contributor("firmware");

        final List<WorkerWriteResult> results = inJdbiTransaction(handle -> new AssessmentProjectionDao(handle)
                .applyWorkerWrites(List.of(
                        new WorkerWrite(
                                first,
                                AssessmentOwnership.INHERITED,
                                richDecision(),
                                null,
                                null,
                                null,
                                0,
                                List.of(new SourceContributionWrite(
                                        kernel,
                                        "from kernel",
                                        List.of(new SourceCommentWrite(
                                                17, "kernel note", "alice", ORIGINAL_TIMESTAMP))))),
                        new WorkerWrite(
                                second,
                                AssessmentOwnership.INHERITED,
                                richDecision(),
                                null,
                                null,
                                null,
                                0,
                                List.of(new SourceContributionWrite(firmware, "from firmware", List.of()))),
                        write(stale, AssessmentOwnership.INHERITED, richDecision(), null, 5),
                        write(local, AssessmentOwnership.INHERITED, richDecision(), null, 1),
                        write(missing, AssessmentOwnership.INHERITED, richDecision(), null, 0))));

        assertThat(results)
                .extracting(WorkerWriteResult::status)
                .containsExactly(
                        WorkerWriteStatus.APPLIED,
                        WorkerWriteStatus.APPLIED,
                        WorkerWriteStatus.REJECTED_VERSION,
                        WorkerWriteStatus.REJECTED_OWNERSHIP,
                        WorkerWriteStatus.MISSING);
        assertThat(results.get(0).decisionVersion()).isEqualTo(1);
        final StoredProjection firstStored = load(first);
        assertThat(firstStored.decision()).isEqualTo(richDecision());
        assertThat(firstStored.contributions()).singleElement().satisfies(contribution -> {
            assertThat(contribution.sourceDetails()).isEqualTo("from kernel");
            assertThat(contribution.comments())
                    .extracting(StoredComment::comment)
                    .containsExactly("kernel note");
        });
        assertThat(load(second).contributions())
                .extracting(StoredContribution::sourceDetails)
                .containsExactly("from firmware");
        assertThat(load(stale).decision().state()).isEqualTo(AnalysisState.NOT_SET);
        assertThat(load(local).decision().state()).isEqualTo(AnalysisState.EXPLOITABLE);
    }

    @Test
    void shouldWriteABatchInAFixedNumberOfStatements() {
        assertThat(statementsFor(4)).isEqualTo(statementsFor(2));
    }

    private int statementsFor(final int writes) {
        final var analysisIds = new java.util.ArrayList<Long>();
        for (int i = 0; i < writes; i++) {
            analysisIds.add(persistAnalysis(AnalysisState.NOT_SET, null));
        }
        final var batch = analysisIds.stream()
                .map(id -> new WorkerWrite(
                        id,
                        AssessmentOwnership.INHERITED,
                        richDecision(),
                        null,
                        null,
                        null,
                        0,
                        List.of(new SourceContributionWrite(
                                contributor("kernel"),
                                "from kernel",
                                List.of(new SourceCommentWrite(17, "kernel note", "alice", ORIGINAL_TIMESTAMP))))))
                .toList();
        final var count = new java.util.concurrent.atomic.AtomicInteger();
        inJdbiTransaction(handle -> {
            handle.getConfig(org.jdbi.v3.core.statement.SqlStatements.class)
                    .setSqlLogger(new org.jdbi.v3.core.statement.SqlLogger() {
                        @Override
                        public void logAfterExecution(final org.jdbi.v3.core.statement.StatementContext context) {
                            count.incrementAndGet();
                        }
                    });
            return new AssessmentProjectionDao(handle).applyWorkerWrites(batch);
        });
        return count.get();
    }

    private static StoredProjection load(final long analysisId) {
        return requireNonNull(withJdbiHandle(handle -> new AssessmentProjectionDao(handle).load(analysisId)));
    }

    private long persistAnalysis(final AnalysisState state, final String comment) {
        final Project project = persistProject("cmx500-" + UUID.randomUUID(), "1.0.0");
        final Component component = persistComponent(project, "libc6", "2.36");
        final Vulnerability vulnerability = persistVulnerability("CVE-2099-" + UUID.randomUUID());
        var command = new MakeAnalysisCommand(component, vulnerability)
                .withState(state)
                .withOptions(EnumSet.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION));
        if (comment != null) {
            command = command.withComment(comment).withCommenter("product-owner");
        }
        return qm.makeAnalysis(command);
    }

    private static WorkerWrite write(
            final long analysisId,
            final AssessmentOwnership owner,
            final AssessmentDecision decision,
            final String details,
            final long expectedDecisionVersion) {
        return new WorkerWrite(analysisId, owner, decision, details, null, null, expectedDecisionVersion, List.of());
    }

    private static AssessmentDecision richDecision() {
        return AssessmentDecision.of(
                AnalysisState.NOT_AFFECTED,
                AnalysisJustification.CODE_NOT_PRESENT,
                AnalysisResponse.WILL_NOT_FIX,
                true,
                Severity.MEDIUM,
                "AV:L/AC:L/Au:N/C:N/I:N/A:N",
                new BigDecimal("4.0"),
                null,
                BigDecimal.ZERO,
                null,
                null,
                null,
                null);
    }

    private static AssessmentDecision score(final BigDecimal cvssV2Score) {
        return AssessmentDecision.of(
                AnalysisState.NOT_SET,
                AnalysisJustification.NOT_SET,
                AnalysisResponse.NOT_SET,
                false,
                null,
                null,
                cvssV2Score,
                null,
                null,
                null,
                null,
                null,
                null);
    }

    private static Contributor contributor(final String name) {
        return new Contributor(
                UUID.nameUUIDFromBytes(("project-" + name).getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                UUID.nameUUIDFromBytes(("component-" + name).getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                UUID.nameUUIDFromBytes(("vuln-" + name).getBytes(java.nio.charset.StandardCharsets.UTF_8)),
                name.equals("kernel") ? 901 : 902);
    }

    private Project persistProject(final String name, final String version) {
        final var project = new Project();
        project.setName(name);
        project.setVersion(version);
        return qm.persist(project);
    }

    private Component persistComponent(final Project project, final String name, final String version) {
        final var component = new Component();
        component.setProject(project);
        component.setName(name);
        component.setVersion(version);
        component.setClassifier(Classifier.LIBRARY);
        return qm.persist(component);
    }

    private Vulnerability persistVulnerability(final String vulnId) {
        final var vulnerability = new Vulnerability();
        vulnerability.setVulnId(vulnId);
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setSeverity(Severity.HIGH);
        return qm.persist(vulnerability);
    }

    private static long insertPolicy() {
        return inJdbiTransaction(
                handle -> handle.createQuery("""
                        INSERT INTO "VULNERABILITY_POLICY" ("NAME", "ANALYSIS", "CONDITION")
                        VALUES ('kernel-policy', '{}'::jsonb, 'true')
                        RETURNING "ID"
                        """).mapTo(long.class).one());
    }

    private static List<String> localComments(final long analysisId) {
        return inJdbiTransaction(handle -> handle.createQuery("""
                        SELECT "COMMENT"
                          FROM "ANALYSISCOMMENT"
                         WHERE "ANALYSIS_ID" = :analysisId
                         ORDER BY "ID"
                        """)
                .bind("analysisId", analysisId)
                .mapTo(String.class)
                .list());
    }

    private static int analysisCount(final long analysisId) {
        return inJdbiTransaction(handle -> handle.createQuery("""
                        SELECT COUNT(*)
                          FROM "ANALYSIS"
                         WHERE "ID" = :analysisId
                        """)
                .bind("analysisId", analysisId)
                .mapTo(int.class)
                .one());
    }

    private static long originVersion(final long analysisId) {
        return withJdbiHandle(handle -> requireNonNull(new AssessmentOriginDao(handle).findOrigin(analysisId)))
                .decisionVersion();
    }
}
