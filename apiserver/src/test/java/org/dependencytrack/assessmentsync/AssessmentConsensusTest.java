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

import org.dependencytrack.assessmentsync.AssessmentConsensus.Agreed;
import org.dependencytrack.assessmentsync.AssessmentConsensus.Conflict;
import org.dependencytrack.assessmentsync.AssessmentConsensus.Contributor;
import org.dependencytrack.assessmentsync.AssessmentConsensus.Result;
import org.dependencytrack.assessmentsync.AssessmentConsensus.SourceAssessment;
import org.dependencytrack.assessmentsync.AssessmentConsensus.Unavailable;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Severity;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class AssessmentConsensusTest {

    private static final Contributor FIRST = contributor(
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000001",
            1L);
    private static final Contributor SECOND = contributor(
            "00000000-0000-0000-0000-000000000002",
            "00000000-0000-0000-0000-000000000002",
            "00000000-0000-0000-0000-000000000002",
            2L);
    private static final Contributor THIRD = contributor(
            "00000000-0000-0000-0000-000000000003",
            "00000000-0000-0000-0000-000000000003",
            "00000000-0000-0000-0000-000000000003",
            3L);

    private static final AssessmentDecision BASE = AssessmentDecision.of(
            AnalysisState.NOT_AFFECTED,
            AnalysisJustification.CODE_NOT_PRESENT,
            AnalysisResponse.WILL_NOT_FIX,
            false,
            Severity.HIGH,
            "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            new BigDecimal("7.5"),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            new BigDecimal("9.8"),
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            new BigDecimal("9.3"),
            "(SL:1/M:1/O:0/S:2/ED:1/EE:1/A:1/ID:1/LC:2/LI:1/LAV:1/LAC:1/FD:1/RD:1/NC:2/PV:1)",
            new BigDecimal("5.5"));

    @Test
    void shouldAgreeOnASingleSource() {
        final Result result = AssessmentConsensus.resolve(
                List.of(source(FIRST, AssessmentOwnership.LOCAL, BASE, "kernel package is not affected")));

        assertThat(result).isInstanceOfSatisfying(Agreed.class, agreed -> {
            assertThat(agreed.decision()).isEqualTo(BASE);
            assertThat(agreed.decision().state()).isEqualTo(AnalysisState.NOT_AFFECTED);
            assertThat(agreed.contributors()).containsExactly(FIRST);
        });
    }

    @Test
    void shouldAgreeWhenExplanationsDiffer() {
        final Result result = AssessmentConsensus.resolve(List.of(
                source(FIRST, AssessmentOwnership.LOCAL, BASE, "kernel package is not affected in this build"),
                source(SECOND, AssessmentOwnership.POLICY, BASE, "not reachable from the product entry point")));

        assertThat(result).isInstanceOfSatisfying(Agreed.class, agreed -> {
            assertThat(agreed.decision()).isEqualTo(BASE);
            assertThat(agreed.contributors()).containsExactly(FIRST, SECOND);
        });
    }

    @Test
    void shouldConflictWhenStateDiffers() {
        assertFieldConflict(withState(AnalysisState.EXPLOITABLE));
    }

    @Test
    void shouldConflictWhenJustificationDiffers() {
        assertFieldConflict(withJustification(AnalysisJustification.CODE_NOT_REACHABLE));
    }

    @Test
    void shouldConflictWhenResponseDiffers() {
        assertFieldConflict(withResponse(AnalysisResponse.UPDATE));
    }

    @Test
    void shouldConflictWhenSuppressionDiffers() {
        assertFieldConflict(withSuppressed(true));
    }

    @Test
    void shouldConflictWhenSeverityDiffers() {
        assertFieldConflict(withSeverity(Severity.CRITICAL));
    }

    @Test
    void shouldConflictWhenSeverityOverrideIsNullVersusExplicit() {
        final AssessmentDecision explicit = withSeverity(Severity.UNASSIGNED);
        final AssessmentDecision absent = withSeverity(null);

        assertThat(absent.severity()).isNull();
        assertThat(explicit.severity()).isEqualTo(Severity.UNASSIGNED);
        assertThat(absent).isNotEqualTo(explicit);

        final Result result = AssessmentConsensus.resolve(List.of(
                source(FIRST, AssessmentOwnership.LOCAL, absent, "no override"),
                source(SECOND, AssessmentOwnership.LOCAL, explicit, "explicit unassigned")));

        assertThat(result)
                .isInstanceOfSatisfying(
                        Conflict.class,
                        conflict -> assertThat(conflict.contributors()).containsExactly(FIRST, SECOND));
    }

    @Test
    void shouldConflictWhenCvssV2VectorDiffers() {
        assertFieldConflict(withCvssV2Vector("AV:L/AC:L/Au:N/C:N/I:N/A:N"));
    }

    @Test
    void shouldConflictWhenCvssV2ScoreDiffers() {
        assertFieldConflict(withCvssV2Score(new BigDecimal("1.0")));
    }

    @Test
    void shouldConflictWhenCvssV3VectorDiffers() {
        assertFieldConflict(withCvssV3Vector("CVSS:3.1/AC:L/AV:N/PR:N/UI:N/S:U/C:H/I:H/A:H"));
    }

    @Test
    void shouldConflictWhenCvssV3ScoreDiffers() {
        assertFieldConflict(withCvssV3Score(new BigDecimal("0")));
    }

    @Test
    void shouldConflictWhenCvssV4VectorDiffers() {
        assertFieldConflict(withCvssV4Vector("CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"));
    }

    @Test
    void shouldConflictWhenCvssV4ScoreDiffers() {
        assertFieldConflict(withCvssV4Score(new BigDecimal("10")));
    }

    @Test
    void shouldConflictWhenOwaspVectorDiffers() {
        assertFieldConflict(withOwaspVector("(SL:0/M:0)"));
    }

    @Test
    void shouldConflictWhenOwaspScoreDiffers() {
        assertFieldConflict(withOwaspScore(new BigDecimal("0.1")));
    }

    @Test
    void shouldConflictWhenScoreIsNullVersusZero() {
        assertThat(withCvssV2Score(null).cvssV2Score()).isNull();
        assertThat(withCvssV2Score(BigDecimal.ZERO).cvssV2Score()).isEqualByComparingTo("0");
        assertNullConflictsWithZero(withCvssV2Score(null), withCvssV2Score(BigDecimal.ZERO));

        assertThat(withCvssV3Score(null).cvssV3Score()).isNull();
        assertThat(withCvssV3Score(BigDecimal.ZERO).cvssV3Score()).isEqualByComparingTo("0");
        assertNullConflictsWithZero(withCvssV3Score(null), withCvssV3Score(BigDecimal.ZERO));

        assertThat(withCvssV4Score(null).cvssV4Score()).isNull();
        assertThat(withCvssV4Score(BigDecimal.ZERO).cvssV4Score()).isEqualByComparingTo("0");
        assertNullConflictsWithZero(withCvssV4Score(null), withCvssV4Score(BigDecimal.ZERO));

        assertThat(withOwaspScore(null).owaspScore()).isNull();
        assertThat(withOwaspScore(BigDecimal.ZERO).owaspScore()).isEqualByComparingTo("0");
        assertNullConflictsWithZero(withOwaspScore(null), withOwaspScore(BigDecimal.ZERO));
    }

    @Test
    void shouldAgreeWhenDecimalScalesDiffer() {
        final AssessmentDecision scaleOne = withScores(new BigDecimal("1.0"));
        final AssessmentDecision scaleTwo = withScores(new BigDecimal("1.00"));

        assertThat(scaleOne).isEqualTo(scaleTwo);
        assertThat(scaleOne.cvssV2Score()).isEqualByComparingTo("1.00");
        assertThat(scaleOne.cvssV3Score()).isEqualByComparingTo("1.00");
        assertThat(scaleOne.cvssV4Score()).isEqualByComparingTo("1.00");
        assertThat(scaleOne.owaspScore()).isEqualByComparingTo("1.00");

        final Result result = AssessmentConsensus.resolve(List.of(
                source(SECOND, AssessmentOwnership.LOCAL, scaleTwo, "scale two"),
                source(FIRST, AssessmentOwnership.LOCAL, scaleOne, "scale one")));

        assertThat(result).isInstanceOfSatisfying(Agreed.class, agreed -> {
            assertThat(agreed.decision().cvssV2Score()).isEqualByComparingTo(new BigDecimal("1.00"));
            assertThat(agreed.decision().cvssV3Score()).isEqualByComparingTo(new BigDecimal("1.0"));
            assertThat(agreed.decision().cvssV4Score()).isEqualByComparingTo(new BigDecimal("1.00"));
            assertThat(agreed.decision().owaspScore()).isEqualByComparingTo(new BigDecimal("1.0"));
            assertThat(agreed.contributors()).containsExactly(FIRST, SECOND);
        });
    }

    @Test
    void shouldNormalizeMissingJustificationAndResponseToNotSet() {
        final AssessmentDecision missing = AssessmentDecision.of(
                AnalysisState.IN_TRIAGE, null, null, false, null, null, null, null, null, null, null, null, null);
        final AssessmentDecision explicit = AssessmentDecision.of(
                AnalysisState.IN_TRIAGE,
                AnalysisJustification.NOT_SET,
                AnalysisResponse.NOT_SET,
                false,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null);

        assertThat(missing.justification()).isEqualTo(AnalysisJustification.NOT_SET);
        assertThat(missing.response()).isEqualTo(AnalysisResponse.NOT_SET);
        assertThat(missing).isEqualTo(explicit);

        final Result result = AssessmentConsensus.resolve(List.of(
                source(FIRST, AssessmentOwnership.LOCAL, missing, "omitted"),
                source(SECOND, AssessmentOwnership.LOCAL, explicit, "explicit not set")));

        assertThat(result).isInstanceOfSatisfying(Agreed.class, agreed -> {
            assertThat(agreed.decision().justification()).isEqualTo(AnalysisJustification.NOT_SET);
            assertThat(agreed.decision().response()).isEqualTo(AnalysisResponse.NOT_SET);
            assertThat(agreed.contributors()).containsExactly(FIRST, SECOND);
        });
    }

    @Test
    void shouldOrderContributorsBySourceIdentity() {
        final Contributor byAnalysis = contributor(
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000001",
                4L);
        final Contributor byVulnerability = contributor(
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000009",
                1L);
        final Contributor byComponent = contributor(
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000008",
                "00000000-0000-0000-0000-000000000001",
                1L);
        final Contributor byProject = contributor(
                "00000000-0000-0000-0000-000000000007",
                "00000000-0000-0000-0000-000000000001",
                "00000000-0000-0000-0000-000000000001",
                1L);

        final Result result = AssessmentConsensus.resolve(List.of(
                source(byProject, AssessmentOwnership.LOCAL, BASE, "project"),
                source(byComponent, AssessmentOwnership.LOCAL, BASE, "component"),
                source(byVulnerability, AssessmentOwnership.LOCAL, BASE, "vulnerability"),
                source(byAnalysis, AssessmentOwnership.LOCAL, BASE, "analysis")));

        assertThat(result)
                .isInstanceOfSatisfying(
                        Agreed.class,
                        agreed -> assertThat(agreed.contributors())
                                .containsExactly(byAnalysis, byVulnerability, byComponent, byProject));
    }

    @Test
    void shouldKeepAgreementWhenOneOfTwoContributorsIsRemoved() {
        final Result both = AssessmentConsensus.resolve(List.of(
                source(FIRST, AssessmentOwnership.LOCAL, BASE, "first"),
                source(SECOND, AssessmentOwnership.POLICY, BASE, "second")));
        final Result remaining =
                AssessmentConsensus.resolve(List.of(source(SECOND, AssessmentOwnership.POLICY, BASE, "second")));

        assertThat(both).isInstanceOfSatisfying(Agreed.class, agreed -> {
            assertThat(agreed.decision()).isEqualTo(BASE);
            assertThat(agreed.contributors()).containsExactly(FIRST, SECOND);
        });
        assertThat(remaining).isInstanceOfSatisfying(Agreed.class, agreed -> {
            assertThat(agreed.decision()).isEqualTo(BASE);
            assertThat(agreed.contributors()).containsExactly(SECOND);
        });
    }

    @Test
    void shouldBecomeUnavailableWhenTheLastContributorIsRemoved() {
        final Result result = AssessmentConsensus.resolve(List.of());

        assertThat(result)
                .isInstanceOfSatisfying(
                        Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.NO_AUTHORED_SOURCE));
    }

    @Test
    void shouldIgnoreInheritedAndNeutralRows() {
        final AssessmentDecision inheritedDecision = withState(AnalysisState.EXPLOITABLE);
        final AssessmentDecision neutralDecision = withState(AnalysisState.RESOLVED);
        final SourceAssessment inherited = source(FIRST, AssessmentOwnership.INHERITED, inheritedDecision, "copied");
        final SourceAssessment neutral = source(SECOND, AssessmentOwnership.NEUTRAL, neutralDecision, "cleared");
        final SourceAssessment authored = source(THIRD, AssessmentOwnership.LOCAL, BASE, "product source");

        final Result withAuthor = AssessmentConsensus.resolve(List.of(inherited, neutral, authored));
        final Result withoutAuthor = AssessmentConsensus.resolve(List.of(inherited, neutral));

        assertThat(withAuthor).isInstanceOfSatisfying(Agreed.class, agreed -> {
            assertThat(agreed.decision()).isEqualTo(BASE);
            assertThat(agreed.decision().state()).isEqualTo(AnalysisState.NOT_AFFECTED);
            assertThat(agreed.contributors()).containsExactly(THIRD);
        });
        assertThat(withoutAuthor)
                .isInstanceOfSatisfying(
                        Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.NO_AUTHORED_SOURCE));
    }

    @Test
    void shouldTreatLegacyNullOriginAsAuthored() {
        final Result result = AssessmentConsensus.resolve(List.of(source(FIRST, null, BASE, "row has no sidecar")));

        assertThat(result).isInstanceOfSatisfying(Agreed.class, agreed -> {
            assertThat(agreed.decision()).isEqualTo(BASE);
            assertThat(agreed.contributors()).containsExactly(FIRST);
        });
    }

    @Test
    void shouldNotSelectAWinnerOnConflict() {
        final Result result = AssessmentConsensus.resolve(List.of(
                source(SECOND, AssessmentOwnership.LOCAL, withState(AnalysisState.EXPLOITABLE), "second"),
                source(FIRST, AssessmentOwnership.POLICY, BASE, "first")));

        assertThat(result).isInstanceOf(Conflict.class).isNotInstanceOf(Agreed.class);
        assertThat(result)
                .isInstanceOfSatisfying(
                        Conflict.class,
                        conflict -> assertThat(conflict.contributors()).containsExactly(FIRST, SECOND));
    }

    @Test
    void shouldIgnoreFindingWithoutAnAuthoredAssessment() {
        final Result result = AssessmentConsensus.resolve(List.of(
                new SourceAssessment(FIRST, AssessmentOwnership.LOCAL, null, "matching finding, no analysis"),
                source(SECOND, AssessmentOwnership.LOCAL, BASE, "authored")));

        assertThat(result).isInstanceOfSatisfying(Agreed.class, agreed -> {
            assertThat(agreed.decision()).isEqualTo(BASE);
            assertThat(agreed.contributors()).containsExactly(SECOND);
        });
    }

    @Test
    void shouldNotLetANeutralSourceRowBlockAgreement() {
        final Result result = AssessmentConsensus.resolve(List.of(
                source(FIRST, AssessmentOwnership.LOCAL, AssessmentDecision.neutral(), "comment only"),
                source(SECOND, AssessmentOwnership.LOCAL, BASE, "decided")));
        final Result neutralOnly = AssessmentConsensus.resolve(
                List.of(source(FIRST, AssessmentOwnership.LOCAL, AssessmentDecision.neutral(), "comment only")));

        assertThat(result).isInstanceOfSatisfying(Agreed.class, agreed -> {
            assertThat(agreed.decision()).isEqualTo(BASE);
            assertThat(agreed.contributors()).containsExactly(SECOND);
        });
        assertThat(neutralOnly)
                .isInstanceOfSatisfying(
                        Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.NO_AUTHORED_SOURCE));
    }

    @Test
    void shouldLetSuppressedNotSetAndInTriageRowsVote() {
        final AssessmentDecision suppressedNotSet = AssessmentDecision.of(
                AnalysisState.NOT_SET, null, null, true, null, null, null, null, null, null, null, null, null);
        final AssessmentDecision inTriage = AssessmentDecision.of(
                AnalysisState.IN_TRIAGE, null, null, false, null, null, null, null, null, null, null, null, null);

        assertFieldConflict(suppressedNotSet);
        assertFieldConflict(inTriage);
    }

    @Test
    void shouldCollapseDuplicateGraphPathsToOneContributor() {
        final Result result = AssessmentConsensus.resolve(List.of(
                source(FIRST, AssessmentOwnership.LOCAL, BASE, "path through the marker"),
                source(FIRST, AssessmentOwnership.LOCAL, BASE, "the same finding reached again")));

        assertThat(result).isInstanceOfSatisfying(Agreed.class, agreed -> {
            assertThat(agreed.decision()).isEqualTo(BASE);
            assertThat(agreed.contributors()).containsExactly(FIRST);
        });
    }

    private static void assertFieldConflict(final AssessmentDecision other) {
        final Result result = AssessmentConsensus.resolve(List.of(
                source(FIRST, AssessmentOwnership.LOCAL, BASE, "base"),
                source(SECOND, AssessmentOwnership.LOCAL, other, "other")));

        assertThat(result)
                .isInstanceOfSatisfying(
                        Conflict.class,
                        conflict -> assertThat(conflict.contributors()).containsExactly(FIRST, SECOND));
    }

    private static void assertNullConflictsWithZero(final AssessmentDecision absent, final AssessmentDecision zero) {
        assertThat(absent).isNotEqualTo(zero);
        final Result result = AssessmentConsensus.resolve(List.of(
                source(FIRST, AssessmentOwnership.LOCAL, absent, "absent"),
                source(SECOND, AssessmentOwnership.LOCAL, zero, "zero")));
        assertThat(result)
                .isInstanceOfSatisfying(
                        Conflict.class,
                        conflict -> assertThat(conflict.contributors()).containsExactly(FIRST, SECOND));
    }

    private static SourceAssessment source(
            final Contributor contributor,
            final AssessmentOwnership origin,
            final AssessmentDecision decision,
            final String explanation) {
        return new SourceAssessment(contributor, origin, decision, explanation);
    }

    private static Contributor contributor(
            final String project, final String component, final String vulnerability, final long analysisId) {
        return new Contributor(
                UUID.fromString(project), UUID.fromString(component), UUID.fromString(vulnerability), analysisId);
    }

    private static AssessmentDecision withState(final AnalysisState state) {
        return AssessmentDecision.of(
                state,
                BASE.justification(),
                BASE.response(),
                BASE.suppressed(),
                BASE.severity(),
                BASE.cvssV2Vector(),
                BASE.cvssV2Score(),
                BASE.cvssV3Vector(),
                BASE.cvssV3Score(),
                BASE.cvssV4Vector(),
                BASE.cvssV4Score(),
                BASE.owaspVector(),
                BASE.owaspScore());
    }

    private static AssessmentDecision withJustification(final AnalysisJustification justification) {
        return AssessmentDecision.of(
                BASE.state(),
                justification,
                BASE.response(),
                BASE.suppressed(),
                BASE.severity(),
                BASE.cvssV2Vector(),
                BASE.cvssV2Score(),
                BASE.cvssV3Vector(),
                BASE.cvssV3Score(),
                BASE.cvssV4Vector(),
                BASE.cvssV4Score(),
                BASE.owaspVector(),
                BASE.owaspScore());
    }

    private static AssessmentDecision withResponse(final AnalysisResponse response) {
        return AssessmentDecision.of(
                BASE.state(),
                BASE.justification(),
                response,
                BASE.suppressed(),
                BASE.severity(),
                BASE.cvssV2Vector(),
                BASE.cvssV2Score(),
                BASE.cvssV3Vector(),
                BASE.cvssV3Score(),
                BASE.cvssV4Vector(),
                BASE.cvssV4Score(),
                BASE.owaspVector(),
                BASE.owaspScore());
    }

    private static AssessmentDecision withSuppressed(final boolean suppressed) {
        return AssessmentDecision.of(
                BASE.state(),
                BASE.justification(),
                BASE.response(),
                suppressed,
                BASE.severity(),
                BASE.cvssV2Vector(),
                BASE.cvssV2Score(),
                BASE.cvssV3Vector(),
                BASE.cvssV3Score(),
                BASE.cvssV4Vector(),
                BASE.cvssV4Score(),
                BASE.owaspVector(),
                BASE.owaspScore());
    }

    private static AssessmentDecision withSeverity(final Severity severity) {
        return AssessmentDecision.of(
                BASE.state(),
                BASE.justification(),
                BASE.response(),
                BASE.suppressed(),
                severity,
                BASE.cvssV2Vector(),
                BASE.cvssV2Score(),
                BASE.cvssV3Vector(),
                BASE.cvssV3Score(),
                BASE.cvssV4Vector(),
                BASE.cvssV4Score(),
                BASE.owaspVector(),
                BASE.owaspScore());
    }

    private static AssessmentDecision withCvssV2Vector(final String vector) {
        return AssessmentDecision.of(
                BASE.state(),
                BASE.justification(),
                BASE.response(),
                BASE.suppressed(),
                BASE.severity(),
                vector,
                BASE.cvssV2Score(),
                BASE.cvssV3Vector(),
                BASE.cvssV3Score(),
                BASE.cvssV4Vector(),
                BASE.cvssV4Score(),
                BASE.owaspVector(),
                BASE.owaspScore());
    }

    private static AssessmentDecision withCvssV2Score(final BigDecimal score) {
        return AssessmentDecision.of(
                BASE.state(),
                BASE.justification(),
                BASE.response(),
                BASE.suppressed(),
                BASE.severity(),
                BASE.cvssV2Vector(),
                score,
                BASE.cvssV3Vector(),
                BASE.cvssV3Score(),
                BASE.cvssV4Vector(),
                BASE.cvssV4Score(),
                BASE.owaspVector(),
                BASE.owaspScore());
    }

    private static AssessmentDecision withCvssV3Vector(final String vector) {
        return AssessmentDecision.of(
                BASE.state(),
                BASE.justification(),
                BASE.response(),
                BASE.suppressed(),
                BASE.severity(),
                BASE.cvssV2Vector(),
                BASE.cvssV2Score(),
                vector,
                BASE.cvssV3Score(),
                BASE.cvssV4Vector(),
                BASE.cvssV4Score(),
                BASE.owaspVector(),
                BASE.owaspScore());
    }

    private static AssessmentDecision withCvssV3Score(final BigDecimal score) {
        return AssessmentDecision.of(
                BASE.state(),
                BASE.justification(),
                BASE.response(),
                BASE.suppressed(),
                BASE.severity(),
                BASE.cvssV2Vector(),
                BASE.cvssV2Score(),
                BASE.cvssV3Vector(),
                score,
                BASE.cvssV4Vector(),
                BASE.cvssV4Score(),
                BASE.owaspVector(),
                BASE.owaspScore());
    }

    private static AssessmentDecision withCvssV4Vector(final String vector) {
        return AssessmentDecision.of(
                BASE.state(),
                BASE.justification(),
                BASE.response(),
                BASE.suppressed(),
                BASE.severity(),
                BASE.cvssV2Vector(),
                BASE.cvssV2Score(),
                BASE.cvssV3Vector(),
                BASE.cvssV3Score(),
                vector,
                BASE.cvssV4Score(),
                BASE.owaspVector(),
                BASE.owaspScore());
    }

    private static AssessmentDecision withCvssV4Score(final BigDecimal score) {
        return AssessmentDecision.of(
                BASE.state(),
                BASE.justification(),
                BASE.response(),
                BASE.suppressed(),
                BASE.severity(),
                BASE.cvssV2Vector(),
                BASE.cvssV2Score(),
                BASE.cvssV3Vector(),
                BASE.cvssV3Score(),
                BASE.cvssV4Vector(),
                score,
                BASE.owaspVector(),
                BASE.owaspScore());
    }

    private static AssessmentDecision withOwaspVector(final String vector) {
        return AssessmentDecision.of(
                BASE.state(),
                BASE.justification(),
                BASE.response(),
                BASE.suppressed(),
                BASE.severity(),
                BASE.cvssV2Vector(),
                BASE.cvssV2Score(),
                BASE.cvssV3Vector(),
                BASE.cvssV3Score(),
                BASE.cvssV4Vector(),
                BASE.cvssV4Score(),
                vector,
                BASE.owaspScore());
    }

    private static AssessmentDecision withOwaspScore(final BigDecimal score) {
        return AssessmentDecision.of(
                BASE.state(),
                BASE.justification(),
                BASE.response(),
                BASE.suppressed(),
                BASE.severity(),
                BASE.cvssV2Vector(),
                BASE.cvssV2Score(),
                BASE.cvssV3Vector(),
                BASE.cvssV3Score(),
                BASE.cvssV4Vector(),
                BASE.cvssV4Score(),
                BASE.owaspVector(),
                score);
    }

    private static AssessmentDecision withScores(final BigDecimal score) {
        return AssessmentDecision.of(
                BASE.state(),
                BASE.justification(),
                BASE.response(),
                BASE.suppressed(),
                BASE.severity(),
                BASE.cvssV2Vector(),
                score,
                BASE.cvssV3Vector(),
                score,
                BASE.cvssV4Vector(),
                score,
                BASE.owaspVector(),
                score);
    }
}
