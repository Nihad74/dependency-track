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
package org.dependencytrack.analysis;

import org.dependencytrack.assessmentsync.AssessmentNotReleasableException;
import org.dependencytrack.assessmentsync.AssessmentOriginDao.Origin;
import org.dependencytrack.assessmentsync.AssessmentOwnership;
import org.dependencytrack.assessmentsync.StaleAssessmentDecisionException;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.command.MakeAnalysisCommand.DecisionAction;
import org.dependencytrack.persistence.command.MakeAnalysisCommand.Option;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.math.BigDecimal;
import java.util.EnumSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AnalysisMutationPlannerTest {

    @Test
    void changingAnInheritedDecisionPlansAllEffectsWithoutMutatingTheInput() {
        final var stored = analysis();
        stored.setAnalysisDetails("source explanation");
        stored.setCvssV3Vector("CVSS:3.1/AV:N");
        stored.setCvssV3Score(new BigDecimal("9.8"));
        final var plan = AnalysisMutationPlanner.plan(
                request(command().withState(AnalysisState.EXPLOITABLE)),
                stored,
                new Origin(AssessmentOwnership.INHERITED, 7, null));

        assertThat(stored.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(plan.values().getAnalysisState()).isEqualTo(AnalysisState.EXPLOITABLE);
        assertThat(plan.values().getCvssV3Score()).isEqualByComparingTo("9.8");
        assertThat(plan.values().getAnalysisDetails()).isEqualTo("source explanation");
        assertThat(plan.owner()).isEqualTo(AssessmentOwnership.LOCAL);
        assertThat(plan.advanceDecisionVersion()).isTrue();
        assertThat(plan.dropCopiedTrail()).isTrue();
        assertThat(plan.recordChange()).isTrue();
        assertThat(plan.notifyDecisionChange()).isTrue();
        assertThat(plan.comments()).containsExactly("Analysis: NOT_AFFECTED → EXPLOITABLE");
    }

    @Test
    void explanationEditTakesOwnershipWithoutDroppingTheStructuredDecisionProvenance() {
        final var plan = AnalysisMutationPlanner.plan(
                request(command().withDetails("my explanation")),
                analysis(),
                new Origin(AssessmentOwnership.INHERITED, 7, null));
        assertThat(plan.owner()).isEqualTo(AssessmentOwnership.LOCAL);
        assertThat(plan.valuesChanged()).isTrue();
        assertThat(plan.advanceDecisionVersion()).isTrue();
        assertThat(plan.dropCopiedTrail()).isFalse();
        assertThat(plan.notifyDecisionChange()).isFalse();
    }

    @ParameterizedTest
    @EnumSource(AssessmentOwnership.class)
    void commentsPreserveEveryExistingOwnerAndVersion(final AssessmentOwnership owner) {
        final var plan = AnalysisMutationPlanner.plan(
                request(command()
                        .withDecisionAction(DecisionAction.COMMENT_ONLY)
                        .withComment("a note")),
                analysis(),
                new Origin(owner, 7, null));
        assertThat(plan.owner()).isNull();
        assertThat(plan.advanceDecisionVersion()).isFalse();
        assertThat(plan.dropCopiedTrail()).isFalse();
        assertThat(plan.valuesChanged()).isFalse();
        assertThat(plan.recordChange()).isTrue();
        assertThat(plan.comments()).containsExactly("a note");
    }

    @Test
    void takeoverOfUnlabeledPolicyMovesTheVersionEvenWithIdenticalValues() {
        final var stored = analysis();
        stored.setVulnerabilityPolicyId(42L);
        final var plan = AnalysisMutationPlanner.plan(
                request(command().withDecisionAction(DecisionAction.TAKE_LOCAL)), stored, null);
        assertThat(plan.owner()).isEqualTo(AssessmentOwnership.LOCAL);
        assertThat(plan.advanceDecisionVersion()).isTrue();
        assertThat(plan.valuesChanged()).isFalse();
        assertThat(plan.dropCopiedTrail()).isFalse();
    }

    @Test
    void releaseClearsOverridesAndPolicyAssociationWithoutMutatingTheStoredValues() {
        final var stored = analysis();
        stored.setSuppressed(true);
        stored.setSeverity(Severity.HIGH);
        stored.setCvssV2Vector("v2");
        stored.setCvssV2Score(BigDecimal.ONE);
        stored.setCvssV3Vector("v3");
        stored.setCvssV3Score(BigDecimal.TEN);
        stored.setCvssV4Vector("v4");
        stored.setCvssV4Score(BigDecimal.TEN);
        stored.setOwaspVector("owasp");
        stored.setOwaspScore(BigDecimal.TEN);
        stored.setVulnerabilityPolicyId(42L);
        final var plan = AnalysisMutationPlanner.plan(
                request(command().withDecisionAction(DecisionAction.RELEASE_LOCAL)),
                stored,
                new Origin(AssessmentOwnership.LOCAL, 3, null));
        assertThat(plan.values())
                .extracting("analysisState", "analysisJustification", "analysisResponse", "suppressed")
                .containsExactly(AnalysisState.NOT_SET, AnalysisJustification.NOT_SET, AnalysisResponse.NOT_SET, false);
        assertThat(plan.values())
                .extracting(
                        "severity",
                        "cvssV2Vector",
                        "cvssV2Score",
                        "cvssV3Vector",
                        "cvssV3Score",
                        "cvssV4Vector",
                        "cvssV4Score",
                        "owaspVector",
                        "owaspScore",
                        "vulnerabilityPolicyId")
                .containsOnlyNulls();
        assertThat(stored.getSeverity()).isEqualTo(Severity.HIGH);
        assertThat(stored.getVulnerabilityPolicyId()).isEqualTo(42L);
        assertThat(plan.owner()).isEqualTo(AssessmentOwnership.NEUTRAL);
        assertThat(plan.dropCopiedTrail()).isTrue();
    }

    @Test
    void staleVersionsAndInvalidReleasesCannotProduceAPlan() {
        assertThatThrownBy(() -> AnalysisMutationPlanner.plan(
                        request(command().withExpectedDecisionVersion(6L)),
                        analysis(),
                        new Origin(AssessmentOwnership.LOCAL, 7, null)))
                .isInstanceOf(StaleAssessmentDecisionException.class);
        assertThatThrownBy(() -> AnalysisMutationPlanner.plan(
                        request(command().withDecisionAction(DecisionAction.RELEASE_LOCAL)),
                        analysis(),
                        new Origin(AssessmentOwnership.POLICY, 7, null)))
                .isInstanceOf(AssessmentNotReleasableException.class);
    }

    @Test
    void legacyDefaultsDependOnOwnership() {
        final var request = request(command().withOptions(Set.of(Option.V1_RESET_OMITTED_DECISION)));
        final var inherited =
                AnalysisMutationPlanner.plan(request, analysis(), new Origin(AssessmentOwnership.INHERITED, 1, null));
        final var local =
                AnalysisMutationPlanner.plan(request, analysis(), new Origin(AssessmentOwnership.LOCAL, 1, null));
        assertThat(inherited.values().getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(inherited.recordChange()).isFalse();
        assertThat(local.values().getAnalysisState()).isEqualTo(AnalysisState.NOT_SET);
        assertThat(local.advanceDecisionVersion()).isTrue();
    }

    @Test
    void notificationAndAuditOptionsDoNotDiscardAnExplicitComment() {
        final var plan = AnalysisMutationPlanner.plan(
                request(command()
                        .withState(AnalysisState.EXPLOITABLE)
                        .withComment("user comment")
                        .withOptions(Set.of(Option.OMIT_AUDIT_TRAIL, Option.OMIT_NOTIFICATION))),
                analysis(),
                null);
        assertThat(plan.comments()).containsExactly("user comment");
        assertThat(plan.notifyDecisionChange()).isFalse();
        assertThat(plan.recordChange()).isTrue();
    }

    @Test
    void commandCopiesKeepAllOtherFieldsAndSnapshotMutableOptions() {
        final var options = EnumSet.of(Option.OMIT_NOTIFICATION);
        final var original = command()
                .withState(AnalysisState.NOT_AFFECTED)
                .withJustification(AnalysisJustification.CODE_NOT_REACHABLE)
                .withResponse(AnalysisResponse.CAN_NOT_FIX)
                .withDetails("explanation")
                .withSuppress(true)
                .withCommenter("author")
                .withComment("note")
                .withOwasp("vector", BigDecimal.ONE)
                .withOptions(options)
                .withDecisionAction(DecisionAction.TAKE_LOCAL)
                .withExpectedDecisionVersion(7L);
        options.clear();
        final var edited = original.toBuilder().state(AnalysisState.EXPLOITABLE).build();
        assertThat(edited).usingRecursiveComparison().ignoringFields("state").isEqualTo(original);
        assertThat(original.state()).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(edited.options()).containsExactly(Option.OMIT_NOTIFICATION);
    }

    private static MakeAnalysisCommand command() {
        return new MakeAnalysisCommand(new Component(), new Vulnerability());
    }

    private static AnalysisMutationPlanner.Request request(final MakeAnalysisCommand command) {
        return new AnalysisMutationPlanner.Request(
                command.state(),
                command.justification(),
                command.response(),
                command.details(),
                command.suppress(),
                command.comment(),
                command.owaspVector(),
                command.owaspScore(),
                command.options(),
                command.decisionAction(),
                command.expectedDecisionVersion());
    }

    private static AnalysisValues analysis() {
        final var analysis = new AnalysisValues();
        analysis.setAnalysisState(AnalysisState.NOT_AFFECTED);
        analysis.setAnalysisJustification(AnalysisJustification.NOT_SET);
        analysis.setAnalysisResponse(AnalysisResponse.NOT_SET);
        return analysis;
    }
}
