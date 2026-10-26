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
import org.dependencytrack.assessmentsync.AssessmentConsensus.Unavailable;
import org.dependencytrack.assessmentsync.AssessmentProjectionDiff.Change;
import org.dependencytrack.assessmentsync.AssessmentProjectionDiff.CurrentProjection;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Severity;
import org.junit.jupiter.api.Test;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class AssessmentProjectionDiffTest {

    private static final Contributor FIRST = contributor("00000000-0000-0000-0000-000000000001", 1L);
    private static final Contributor SECOND = contributor("00000000-0000-0000-0000-000000000002", 2L);

    private static final AssessmentDecision LOCAL_NOT_SET = AssessmentDecision.neutral();
    private static final AssessmentDecision AGREED = AssessmentDecision.of(
            AnalysisState.NOT_AFFECTED,
            AnalysisJustification.CODE_NOT_REACHABLE,
            AnalysisResponse.WILL_NOT_FIX,
            true,
            Severity.LOW,
            "AV:N/AC:L/Au:N/C:P/I:P/A:P",
            new BigDecimal("7.5"),
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            new BigDecimal("9.8"),
            "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
            new BigDecimal("9.3"),
            "(SL:1/M:1)",
            new BigDecimal("5.5"));

    @Test
    void shouldProtectLocalOwnership() {
        final CurrentProjection current = new CurrentProjection(
                AssessmentOwnership.LOCAL, LOCAL_NOT_SET, "product note", 42L, List.of(FIRST), true);

        final Change change = AssessmentProjectionDiff.diff(current, new Agreed(AGREED, List.of(FIRST, SECOND)));

        assertThat(change.origin()).isEqualTo(AssessmentOwnership.LOCAL);
        assertThat(change.reason()).isEqualTo(AssessmentReason.TARGET_LOCAL);
        assertThat(change.machineChanged()).isFalse();
        assertThat(change.contributorsChanged()).isFalse();
        assertThat(change.decision().state()).isEqualTo(AnalysisState.NOT_SET);
        assertThat(change.decision().justification()).isEqualTo(AnalysisJustification.NOT_SET);
        assertThat(change.decision().response()).isEqualTo(AnalysisResponse.NOT_SET);
        assertThat(change.decision().suppressed()).isFalse();
        assertThat(change.decision().severity()).isNull();
        assertThat(change.details()).isEqualTo("product note");
        assertThat(change.policyId()).isEqualTo(42L);
        assertThat(change.contributors()).containsExactly(FIRST);
        assertThat(change.localComment()).isTrue();
    }

    @Test
    void shouldProtectPolicyOwnership() {
        final CurrentProjection current =
                new CurrentProjection(AssessmentOwnership.POLICY, AGREED, "policy detail", 8L, List.of(FIRST), false);

        final Change change =
                AssessmentProjectionDiff.diff(current, new Unavailable(AssessmentReason.NO_AUTHORED_SOURCE));

        assertThat(change.origin()).isEqualTo(AssessmentOwnership.POLICY);
        assertThat(change.reason()).isEqualTo(AssessmentReason.TARGET_LOCAL);
        assertThat(change.machineChanged()).isFalse();
        assertThat(change.contributorsChanged()).isFalse();
        assertThat(change.decision()).isEqualTo(AGREED);
        assertThat(change.details()).isEqualTo("policy detail");
        assertThat(change.policyId()).isEqualTo(8L);
        assertThat(change.localComment()).isFalse();
    }

    @Test
    void shouldProtectNullOrigin() {
        final CurrentProjection current = new CurrentProjection(null, LOCAL_NOT_SET, null, null, List.of(), true);

        final Change change = AssessmentProjectionDiff.diff(current, new Agreed(AGREED, List.of(FIRST)));

        assertThat(change.origin()).isNull();
        assertThat(change.reason()).isEqualTo(AssessmentReason.TARGET_LOCAL);
        assertThat(change.machineChanged()).isFalse();
        assertThat(change.decision().state()).isEqualTo(AnalysisState.NOT_SET);
        assertThat(change.localComment()).isTrue();
    }

    @Test
    void shouldApplyAgreedDecision() {
        final CurrentProjection current =
                new CurrentProjection(AssessmentOwnership.NEUTRAL, LOCAL_NOT_SET, "stale", 7L, List.of(), false);

        final Change change = AssessmentProjectionDiff.diff(current, new Agreed(AGREED, List.of(FIRST, SECOND)));

        assertThat(change.origin()).isEqualTo(AssessmentOwnership.INHERITED);
        assertThat(change.decision()).isEqualTo(AGREED);
        assertThat(change.decision().state()).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(change.decision().suppressed()).isTrue();
        assertThat(change.decision().severity()).isEqualTo(Severity.LOW);
        assertThat(change.details()).isNull();
        assertThat(change.policyId()).isNull();
        assertThat(change.contributors()).containsExactly(FIRST, SECOND);
        assertThat(change.localComment()).isFalse();
        assertThat(change.reason()).isNull();
        assertThat(change.machineChanged()).isTrue();
        assertThat(change.contributorsChanged()).isTrue();
    }

    @Test
    void shouldWithdrawInheritedValuesOnConflict() {
        final CurrentProjection current = new CurrentProjection(
                AssessmentOwnership.INHERITED, AGREED, "copied source text", 9L, List.of(FIRST, SECOND), true);

        final Change change = AssessmentProjectionDiff.diff(current, new Conflict(List.of(FIRST, SECOND)));

        assertWithdrawn(change, AssessmentReason.SOURCE_CONFLICT);
    }

    @Test
    void shouldWithdrawInheritedValuesWhenUnavailable() {
        final CurrentProjection current = new CurrentProjection(
                AssessmentOwnership.INHERITED, AGREED, "copied source text", 9L, List.of(FIRST), true);

        final Change change =
                AssessmentProjectionDiff.diff(current, new Unavailable(AssessmentReason.NO_AUTHORED_SOURCE));

        assertWithdrawn(change, AssessmentReason.NO_AUTHORED_SOURCE);
    }

    @Test
    void shouldRecordContributorChangeWithoutMachineChange() {
        final CurrentProjection current =
                new CurrentProjection(AssessmentOwnership.INHERITED, AGREED, null, null, List.of(FIRST, SECOND), true);

        final Change change = AssessmentProjectionDiff.diff(current, new Agreed(AGREED, List.of(FIRST)));

        assertThat(change.origin()).isEqualTo(AssessmentOwnership.INHERITED);
        assertThat(change.decision()).isEqualTo(AGREED);
        assertThat(change.decision().state()).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(change.details()).isNull();
        assertThat(change.policyId()).isNull();
        assertThat(change.contributors()).containsExactly(FIRST);
        assertThat(change.localComment()).isTrue();
        assertThat(change.reason()).isNull();
        assertThat(change.machineChanged()).isFalse();
        assertThat(change.contributorsChanged()).isTrue();
    }

    @Test
    void shouldLeaveNeutralUnchangedWhenSourcesConflict() {
        final CurrentProjection current =
                new CurrentProjection(AssessmentOwnership.NEUTRAL, LOCAL_NOT_SET, null, null, List.of(), true);

        final Change change = AssessmentProjectionDiff.diff(current, new Conflict(List.of(FIRST, SECOND)));

        assertThat(change.origin()).isEqualTo(AssessmentOwnership.NEUTRAL);
        assertThat(change.decision().state()).isEqualTo(AnalysisState.NOT_SET);
        assertThat(change.machineChanged()).isFalse();
        assertThat(change.contributorsChanged()).isFalse();
        assertThat(change.localComment()).isTrue();
        assertThat(change.reason()).isNull();
    }

    private static void assertWithdrawn(final Change change, final AssessmentReason reason) {
        assertThat(change.origin()).isEqualTo(AssessmentOwnership.NEUTRAL);
        assertThat(change.reason()).isEqualTo(reason);
        assertThat(change.machineChanged()).isTrue();
        assertThat(change.contributorsChanged()).isTrue();
        assertThat(change.details()).isNull();
        assertThat(change.policyId()).isNull();
        assertThat(change.contributors()).isEmpty();
        assertThat(change.localComment()).isTrue();
        assertThat(change.decision().state()).isEqualTo(AnalysisState.NOT_SET);
        assertThat(change.decision().justification()).isEqualTo(AnalysisJustification.NOT_SET);
        assertThat(change.decision().response()).isEqualTo(AnalysisResponse.NOT_SET);
        assertThat(change.decision().suppressed()).isFalse();
        assertThat(change.decision().severity()).isNull();
        assertThat(change.decision().cvssV2Vector()).isNull();
        assertThat(change.decision().cvssV2Score()).isNull();
        assertThat(change.decision().cvssV3Vector()).isNull();
        assertThat(change.decision().cvssV3Score()).isNull();
        assertThat(change.decision().cvssV4Vector()).isNull();
        assertThat(change.decision().cvssV4Score()).isNull();
        assertThat(change.decision().owaspVector()).isNull();
        assertThat(change.decision().owaspScore()).isNull();
    }

    private static Contributor contributor(final String project, final long analysisId) {
        return new Contributor(
                UUID.fromString(project),
                UUID.fromString("00000000-0000-0000-0000-000000000010"),
                UUID.fromString("00000000-0000-0000-0000-000000000020"),
                analysisId);
    }
}
