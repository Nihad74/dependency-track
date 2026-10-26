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

import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Severity;
import org.jspecify.annotations.Nullable;

import java.math.BigDecimal;
import java.util.Objects;

/// Structured machine tuple compared by consensus.
///
/// Scores are stored with trailing zeros removed so numerical equals holds for different scales.
/// Vector strings are kept as given. A null rating override is distinct from an explicit zero.
public record AssessmentDecision(
        AnalysisState state,
        AnalysisJustification justification,
        AnalysisResponse response,
        boolean suppressed,
        @Nullable Severity severity,
        @Nullable String cvssV2Vector,
        @Nullable BigDecimal cvssV2Score,
        @Nullable String cvssV3Vector,
        @Nullable BigDecimal cvssV3Score,
        @Nullable String cvssV4Vector,
        @Nullable BigDecimal cvssV4Score,
        @Nullable String owaspVector,
        @Nullable BigDecimal owaspScore) {

    public AssessmentDecision {
        Objects.requireNonNull(state, "state must not be null");
        Objects.requireNonNull(justification, "justification must not be null");
        Objects.requireNonNull(response, "response must not be null");
        cvssV2Score = canonicalScore(cvssV2Score);
        cvssV3Score = canonicalScore(cvssV3Score);
        cvssV4Score = canonicalScore(cvssV4Score);
        owaspScore = canonicalScore(owaspScore);
    }

    /// Missing justification and response use the existing {@code NOT_SET} value.
    public static AssessmentDecision of(
            final AnalysisState state,
            final @Nullable AnalysisJustification justification,
            final @Nullable AnalysisResponse response,
            final boolean suppressed,
            final @Nullable Severity severity,
            final @Nullable String cvssV2Vector,
            final @Nullable BigDecimal cvssV2Score,
            final @Nullable String cvssV3Vector,
            final @Nullable BigDecimal cvssV3Score,
            final @Nullable String cvssV4Vector,
            final @Nullable BigDecimal cvssV4Score,
            final @Nullable String owaspVector,
            final @Nullable BigDecimal owaspScore) {
        return new AssessmentDecision(
                state,
                justification == null ? AnalysisJustification.NOT_SET : justification,
                response == null ? AnalysisResponse.NOT_SET : response,
                suppressed,
                severity,
                cvssV2Vector,
                cvssV2Score,
                cvssV3Vector,
                cvssV3Score,
                cvssV4Vector,
                cvssV4Score,
                owaspVector,
                owaspScore);
    }

    /// Worker-owned fields after an inherited decision is withdrawn.
    public static AssessmentDecision neutral() {
        return of(
                AnalysisState.NOT_SET,
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
    }

    private static @Nullable BigDecimal canonicalScore(final @Nullable BigDecimal score) {
        if (score == null) {
            return null;
        }
        return score.stripTrailingZeros();
    }
}
