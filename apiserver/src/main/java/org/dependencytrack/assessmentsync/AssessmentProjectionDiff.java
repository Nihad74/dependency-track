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

import org.dependencytrack.assessmentsync.AssessmentConsensus.Contributor;
import org.dependencytrack.assessmentsync.AssessmentConsensus.Result;
import org.jspecify.annotations.Nullable;

import java.util.HashSet;
import java.util.List;
import java.util.Objects;

/// Calculates the next target projection. Does not write it.
public final class AssessmentProjectionDiff {

    private AssessmentProjectionDiff() {}

    public static Change diff(final CurrentProjection current, final Result consensus) {
        Objects.requireNonNull(current, "current must not be null");
        Objects.requireNonNull(consensus, "consensus must not be null");
        if (protectsLocalDecision(current.origin())) {
            return copy(current, AssessmentReason.TARGET_LOCAL, false, false);
        }
        return switch (consensus) {
            case AssessmentConsensus.Agreed agreed -> applyAgreed(current, agreed);
            case AssessmentConsensus.Unavailable unavailable -> withdrawOrKeep(current, unavailable.reason());
            case AssessmentConsensus.Conflict conflict -> withdrawInherited(current, conflict);
        };
    }

    /// Authored target rows, including a legacy row with no sidecar, are not machine-written.
    private static boolean protectsLocalDecision(final @Nullable AssessmentOwnership origin) {
        return origin == null || origin == AssessmentOwnership.LOCAL || origin == AssessmentOwnership.POLICY;
    }

    private static Change applyAgreed(final CurrentProjection current, final AssessmentConsensus.Agreed agreed) {
        final boolean machineChanged = !current.decision().equals(agreed.decision())
                || current.origin() != AssessmentOwnership.INHERITED
                || current.details() != null
                || current.policyId() != null;
        final boolean contributorsChanged = !sameContributors(current.contributors(), agreed.contributors());
        return new Change(
                AssessmentOwnership.INHERITED,
                agreed.decision(),
                null,
                null,
                agreed.contributors(),
                current.localComment(),
                null,
                machineChanged,
                contributorsChanged);
    }

    private static Change withdrawInherited(
            final CurrentProjection current, final AssessmentConsensus.Conflict conflict) {
        // Conflict keeps every contributor on the result and selects none of their decisions.
        Objects.requireNonNull(conflict.contributors(), "contributors must not be null");
        return withdrawOrKeep(current, AssessmentReason.SOURCE_CONFLICT);
    }

    private static Change withdrawOrKeep(final CurrentProjection current, final AssessmentReason reason) {
        if (current.origin() != AssessmentOwnership.INHERITED) {
            return copy(current, null, false, false);
        }
        return new Change(
                AssessmentOwnership.NEUTRAL,
                AssessmentDecision.neutral(),
                null,
                null,
                List.of(),
                current.localComment(),
                reason,
                true,
                !current.contributors().isEmpty());
    }

    private static Change copy(
            final CurrentProjection current,
            final @Nullable AssessmentReason reason,
            final boolean machineChanged,
            final boolean contributorsChanged) {
        return new Change(
                current.origin(),
                current.decision(),
                current.details(),
                current.policyId(),
                current.contributors(),
                current.localComment(),
                reason,
                machineChanged,
                contributorsChanged);
    }

    private static boolean sameContributors(final List<Contributor> left, final List<Contributor> right) {
        return new HashSet<>(left).equals(new HashSet<>(right));
    }

    /// Current target ownership and the machine fields synchronization is allowed to replace.
    public record CurrentProjection(
            @Nullable AssessmentOwnership origin,
            AssessmentDecision decision,
            @Nullable String details,
            @Nullable Long policyId,
            List<Contributor> contributors,
            boolean localComment) {

        public CurrentProjection {
            Objects.requireNonNull(decision, "decision must not be null");
            Objects.requireNonNull(contributors, "contributors must not be null");
            contributors = List.copyOf(contributors);
        }
    }

    /// Next machine tuple. {@code localComment} is copied through and is not a machine field.
    public record Change(
            @Nullable AssessmentOwnership origin,
            AssessmentDecision decision,
            @Nullable String details,
            @Nullable Long policyId,
            List<Contributor> contributors,
            boolean localComment,
            @Nullable AssessmentReason reason,
            boolean machineChanged,
            boolean contributorsChanged) {

        public Change {
            Objects.requireNonNull(decision, "decision must not be null");
            Objects.requireNonNull(contributors, "contributors must not be null");
            contributors = List.copyOf(contributors);
        }
    }
}
