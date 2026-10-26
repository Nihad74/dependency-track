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

import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.TreeMap;
import java.util.UUID;

/// Agreement across eligible authored source decisions. Explanation text is ignored.
public final class AssessmentConsensus {

    private AssessmentConsensus() {}

    public static Result resolve(final List<SourceAssessment> sourceAssessments) {
        Objects.requireNonNull(sourceAssessments, "sourceAssessments must not be null");
        final var decisions = new TreeMap<Contributor, AssessmentDecision>();
        var sameIdentityDisagrees = false;
        for (final SourceAssessment assessment : sourceAssessments) {
            Objects.requireNonNull(assessment, "source assessment must not be null");
            if (assessment.decision() == null || !eligible(assessment.origin())) {
                continue;
            }
            final AssessmentDecision existing = decisions.putIfAbsent(assessment.contributor(), assessment.decision());
            if (existing != null && !existing.equals(assessment.decision())) {
                sameIdentityDisagrees = true;
            }
        }
        if (decisions.isEmpty()) {
            return new Unavailable(AssessmentReason.NO_AUTHORED_SOURCE);
        }
        final List<Contributor> contributors = List.copyOf(decisions.keySet());
        final AssessmentDecision agreed = soleDecision(decisions.values());
        if (sameIdentityDisagrees || agreed == null) {
            return new Conflict(contributors);
        }
        return new Agreed(agreed, contributors);
    }

    /// {@code null} origin is a legacy row and is treated as authored.
    static boolean eligible(final @Nullable AssessmentOwnership origin) {
        return origin == null || origin == AssessmentOwnership.LOCAL || origin == AssessmentOwnership.POLICY;
    }

    private static @Nullable AssessmentDecision soleDecision(final Collection<AssessmentDecision> decisions) {
        AssessmentDecision sole = null;
        for (final AssessmentDecision decision : decisions) {
            if (sole == null) {
                sole = decision;
            } else if (!sole.equals(decision)) {
                return null;
            }
        }
        return sole;
    }

    /// One source finding that may vote. A null decision does not vote.
    public record SourceAssessment(
            Contributor contributor,
            @Nullable AssessmentOwnership origin,
            @Nullable AssessmentDecision decision,
            @Nullable String explanation) {

        public SourceAssessment {
            Objects.requireNonNull(contributor, "contributor must not be null");
        }
    }

    /// Stable source identity. Order is project, component, vulnerability, then analysis id.
    public record Contributor(
            UUID sourceProjectUuid, UUID sourceComponentUuid, UUID sourceVulnerabilityUuid, long sourceAnalysisId)
            implements Comparable<Contributor> {

        public Contributor {
            Objects.requireNonNull(sourceProjectUuid, "sourceProjectUuid must not be null");
            Objects.requireNonNull(sourceComponentUuid, "sourceComponentUuid must not be null");
            Objects.requireNonNull(sourceVulnerabilityUuid, "sourceVulnerabilityUuid must not be null");
        }

        @Override
        public int compareTo(final Contributor other) {
            final int byProject = sourceProjectUuid.compareTo(other.sourceProjectUuid);
            if (byProject != 0) {
                return byProject;
            }
            final int byComponent = sourceComponentUuid.compareTo(other.sourceComponentUuid);
            if (byComponent != 0) {
                return byComponent;
            }
            final int byVulnerability = sourceVulnerabilityUuid.compareTo(other.sourceVulnerabilityUuid);
            if (byVulnerability != 0) {
                return byVulnerability;
            }
            return Long.compare(sourceAnalysisId, other.sourceAnalysisId);
        }
    }

    public sealed interface Result permits Unavailable, Agreed, Conflict {}

    /// No eligible authored decision.
    public record Unavailable(AssessmentReason reason) implements Result {

        public Unavailable {
            Objects.requireNonNull(reason, "reason must not be null");
        }
    }

    /// Every eligible contributor has this decision. The list is sorted and deduplicated.
    public record Agreed(AssessmentDecision decision, List<Contributor> contributors) implements Result {

        public Agreed {
            Objects.requireNonNull(decision, "decision must not be null");
            Objects.requireNonNull(contributors, "contributors must not be null");
            contributors = List.copyOf(contributors);
            if (contributors.isEmpty()) {
                throw new IllegalArgumentException("agreed result requires at least one contributor");
            }
        }
    }

    /// At least two structured tuples differ. No source is selected.
    public record Conflict(List<Contributor> contributors) implements Result {

        public Conflict {
            Objects.requireNonNull(contributors, "contributors must not be null");
            contributors = List.copyOf(contributors);
            if (contributors.isEmpty()) {
                throw new IllegalArgumentException("conflict result requires at least one contributor");
            }
        }
    }
}
