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
package org.dependencytrack.pkghealth;

import org.dependencytrack.model.PackageHealthMetadata;
import org.dependencytrack.model.PackageHealthScorecardCheck;
import org.jspecify.annotations.Nullable;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Compares the package health values that component policies can read.
 */
final class PackageHealthPolicyDelta {

    private PackageHealthPolicyDelta() {}

    static boolean changed(final @Nullable PackageHealthMetadata previous, final PackageHealthMetadata next) {
        if (previous == null) {
            return hasPolicyValue(next);
        }

        return !Objects.equals(previous.stars(), next.stars())
                || !Objects.equals(previous.forks(), next.forks())
                || !Objects.equals(previous.commitFrequencyWeekly(), next.commitFrequencyWeekly())
                || !Objects.equals(previous.lastCommit(), next.lastCommit())
                || !Objects.equals(previous.busFactor(), next.busFactor())
                || !Objects.equals(previous.dependents(), next.dependents())
                || !Objects.equals(previous.repositoryArchived(), next.repositoryArchived())
                || !Objects.equals(previous.scorecardScore(), next.scorecardScore())
                || !Objects.equals(previous.averageIssueAgeDays(), next.averageIssueAgeDays())
                || !sameChecks(previous.scorecardChecks(), next.scorecardChecks());
    }

    private static boolean hasPolicyValue(final PackageHealthMetadata metadata) {
        return metadata.stars() != null
                || metadata.forks() != null
                || metadata.commitFrequencyWeekly() != null
                || metadata.lastCommit() != null
                || metadata.busFactor() != null
                || metadata.dependents() != null
                || metadata.repositoryArchived() != null
                || metadata.scorecardScore() != null
                || metadata.averageIssueAgeDays() != null
                || !metadata.scorecardChecks().isEmpty();
    }

    private static boolean sameChecks(
            final List<PackageHealthScorecardCheck> previous, final List<PackageHealthScorecardCheck> next) {
        return checkScores(previous).equals(checkScores(next));
    }

    private static Map<String, @Nullable Float> checkScores(final List<PackageHealthScorecardCheck> checks) {
        final var scores = new HashMap<String, @Nullable Float>(checks.size());
        for (final PackageHealthScorecardCheck check : checks) {
            scores.put(check.name(), check.score());
        }
        return scores;
    }
}
