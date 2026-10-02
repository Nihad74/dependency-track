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

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Compares the package health values that component policies can read.
 * <p>
 * Average issue age and commit frequency are computed relative to the time of the fetch,
 * so they change on every refresh even when nothing changed upstream. Those changes are
 * not reported, so that an unchanged refresh does not start policy evaluation.
 */
final class PackageHealthPolicyDelta {

    /**
     * Smallest change in average issue age, beyond the time elapsed between fetches,
     * that counts as a change.
     */
    private static final double ISSUE_AGE_TOLERANCE_DAYS = 1.0;

    /**
     * Smallest relative change in commit frequency that counts as a change. Commit frequency
     * divides by the repository age in weeks, so it shrinks by less than 2% per week for
     * repositories older than a year without any new commits.
     */
    private static final double COMMIT_FREQUENCY_RELATIVE_TOLERANCE = 0.05;

    private PackageHealthPolicyDelta() {}

    static boolean changed(final @Nullable PackageHealthMetadata previous, final PackageHealthMetadata next) {
        if (previous == null) {
            return hasPolicyValue(next);
        }

        return !Objects.equals(previous.stars(), next.stars())
                || !Objects.equals(previous.forks(), next.forks())
                || commitFrequencyChanged(previous.commitFrequencyWeekly(), next.commitFrequencyWeekly())
                || !Objects.equals(previous.lastCommit(), next.lastCommit())
                || !Objects.equals(previous.busFactor(), next.busFactor())
                || !Objects.equals(previous.dependents(), next.dependents())
                || !Objects.equals(previous.repositoryArchived(), next.repositoryArchived())
                || !Objects.equals(previous.scorecardScore(), next.scorecardScore())
                || issueAgeChanged(previous, next)
                || !sameChecks(previous.scorecardChecks(), next.scorecardChecks());
    }

    private static boolean issueAgeChanged(final PackageHealthMetadata previous, final PackageHealthMetadata next) {
        final @Nullable Float previousAge = previous.averageIssueAgeDays();
        final @Nullable Float nextAge = next.averageIssueAgeDays();
        if (Objects.equals(previousAge, nextAge)) {
            return false;
        }
        if (previousAge == null || nextAge == null) {
            return true;
        }

        final @Nullable Instant previousFetch = previous.lastFetch();
        final @Nullable Instant nextFetch = next.lastFetch();
        final double elapsedDays = previousFetch != null && nextFetch != null
                ? Duration.between(previousFetch, nextFetch).toSeconds() / 86_400.0
                : 0;
        return Math.abs(nextAge - (previousAge + elapsedDays)) >= ISSUE_AGE_TOLERANCE_DAYS;
    }

    private static boolean commitFrequencyChanged(final @Nullable Float previous, final @Nullable Float next) {
        if (Objects.equals(previous, next)) {
            return false;
        }
        if (previous == null || next == null) {
            return true;
        }

        final double magnitude = Math.max(Math.abs(previous), Math.abs(next));
        return Math.abs(next - previous) / magnitude >= COMMIT_FREQUENCY_RELATIVE_TOLERANCE;
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
