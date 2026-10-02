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
package org.dependencytrack.pkghealth.mapping;

import org.dependencytrack.model.PackageHealthMetadata;
import org.dependencytrack.model.PackageHealthMetadataStatus;
import org.dependencytrack.pkghealth.model.AnalyzedPackageHealth;
import org.jspecify.annotations.NullMarked;

import java.time.Instant;

import static java.util.Objects.requireNonNull;

@NullMarked
public final class PackageHealthMetadataMapper {

    private PackageHealthMetadataMapper() {}

    public static PackageHealthMetadata map(
            final AnalyzedPackageHealth source, final PackageHealthMetadataStatus status, final Instant lastFetch) {
        requireNonNull(source, "source must not be null");
        requireNonNull(status, "status must not be null");
        requireNonNull(lastFetch, "lastFetch must not be null");

        return new PackageHealthMetadata(
                source.getPurl(),
                source.getStars(),
                source.getForks(),
                source.getContributors(),
                source.getCommitFrequencyWeekly(),
                source.getOpenIssues(),
                source.getOpenPullRequests(),
                source.getLastCommit(),
                source.getBusFactor(),
                source.getHasReadme(),
                source.getHasCodeOfConduct(),
                source.getHasSecurityPolicy(),
                source.getDependents(),
                source.getFiles(),
                source.getRepositoryArchived(),
                source.getScorecardScore(),
                source.getScorecardReferenceVersion(),
                source.getScorecardTimestamp(),
                source.getProjectMetadataObservedAt(),
                source.getDepsDevUrl(),
                source.getGithubUrl(),
                source.getAverageIssueAgeDays(),
                lastFetch,
                status,
                source.getScorecardChecks());
    }
}
