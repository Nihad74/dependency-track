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

import com.github.packageurl.PackageURL;
import org.dependencytrack.model.PackageHealthMetadataStatus;
import org.dependencytrack.model.PackageHealthScorecardCheck;
import org.dependencytrack.pkghealth.model.AnalyzedPackageHealth;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class PackageHealthMetadataMapperTest {

    @Test
    void shouldMapMetadata() throws Exception {
        final var purl = new PackageURL("pkg:npm/example");
        final var lastFetch = Instant.parse("2026-09-24T10:00:00Z");

        final var source = new AnalyzedPackageHealth(purl);
        source.setStars(100L);
        source.setOpenIssues(12L);
        source.setHasReadme(true);

        final var result = PackageHealthMetadataMapper.map(source, PackageHealthMetadataStatus.PROCESSED, lastFetch);

        assertThat(result.purl()).isEqualTo(purl);
        assertThat(result.stars()).isEqualTo(100L);
        assertThat(result.openIssues()).isEqualTo(12L);
        assertThat(result.hasReadme()).isTrue();
        assertThat(result.status()).isEqualTo(PackageHealthMetadataStatus.PROCESSED);
        assertThat(result.lastFetch()).isEqualTo(lastFetch);
    }

    @Test
    void shouldMapScorecardMetadata() throws Exception {
        final var purl = new PackageURL("pkg:npm/example");
        final var lastFetch = Instant.parse("2026-09-24T10:00:00Z");
        final var scorecardTimestamp = Instant.parse("2026-09-23T08:00:00Z");

        final var check = new PackageHealthScorecardCheck(
                purl,
                "Maintained",
                "Determines whether the project is maintained",
                9.0f,
                "Repository is actively maintained",
                List.of("30 commits found"),
                "https://github.com/ossf/scorecard");

        final var source = new AnalyzedPackageHealth(purl);
        source.setScorecardScore(8.7f);
        source.setScorecardReferenceVersion("v5.0.0");
        source.setScorecardTimestamp(scorecardTimestamp);
        source.setProjectMetadataObservedAt(Instant.ofEpochSecond(1658223503));
        source.setDepsDevUrl("https://deps.dev/npm/example");
        source.setGithubUrl("https://github.com/example/example");
        source.setScorecardChecks(List.of(check));

        final var result = PackageHealthMetadataMapper.map(source, PackageHealthMetadataStatus.PROCESSED, lastFetch);

        assertThat(result.scorecardScore()).isEqualTo(8.7f);
        assertThat(result.scorecardReferenceVersion()).isEqualTo("v5.0.0");
        assertThat(result.scorecardTimestamp()).isEqualTo(scorecardTimestamp);
        assertThat(result.projectMetadataObservedAt()).isEqualTo(Instant.ofEpochSecond(1658223503));
        assertThat(result.depsDevUrl()).isEqualTo("https://deps.dev/npm/example");
        assertThat(result.githubUrl()).isEqualTo("https://github.com/example/example");
        assertThat(result.scorecardChecks()).containsExactly(check);
    }

    @Test
    void shouldMapRepositoryMetadata() throws Exception {
        final var purl = new PackageURL("pkg:maven/org.example/example");
        final var lastCommit = Instant.parse("2026-09-20T12:00:00Z");
        final var lastFetch = Instant.parse("2026-09-24T10:00:00Z");

        final var source = new AnalyzedPackageHealth(purl);
        source.setForks(20L);
        source.setContributors(15L);
        source.setCommitFrequencyWeekly(3.5f);
        source.setOpenPullRequests(4L);
        source.setLastCommit(lastCommit);
        source.setBusFactor(3);
        source.setHasCodeOfConduct(true);
        source.setHasSecurityPolicy(false);
        source.setDependents(200L);
        source.setFiles(900L);
        source.setRepositoryArchived(false);
        source.setAverageIssueAgeDays(6.5f);

        final var result = PackageHealthMetadataMapper.map(source, PackageHealthMetadataStatus.PROCESSED, lastFetch);

        assertThat(result.forks()).isEqualTo(20L);
        assertThat(result.contributors()).isEqualTo(15L);
        assertThat(result.commitFrequencyWeekly()).isEqualTo(3.5f);
        assertThat(result.openPullRequests()).isEqualTo(4L);
        assertThat(result.lastCommit()).isEqualTo(lastCommit);
        assertThat(result.busFactor()).isEqualTo(3);
        assertThat(result.hasCodeOfConduct()).isTrue();
        assertThat(result.hasSecurityPolicy()).isFalse();
        assertThat(result.dependents()).isEqualTo(200L);
        assertThat(result.files()).isEqualTo(900L);
        assertThat(result.repositoryArchived()).isFalse();
        assertThat(result.averageIssueAgeDays()).isEqualTo(6.5f);
    }

    @Test
    void shouldRejectNullSource() {
        assertThatNullPointerException()
                .isThrownBy(() ->
                        PackageHealthMetadataMapper.map(null, PackageHealthMetadataStatus.PROCESSED, Instant.EPOCH))
                .withMessage("source must not be null");
    }

    @Test
    void shouldRejectNullStatus() throws Exception {
        final var source = new AnalyzedPackageHealth(new PackageURL("pkg:npm/example"));

        assertThatNullPointerException()
                .isThrownBy(() -> PackageHealthMetadataMapper.map(source, null, Instant.EPOCH))
                .withMessage("status must not be null");
    }

    @Test
    void shouldRejectNullLastFetch() throws Exception {
        final var source = new AnalyzedPackageHealth(new PackageURL("pkg:npm/example"));

        assertThatNullPointerException()
                .isThrownBy(() -> PackageHealthMetadataMapper.map(source, PackageHealthMetadataStatus.PROCESSED, null))
                .withMessage("lastFetch must not be null");
    }
}
