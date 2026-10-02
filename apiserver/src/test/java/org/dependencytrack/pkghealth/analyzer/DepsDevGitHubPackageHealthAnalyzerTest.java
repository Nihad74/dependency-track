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
package org.dependencytrack.pkghealth.analyzer;

import com.github.packageurl.PackageURL;
import org.dependencytrack.pkghealth.client.DepsDevApiClient;
import org.dependencytrack.pkghealth.client.GitHubApiClient;
import org.dependencytrack.pkghealth.client.GitHubApiClientProvider;
import org.dependencytrack.pkghealth.model.AnalyzedPackageHealth;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class DepsDevGitHubPackageHealthAnalyzerTest {

    private DepsDevApiClient depsDevApiClient;
    private GitHubApiClientProvider gitHubApiClientProvider;
    private DepsDevGitHubPackageHealthAnalyzer analyzer;

    @BeforeEach
    void beforeEach() {
        depsDevApiClient = mock(DepsDevApiClient.class);
        gitHubApiClientProvider = mock(GitHubApiClientProvider.class);

        analyzer = new DepsDevGitHubPackageHealthAnalyzer(depsDevApiClient, gitHubApiClientProvider);
    }

    @Test
    void shouldSupportDepsDevPackageTypes() {
        assertThat(analyzer.supportedPurlTypes())
                .containsExactlyInAnyOrder("npm", "golang", "maven", "pypi", "nuget", "cargo", "gem");
    }

    @Test
    void shouldReturnNotAvailableForUnsupportedPackageType() throws Exception {
        final var purl = new PackageURL("pkg:docker/library/nginx@1.27");

        assertThat(analyzer.analyze(purl)).isInstanceOf(PackageHealthAnalyzer.AnalysisResult.NotAvailable.class);

        verifyNoInteractions(depsDevApiClient, gitHubApiClientProvider);
    }

    @Test
    void shouldReturnNotAvailableWhenLatestVersionIsMissing() throws Exception {
        final var purl = new PackageURL("pkg:npm/lodash@4.17.21");

        when(depsDevApiClient.fetchLatestVersion("NPM", "lodash")).thenReturn(Optional.empty());

        final var result = analyzer.analyze(purl);

        assertThat(result).isInstanceOf(PackageHealthAnalyzer.AnalysisResult.NotAvailable.class);

        verify(depsDevApiClient).fetchLatestVersion("NPM", "lodash");
        verifyNoInteractions(gitHubApiClientProvider);
    }

    @Test
    void shouldUseLatestVersionAsDependentsFallback() throws Exception {
        final var purl = new PackageURL("pkg:npm/lodash@4.17.20");

        when(depsDevApiClient.fetchLatestVersion("NPM", "lodash")).thenReturn(Optional.of("4.17.21"));

        when(depsDevApiClient.fetchDependents("NPM", "lodash", "4.17.20")).thenReturn(Optional.empty());

        when(depsDevApiClient.fetchDependents("NPM", "lodash", "4.17.21")).thenReturn(Optional.of(123L));

        when(depsDevApiClient.fetchSourceRepository("NPM", "lodash", "4.17.21")).thenReturn(Optional.empty());

        final var result = analyzer.analyze(purl);

        assertThat(result).isInstanceOf(PackageHealthAnalyzer.AnalysisResult.Available.class);

        final var available = (PackageHealthAnalyzer.AnalysisResult.Available) result;

        assertThat(available.metadata().getDependents()).isEqualTo(123L);

        verify(depsDevApiClient).fetchDependents("NPM", "lodash", "4.17.20");

        verify(depsDevApiClient).fetchDependents("NPM", "lodash", "4.17.21");

        verifyNoInteractions(gitHubApiClientProvider);
    }

    @Test
    void shouldSkipGitHubClientForNonGitHubRepository() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");
        final var packagePurl = new PackageURL("pkg:npm/example");

        when(depsDevApiClient.fetchLatestVersion("NPM", "example")).thenReturn(Optional.of("1.0.0"));

        when(depsDevApiClient.fetchDependents("NPM", "example", "1.0.0")).thenReturn(Optional.of(42L));

        when(depsDevApiClient.fetchSourceRepository("NPM", "example", "1.0.0"))
                .thenReturn(Optional.of("gitlab.com/acme/example"));

        when(depsDevApiClient.fetchProjectMetadata(packagePurl, "gitlab.com/acme/example"))
                .thenReturn(Optional.empty());

        final var result = analyzer.analyze(purl);

        assertThat(result).isInstanceOf(PackageHealthAnalyzer.AnalysisResult.Available.class);

        final var available = (PackageHealthAnalyzer.AnalysisResult.Available) result;

        assertThat(available.metadata().getDependents()).isEqualTo(42L);

        verify(depsDevApiClient).fetchProjectMetadata(packagePurl, "gitlab.com/acme/example");

        verifyNoInteractions(gitHubApiClientProvider);
    }

    @Test
    void shouldReturnDepsDevMetadataWhenGitHubIsNotConfigured() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");
        final var packagePurl = new PackageURL("pkg:npm/example");

        when(depsDevApiClient.fetchLatestVersion("NPM", "example")).thenReturn(Optional.of("1.0.0"));

        when(depsDevApiClient.fetchDependents("NPM", "example", "1.0.0")).thenReturn(Optional.of(42L));

        when(depsDevApiClient.fetchSourceRepository("NPM", "example", "1.0.0"))
                .thenReturn(Optional.of("github.com/acme/example"));

        when(depsDevApiClient.fetchProjectMetadata(packagePurl, "github.com/acme/example"))
                .thenReturn(Optional.empty());

        when(gitHubApiClientProvider.get()).thenReturn(Optional.empty());

        final var result = analyzer.analyze(purl);

        assertThat(result).isInstanceOf(PackageHealthAnalyzer.AnalysisResult.Available.class);

        final var available = (PackageHealthAnalyzer.AnalysisResult.Available) result;

        assertThat(available.metadata().getDependents()).isEqualTo(42L);

        verify(gitHubApiClientProvider).get();
    }

    @Test
    void shouldMergeDepsDevAndGitHubMetadata() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");
        final var packagePurl = new PackageURL("pkg:npm/example");
        final var repository = "github.com/acme/example";

        final var depsDevMetadata = new AnalyzedPackageHealth(packagePurl);
        depsDevMetadata.setStars(100L);
        depsDevMetadata.setScorecardScore(8.5f);

        final var gitHubMetadata = new AnalyzedPackageHealth(packagePurl);
        gitHubMetadata.setContributors(12L);
        gitHubMetadata.setHasReadme(true);

        final var gitHubApiClient = mock(GitHubApiClient.class);

        when(depsDevApiClient.fetchLatestVersion("NPM", "example")).thenReturn(Optional.of("1.0.0"));

        when(depsDevApiClient.packagePageUrl("NPM", "example")).thenReturn("https://deps.dev/npm/example");

        when(depsDevApiClient.fetchDependents("NPM", "example", "1.0.0")).thenReturn(Optional.of(42L));

        when(depsDevApiClient.fetchSourceRepository("NPM", "example", "1.0.0")).thenReturn(Optional.of(repository));

        when(depsDevApiClient.fetchProjectMetadata(packagePurl, repository)).thenReturn(Optional.of(depsDevMetadata));

        when(gitHubApiClientProvider.get()).thenReturn(Optional.of(gitHubApiClient));

        when(gitHubApiClient.fetchRepositoryMetadata(packagePurl, repository)).thenReturn(Optional.of(gitHubMetadata));

        final var result = analyzer.analyze(purl);

        assertThat(result).isInstanceOf(PackageHealthAnalyzer.AnalysisResult.Available.class);

        final var metadata = ((PackageHealthAnalyzer.AnalysisResult.Available) result).metadata();

        assertThat(metadata.getPurl()).isEqualTo(packagePurl);
        assertThat(metadata.getDependents()).isEqualTo(42L);
        assertThat(metadata.getDepsDevUrl()).isEqualTo("https://deps.dev/npm/example");
        assertThat(metadata.getGithubUrl()).isEqualTo("https://github.com/acme/example");

        // deps.dev data
        assertThat(metadata.getStars()).isEqualTo(100L);
        assertThat(metadata.getScorecardScore()).isEqualTo(8.5f);

        // GitHub data
        assertThat(metadata.getContributors()).isEqualTo(12L);
        assertThat(metadata.getHasReadme()).isTrue();

        verify(gitHubApiClient).fetchRepositoryMetadata(packagePurl, repository);
    }

    @Test
    void shouldWrapIOExceptionInAnalysisException() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");

        when(depsDevApiClient.fetchLatestVersion("NPM", "example")).thenThrow(new IOException("deps.dev unavailable"));

        assertThatExceptionOfType(PackageHealthAnalyzer.AnalysisException.class)
                .isThrownBy(() -> analyzer.analyze(purl))
                .withCauseInstanceOf(IOException.class);
    }

    @Test
    void shouldPropagateInterruptedException() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");

        when(depsDevApiClient.fetchLatestVersion("NPM", "example"))
                .thenThrow(new InterruptedException("request interrupted"));

        assertThatExceptionOfType(InterruptedException.class).isThrownBy(() -> analyzer.analyze(purl));
    }
}
