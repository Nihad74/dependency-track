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

import com.github.packageurl.PackageURL;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.failure.ApplicationFailureException;
import org.dependencytrack.model.PackageHealthMetadataStatus;
import org.dependencytrack.model.PackageMetadata;
import org.dependencytrack.persistence.jdbi.PackageHealthMetadataDao;
import org.dependencytrack.persistence.jdbi.PackageMetadataDao;
import org.dependencytrack.pkghealth.analyzer.PackageHealthAnalyzer;
import org.dependencytrack.pkghealth.client.ApiRateLimitException;
import org.dependencytrack.pkghealth.model.AnalyzedPackageHealth;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataActivityArg;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class ResolvePackageHealthMetadataActivityTest extends PersistenceCapableTest {

    private static final Instant NOW = Instant.parse("2026-09-24T12:00:00Z");

    private PackageHealthService packageHealthService;
    private ResolvePackageHealthMetadataActivity activity;

    @BeforeEach
    void beforeEach() {
        packageHealthService = mock(PackageHealthService.class);

        activity = new ResolvePackageHealthMetadataActivity(packageHealthService, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void shouldFetchAndPersistAvailableMetadata() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");
        final var packagePurl = new PackageURL("pkg:npm/example");

        createPackageMetadata(packagePurl);

        final var model = new AnalyzedPackageHealth(packagePurl);
        model.setStars(100L);
        model.setHasReadme(true);

        when(packageHealthService.fetch(purl)).thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(model));

        final var arg = ResolvePackageHealthMetadataActivityArg.newBuilder()
                .addPurls(purl.toString())
                .build();

        final var firstResult = activity.execute(mock(ActivityContext.class), arg);
        assertThat(firstResult.getChangedPurlsList()).containsExactly(packagePurl.canonicalize());

        final var secondResult = activity.execute(mock(ActivityContext.class), arg);
        assertThat(secondResult.getChangedPurlsList()).isEmpty();

        model.setStars(101L);
        final var thirdResult = activity.execute(mock(ActivityContext.class), arg);
        assertThat(thirdResult.getChangedPurlsList()).containsExactly(packagePurl.canonicalize());

        final var persisted = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(packagePurl));

        assertThat(persisted).isNotNull();
        assertThat(persisted.purl()).isEqualTo(packagePurl);
        assertThat(persisted.stars()).isEqualTo(101L);
        assertThat(persisted.hasReadme()).isTrue();
        assertThat(persisted.status()).isEqualTo(PackageHealthMetadataStatus.PROCESSED);
        assertThat(persisted.lastFetch()).isEqualTo(NOW);
    }

    @Test
    void shouldPersistNotAvailableMetadata() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");
        final var packagePurl = new PackageURL("pkg:npm/example");

        createPackageMetadata(packagePurl);

        when(packageHealthService.fetch(purl)).thenReturn(new PackageHealthAnalyzer.AnalysisResult.NotAvailable());

        final var arg = ResolvePackageHealthMetadataActivityArg.newBuilder()
                .addPurls(purl.toString())
                .build();

        activity.execute(mock(ActivityContext.class), arg);

        final var persisted = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(packagePurl));

        assertThat(persisted).isNotNull();
        assertThat(persisted.purl()).isEqualTo(packagePurl);
        assertThat(persisted.status()).isEqualTo(PackageHealthMetadataStatus.NOT_AVAILABLE);
        assertThat(persisted.lastFetch()).isEqualTo(NOW);

        assertThat(persisted.stars()).isNull();
        assertThat(persisted.scorecardChecks()).isEmpty();
    }

    @Test
    void shouldIgnoreNullArgument() throws Exception {
        activity.execute(mock(ActivityContext.class), null);

        verifyNoInteractions(packageHealthService);
    }

    @Test
    void shouldIgnoreEmptyPurlList() throws Exception {
        final var arg = ResolvePackageHealthMetadataActivityArg.newBuilder().build();

        activity.execute(mock(ActivityContext.class), arg);

        verifyNoInteractions(packageHealthService);
    }

    @Test
    void shouldProcessMultiplePurls() throws Exception {
        final var npmPurl = new PackageURL("pkg:npm/example@1.0.0");
        final var npmPackagePurl = new PackageURL("pkg:npm/example");

        final var pypiPurl = new PackageURL("pkg:pypi/requests@2.32.0");
        final var pypiPackagePurl = new PackageURL("pkg:pypi/requests");

        createPackageMetadata(npmPackagePurl);
        createPackageMetadata(pypiPackagePurl);

        final var npmModel = new AnalyzedPackageHealth(npmPackagePurl);
        npmModel.setStars(100L);

        when(packageHealthService.fetch(npmPurl))
                .thenReturn(new PackageHealthAnalyzer.AnalysisResult.Available(npmModel));

        when(packageHealthService.fetch(pypiPurl)).thenReturn(new PackageHealthAnalyzer.AnalysisResult.NotAvailable());

        final var arg = ResolvePackageHealthMetadataActivityArg.newBuilder()
                .addPurls(npmPurl.toString())
                .addPurls(pypiPurl.toString())
                .build();

        activity.execute(mock(ActivityContext.class), arg);

        final var npmMetadata = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(npmPackagePurl));

        final var pypiMetadata = withJdbiHandle(handle -> new PackageHealthMetadataDao(handle).get(pypiPackagePurl));

        assertThat(npmMetadata).isNotNull();
        assertThat(npmMetadata.status()).isEqualTo(PackageHealthMetadataStatus.PROCESSED);
        assertThat(npmMetadata.stars()).isEqualTo(100L);

        assertThat(pypiMetadata).isNotNull();
        assertThat(pypiMetadata.status()).isEqualTo(PackageHealthMetadataStatus.NOT_AVAILABLE);

        verify(packageHealthService).fetch(npmPurl);
        verify(packageHealthService).fetch(pypiPurl);
    }

    @Test
    void shouldPropagateAnalysisException() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");

        final var expectedException =
                new PackageHealthAnalyzer.AnalysisException("Analysis failed", new IOException("deps.dev unavailable"));

        when(packageHealthService.fetch(purl)).thenThrow(expectedException);

        final var arg = ResolvePackageHealthMetadataActivityArg.newBuilder()
                .addPurls(purl.toString())
                .build();

        final var thrown = catchThrowable(() -> activity.execute(mock(ActivityContext.class), arg));

        assertThat(thrown).isSameAs(expectedException);
    }

    @Test
    void shouldRetryAfterApiRateLimitReset() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");
        final var resetAt = NOW.plus(Duration.ofMinutes(10));

        when(packageHealthService.fetch(purl))
                .thenThrow(new PackageHealthAnalyzer.AnalysisException(
                        "GitHub request failed", new ApiRateLimitException(resetAt)));

        final var arg = ResolvePackageHealthMetadataActivityArg.newBuilder()
                .addPurls(purl.toString())
                .build();

        assertThatExceptionOfType(ApplicationFailureException.class)
                .isThrownBy(() -> activity.execute(mock(ActivityContext.class), arg))
                .satisfies(e -> assertThat(e.retryAfter())
                        .isEqualTo(Duration.ofMinutes(10).plusSeconds(2)));
    }

    private static void createPackageMetadata(final PackageURL packagePurl) {
        withJdbiHandle(handle -> new PackageMetadataDao(handle)
                .upsertAll(List.of(new PackageMetadata(packagePurl, "1.0.0", null, NOW, "test", "test"))));
    }
}
