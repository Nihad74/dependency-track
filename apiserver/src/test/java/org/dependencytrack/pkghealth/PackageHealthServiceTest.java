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
import org.dependencytrack.pkghealth.analyzer.PackageHealthAnalyzer;
import org.dependencytrack.pkghealth.model.PackageHealthMetaModel;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.assertj.core.api.AssertionsForClassTypes.catchThrowable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class PackageHealthServiceTest {

    private PackageHealthAnalyzer analyzer;
    private PackageHealthService service;

    @BeforeEach
    void beforeEach() {
        analyzer = mock(PackageHealthAnalyzer.class);
        service = new PackageHealthService(analyzer);
    }

    @Test
    void shouldReturnNotAvailableForUnsupportedPurl() throws Exception {
        final var purl = new PackageURL("pkg:docker/library/nginx@1.27");

        when(analyzer.supports(purl)).thenReturn(false);

        final var result = service.fetch(purl);

        assertThat(result).isInstanceOf(PackageHealthAnalyzer.AnalysisResult.NotAvailable.class);

        verify(analyzer).supports(purl);
        verify(analyzer, never()).analyze(purl);
    }

    @Test
    void shouldReturnAnalyzerResultForSupportedPurl() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");
        final var packagePurl = new PackageURL("pkg:npm/example");

        final var expectedResult =
                new PackageHealthAnalyzer.AnalysisResult.Available(new PackageHealthMetaModel(packagePurl));

        when(analyzer.supports(purl)).thenReturn(true);
        when(analyzer.analyze(purl)).thenReturn(expectedResult);

        final var result = service.fetch(purl);

        assertThat(result).isSameAs(expectedResult);

        verify(analyzer).supports(purl);
        verify(analyzer).analyze(purl);
    }

    @Test
    void shouldRejectNullAnalyzer() {
        assertThatNullPointerException()
                .isThrownBy(() -> new PackageHealthService(null))
                .withMessage("analyzer must not be null");
    }

    @Test
    void shouldRejectNullPurl() {
        assertThatNullPointerException().isThrownBy(() -> service.fetch(null)).withMessage("purl must not be null");

        verifyNoInteractions(analyzer);
    }

    @Test
    void shouldPropagateAnalysisException() throws Exception {
        final var purl = new PackageURL("pkg:npm/example@1.0.0");

        final var expectedException =
                new PackageHealthAnalyzer.AnalysisException("Analysis failed", new IOException("deps.dev unavailable"));

        when(analyzer.supports(purl)).thenReturn(true);
        when(analyzer.analyze(purl)).thenThrow(expectedException);

        final var thrown = catchThrowable(() -> service.fetch(purl));

        assertThat(thrown).isSameAs(expectedException);

        verify(analyzer).supports(purl);
        verify(analyzer).analyze(purl);
    }
}
