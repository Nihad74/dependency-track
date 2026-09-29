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

import static java.util.Objects.requireNonNull;

public final class PackageHealthService {

    private final PackageHealthAnalyzer analyzer;

    public PackageHealthService(PackageHealthAnalyzer analyzer) {
        this.analyzer = requireNonNull(analyzer, "analyzer must not be null");
    }

    public boolean supports(final PackageURL purl) {
        requireNonNull(purl, "purl must not be null");
        return analyzer.supports(purl);
    }

    public PackageHealthAnalyzer.AnalysisResult fetch(PackageURL purl)
            throws PackageHealthAnalyzer.AnalysisException, InterruptedException {
        requireNonNull(purl, "purl must not be null");

        if (!supports(purl)) {
            return new PackageHealthAnalyzer.AnalysisResult.NotAvailable();
        }

        return analyzer.analyze(purl);
    }
}
