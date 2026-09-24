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
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.model.PackageHealthMetadata;
import org.dependencytrack.model.PackageHealthMetadataStatus;
import org.dependencytrack.persistence.jdbi.PackageHealthMetadataDao;
import org.dependencytrack.pkghealth.analyzer.PackageHealthAnalyzer;
import org.dependencytrack.pkghealth.mapping.PackageHealthMetadataMapper;
import org.dependencytrack.pkghealth.model.PackageHealthMetaModel;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataActivityArg;
import org.dependencytrack.util.PurlUtil;
import org.jspecify.annotations.Nullable;

import java.time.Clock;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;

@ActivitySpec(name = "resolve-package-health-metadata", defaultTaskQueue = "package-health-metadata-resolutions")
public final class ResolvePackageHealthMetadataActivity
        implements Activity<ResolvePackageHealthMetadataActivityArg, Void> {

    private final PackageHealthService packageHealthService;
    private final Clock clock;

    public ResolvePackageHealthMetadataActivity(final PackageHealthService packageHealthService) {
        this(packageHealthService, Clock.systemUTC());
    }

    ResolvePackageHealthMetadataActivity(final PackageHealthService packageHealthService, final Clock clock) {
        this.packageHealthService = requireNonNull(packageHealthService, "packageHealthService must not be null");
        this.clock = requireNonNull(clock, "clock must not be null");
    }

    @Override
    public @Nullable Void execute(
            final ActivityContext ctx, final @Nullable ResolvePackageHealthMetadataActivityArg arg) throws Exception {
        if (arg == null || arg.getPurlsList().isEmpty()) {
            return null;
        }

        for (final String purlString : arg.getPurlsList()) {
            resolveAndPersist(new PackageURL(purlString));
        }

        return null;
    }

    private void resolveAndPersist(final PackageURL purl) throws PackageHealthAnalyzer.AnalysisException {
        final var result = packageHealthService.fetch(purl);
        final PackageHealthMetadata metadata;

        if (result instanceof PackageHealthAnalyzer.AnalysisResult.Available available) {
            metadata = PackageHealthMetadataMapper.map(
                    available.metadata(), PackageHealthMetadataStatus.PROCESSED, clock.instant());
        } else {
            final PackageURL packagePurl =
                    requireNonNull(PurlUtil.silentPurlPackageOnly(purl), "Unable to create package-only PURL");

            metadata = PackageHealthMetadataMapper.map(
                    new PackageHealthMetaModel(packagePurl),
                    PackageHealthMetadataStatus.NOT_AVAILABLE,
                    clock.instant());
        }

        useJdbiHandle(handle -> new PackageHealthMetadataDao(handle).upsert(metadata));
    }
}
