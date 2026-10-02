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
import org.dependencytrack.dex.api.failure.ApplicationFailureException;
import org.dependencytrack.model.PackageHealthMetadata;
import org.dependencytrack.model.PackageHealthMetadataStatus;
import org.dependencytrack.persistence.jdbi.PackageHealthMetadataDao;
import org.dependencytrack.pkghealth.analyzer.PackageHealthAnalyzer;
import org.dependencytrack.pkghealth.client.ApiRateLimitException;
import org.dependencytrack.pkghealth.mapping.PackageHealthMetadataMapper;
import org.dependencytrack.pkghealth.model.AnalyzedPackageHealth;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataActivityArg;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataActivityRes;
import org.dependencytrack.util.InternalComponentIdentifier;
import org.dependencytrack.util.PurlUtil;
import org.jspecify.annotations.Nullable;

import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;

@ActivitySpec(name = "resolve-package-health-metadata", defaultTaskQueue = "package-health-metadata-resolutions")
public final class ResolvePackageHealthMetadataActivity
        implements Activity<ResolvePackageHealthMetadataActivityArg, ResolvePackageHealthMetadataActivityRes> {

    private final PackageHealthAnalyzer analyzer;
    private final Clock clock;

    public ResolvePackageHealthMetadataActivity(final PackageHealthAnalyzer analyzer) {
        this(analyzer, Clock.systemUTC());
    }

    ResolvePackageHealthMetadataActivity(final PackageHealthAnalyzer analyzer, final Clock clock) {
        this.analyzer = requireNonNull(analyzer, "analyzer must not be null");
        this.clock = requireNonNull(clock, "clock must not be null");
    }

    @Override
    public @Nullable ResolvePackageHealthMetadataActivityRes execute(
            final ActivityContext ctx, final @Nullable ResolvePackageHealthMetadataActivityArg arg) throws Exception {
        if (arg == null || arg.getPurlsList().isEmpty()) {
            return ResolvePackageHealthMetadataActivityRes.getDefaultInstance();
        }

        // Same rule as package metadata resolution: names of internal packages must not leave the server.
        final var internalIdentifier = new InternalComponentIdentifier();

        final var metadataToPersist = new ArrayList<PackageHealthMetadata>(arg.getPurlsCount());
        for (final String purlString : arg.getPurlsList()) {
            final var purl = new PackageURL(purlString);
            if (internalIdentifier.isInternal(purl)) {
                metadataToPersist.add(notAvailable(purl));
                continue;
            }

            try {
                metadataToPersist.add(fetchMetadata(purl));
            } catch (PackageHealthAnalyzer.AnalysisException e) {
                if (e.getCause() instanceof ApiRateLimitException rateLimit) {
                    final Duration wait = Duration.between(
                            clock.instant(), rateLimit.resetAt().plusSeconds(2));
                    if (wait.isPositive()) {
                        throw new ApplicationFailureException("External API rate limit reached", e, wait);
                    }
                }
                throw e;
            }
        }

        if (Thread.interrupted()) {
            throw new InterruptedException("Interrupted before package health metadata was stored");
        }

        final List<String> changedPurls = inJdbiTransaction(handle -> {
            final var dao = new PackageHealthMetadataDao(handle);
            final Map<String, PackageHealthMetadata> previousByPurl = dao.getAll(
                    metadataToPersist.stream().map(PackageHealthMetadata::purl).toList());
            dao.upsertAll(metadataToPersist);

            final var changed = new ArrayList<String>(metadataToPersist.size());
            for (final PackageHealthMetadata metadata : metadataToPersist) {
                final String packagePurl = metadata.purl().canonicalize();
                if (PackageHealthPolicyDelta.changed(previousByPurl.get(packagePurl), metadata)) {
                    changed.add(packagePurl);
                }
            }
            return changed;
        });

        return ResolvePackageHealthMetadataActivityRes.newBuilder()
                .addAllChangedPurls(changedPurls)
                .build();
    }

    private PackageHealthMetadata fetchMetadata(final PackageURL purl)
            throws PackageHealthAnalyzer.AnalysisException, InterruptedException {
        final var result = analyzer.analyze(purl);

        if (result instanceof PackageHealthAnalyzer.AnalysisResult.Available available) {
            return PackageHealthMetadataMapper.map(
                    available.metadata(), PackageHealthMetadataStatus.PROCESSED, clock.instant());
        }

        return notAvailable(purl);
    }

    private PackageHealthMetadata notAvailable(final PackageURL purl) {
        final PackageURL packagePurl =
                requireNonNull(PurlUtil.silentPurlPackageOnly(purl), "Unable to create package-only PURL");
        return PackageHealthMetadataMapper.map(
                new AnalyzedPackageHealth(packagePurl), PackageHealthMetadataStatus.NOT_AVAILABLE, clock.instant());
    }
}
