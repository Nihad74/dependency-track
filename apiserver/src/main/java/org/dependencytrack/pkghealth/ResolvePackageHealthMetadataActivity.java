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
import com.google.protobuf.util.Timestamps;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.model.PackageHealthMetadata;
import org.dependencytrack.model.PackageHealthMetadataStatus;
import org.dependencytrack.persistence.jdbi.PackageHealthMetadataDao;
import org.dependencytrack.pkghealth.analyzer.PackageHealthAnalyzer;
import org.dependencytrack.pkghealth.client.ApiRateLimitException;
import org.dependencytrack.pkghealth.model.AnalyzedPackageHealth;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataActivityArg;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataActivityRes;
import org.dependencytrack.util.InternalComponentIdentifier;
import org.dependencytrack.util.PurlUtil;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/**
 * Fetches and stores health metadata for one batch of packages.
 * <p>
 * When an external API rate limit is reached, the packages fetched so far are stored, and the
 * remaining packages are returned together with the time the limit resets. The workflow waits
 * for that time, so rate limits do not use up retry attempts.
 */
@ActivitySpec(name = "resolve-package-health-metadata", defaultTaskQueue = "package-health-metadata-resolutions")
public final class ResolvePackageHealthMetadataActivity
        implements Activity<ResolvePackageHealthMetadataActivityArg, ResolvePackageHealthMetadataActivityRes> {

    private static final Logger LOGGER = LoggerFactory.getLogger(ResolvePackageHealthMetadataActivity.class);

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

        // The setting can be turned off while a run waits for a rate limit to reset.
        if (!withJdbiHandle(PackageHealthSettings::isEnabled)) {
            LOGGER.info("Package health metadata resolution is disabled; Skipping {} packages", arg.getPurlsCount());
            return ResolvePackageHealthMetadataActivityRes.getDefaultInstance();
        }

        // Same rule as package metadata resolution: names of internal packages must not leave the server.
        final var internalIdentifier = new InternalComponentIdentifier();

        final List<String> purls = arg.getPurlsList();
        final var metadataToPersist = new ArrayList<PackageHealthMetadata>(purls.size());
        @Nullable ApiRateLimitException rateLimit = null;
        List<String> unresolvedPurls = List.of();

        for (int i = 0; i < purls.size(); i++) {
            final var purl = new PackageURL(purls.get(i));
            if (internalIdentifier.isInternal(purl)) {
                metadataToPersist.add(notAvailable(purl));
                continue;
            }

            try {
                metadataToPersist.add(fetchMetadata(purl));
            } catch (PackageHealthAnalyzer.AnalysisException e) {
                if (e.getCause() instanceof ApiRateLimitException rateLimitException) {
                    rateLimit = rateLimitException;
                    unresolvedPurls = purls.subList(i, purls.size());
                    break;
                }
                // Not stored, so the package stays due and is tried again by the next run.
                LOGGER.warn("Failed to resolve health metadata for {}; Skipping it", purl, e);
            }
        }

        if (Thread.interrupted()) {
            throw new InterruptedException("Interrupted before package health metadata was stored");
        }

        final List<String> changedPurls = metadataToPersist.isEmpty() ? List.of() : persist(metadataToPersist);

        final var result = ResolvePackageHealthMetadataActivityRes.newBuilder()
                .addAllChangedPurls(changedPurls)
                .addAllUnresolvedPurls(unresolvedPurls);
        if (rateLimit != null) {
            result.setRateLimitResetAt(Timestamps.fromMillis(rateLimit.resetAt().toEpochMilli()));
        }
        return result.build();
    }

    private static List<String> persist(final List<PackageHealthMetadata> metadataToPersist) {
        return inJdbiTransaction(handle -> {
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
    }

    private PackageHealthMetadata fetchMetadata(final PackageURL purl)
            throws PackageHealthAnalyzer.AnalysisException, InterruptedException {
        final var result = analyzer.analyze(purl);

        if (result instanceof PackageHealthAnalyzer.AnalysisResult.Available available) {
            return available.metadata().toMetadata(PackageHealthMetadataStatus.PROCESSED, clock.instant());
        }

        return notAvailable(purl);
    }

    private PackageHealthMetadata notAvailable(final PackageURL purl) {
        final PackageURL packagePurl =
                requireNonNull(PurlUtil.silentPurlPackageOnly(purl), "Unable to create package-only PURL");
        return new AnalyzedPackageHealth(packagePurl)
                .toMetadata(PackageHealthMetadataStatus.NOT_AVAILABLE, clock.instant());
    }
}
