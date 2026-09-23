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
package org.dependencytrack.persistence.jdbi;

import com.github.packageurl.PackageURL;
import org.dependencytrack.model.PackageHealthMetadata;
import org.dependencytrack.model.PackageHealthScorecardCheck;
import org.dependencytrack.util.PurlUtil;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.List;

/**
 * Provides persistence operations for package health metadata.
 *
 * @since 5.2.0
 */
@NullMarked
public final class PackageHealthMetadataDao {

    private final Handle jdbiHandle;

    public PackageHealthMetadataDao(final Handle jdbiHandle) {
        this.jdbiHandle = jdbiHandle;
    }

    public @Nullable PackageHealthMetadata get(final PackageURL purl) {
        final String canonicalPurl = PurlUtil.purlPackageOnly(purl);

        final PackageHealthMetadata metadata = jdbiHandle
                .createQuery("""
                        SELECT "PURL"
                             , "STARS"
                             , "FORKS"
                             , "CONTRIBUTORS"
                             , "COMMIT_FREQUENCY_WEEKLY"
                             , "OPEN_ISSUES"
                             , "OPEN_PRS"
                             , "LAST_COMMIT"
                             , "BUS_FACTOR"
                             , "HAS_README"
                             , "HAS_CODE_OF_CONDUCT"
                             , "HAS_SECURITY_POLICY"
                             , "DEPENDENTS"
                             , "FILES"
                             , "IS_REPO_ARCHIVED"
                             , "SCORECARD_SCORE"
                             , "SCORECARD_REF_VERSION"
                             , "SCORECARD_TIMESTAMP"
                             , "AVG_ISSUE_AGE_DAYS"
                             , "LAST_FETCH"
                             , "STATUS"
                          FROM "PACKAGE_HEALTH_METADATA"
                         WHERE "PURL" = :purl
                        """)
                .bind("purl", canonicalPurl)
                .mapTo(PackageHealthMetadata.class)
                .findOne()
                .orElse(null);

        if (metadata == null) {
            return null;
        }

        final List<PackageHealthScorecardCheck> checks = jdbiHandle
                .createQuery("""
                        SELECT "PURL"
                             , "CHECK_NAME"
                             , "DESCRIPTION"
                             , "SCORE"
                             , "REASON"
                             , "DETAILS"
                             , "DOCUMENTATION_URL"
                          FROM "PACKAGE_HEALTH_SCORECARD_CHECK"
                         WHERE "PURL" = :purl
                         ORDER BY "CHECK_NAME"
                        """)
                .bind("purl", canonicalPurl)
                .mapTo(PackageHealthScorecardCheck.class)
                .list();

        return withScorecardChecks(metadata, checks);
    }

    public void upsert(final PackageHealthMetadata metadata) {
        jdbiHandle.useTransaction(handle -> {
            final String canonicalPurl = PurlUtil.purlPackageOnly(metadata.purl());

            upsertMetadata(handle, canonicalPurl, metadata);
            replaceScorecardChecks(handle, canonicalPurl, metadata.scorecardChecks());
        });
    }

    private static void upsertMetadata(
            final Handle handle, final String canonicalPurl, final PackageHealthMetadata metadata) {

        handle.createUpdate("""
                        INSERT INTO "PACKAGE_HEALTH_METADATA" (
                          "PURL"
                        , "STARS"
                        , "FORKS"
                        , "CONTRIBUTORS"
                        , "COMMIT_FREQUENCY_WEEKLY"
                        , "OPEN_ISSUES"
                        , "OPEN_PRS"
                        , "LAST_COMMIT"
                        , "BUS_FACTOR"
                        , "HAS_README"
                        , "HAS_CODE_OF_CONDUCT"
                        , "HAS_SECURITY_POLICY"
                        , "DEPENDENTS"
                        , "FILES"
                        , "IS_REPO_ARCHIVED"
                        , "SCORECARD_SCORE"
                        , "SCORECARD_REF_VERSION"
                        , "SCORECARD_TIMESTAMP"
                        , "AVG_ISSUE_AGE_DAYS"
                        , "LAST_FETCH"
                        , "STATUS"
                        )
                        VALUES (
                          :purl
                        , :stars
                        , :forks
                        , :contributors
                        , :commitFrequencyWeekly
                        , :openIssues
                        , :openPullRequests
                        , :lastCommit
                        , :busFactor
                        , :hasReadme
                        , :hasCodeOfConduct
                        , :hasSecurityPolicy
                        , :dependents
                        , :files
                        , :repositoryArchived
                        , :scorecardScore
                        , :scorecardReferenceVersion
                        , :scorecardTimestamp
                        , :averageIssueAgeDays
                        , :lastFetch
                        , :status
                        )
                        ON CONFLICT ("PURL") DO UPDATE
                        SET "STARS" = EXCLUDED."STARS"
                          , "FORKS" = EXCLUDED."FORKS"
                          , "CONTRIBUTORS" = EXCLUDED."CONTRIBUTORS"
                          , "COMMIT_FREQUENCY_WEEKLY" = EXCLUDED."COMMIT_FREQUENCY_WEEKLY"
                          , "OPEN_ISSUES" = EXCLUDED."OPEN_ISSUES"
                          , "OPEN_PRS" = EXCLUDED."OPEN_PRS"
                          , "LAST_COMMIT" = EXCLUDED."LAST_COMMIT"
                          , "BUS_FACTOR" = EXCLUDED."BUS_FACTOR"
                          , "HAS_README" = EXCLUDED."HAS_README"
                          , "HAS_CODE_OF_CONDUCT" = EXCLUDED."HAS_CODE_OF_CONDUCT"
                          , "HAS_SECURITY_POLICY" = EXCLUDED."HAS_SECURITY_POLICY"
                          , "DEPENDENTS" = EXCLUDED."DEPENDENTS"
                          , "FILES" = EXCLUDED."FILES"
                          , "IS_REPO_ARCHIVED" = EXCLUDED."IS_REPO_ARCHIVED"
                          , "SCORECARD_SCORE" = EXCLUDED."SCORECARD_SCORE"
                          , "SCORECARD_REF_VERSION" = EXCLUDED."SCORECARD_REF_VERSION"
                          , "SCORECARD_TIMESTAMP" = EXCLUDED."SCORECARD_TIMESTAMP"
                          , "AVG_ISSUE_AGE_DAYS" = EXCLUDED."AVG_ISSUE_AGE_DAYS"
                          , "LAST_FETCH" = EXCLUDED."LAST_FETCH"
                          , "STATUS" = EXCLUDED."STATUS"
                        """)
                .bind("purl", canonicalPurl)
                .bind("stars", metadata.stars())
                .bind("forks", metadata.forks())
                .bind("contributors", metadata.contributors())
                .bind("commitFrequencyWeekly", metadata.commitFrequencyWeekly())
                .bind("openIssues", metadata.openIssues())
                .bind("openPullRequests", metadata.openPullRequests())
                .bind("lastCommit", metadata.lastCommit())
                .bind("busFactor", metadata.busFactor())
                .bind("hasReadme", metadata.hasReadme())
                .bind("hasCodeOfConduct", metadata.hasCodeOfConduct())
                .bind("hasSecurityPolicy", metadata.hasSecurityPolicy())
                .bind("dependents", metadata.dependents())
                .bind("files", metadata.files())
                .bind("repositoryArchived", metadata.repositoryArchived())
                .bind("scorecardScore", metadata.scorecardScore())
                .bind("scorecardReferenceVersion", metadata.scorecardReferenceVersion())
                .bind("scorecardTimestamp", metadata.scorecardTimestamp())
                .bind("averageIssueAgeDays", metadata.averageIssueAgeDays())
                .bind("lastFetch", metadata.lastFetch())
                .bind("status", metadata.status().name())
                .execute();
    }

    private static void replaceScorecardChecks(
            final Handle handle, final String canonicalPurl, final List<PackageHealthScorecardCheck> checks) {

        handle.createUpdate("""
                        DELETE FROM "PACKAGE_HEALTH_SCORECARD_CHECK"
                         WHERE "PURL" = :purl
                        """).bind("purl", canonicalPurl).execute();

        if (checks.isEmpty()) {
            return;
        }

        final var batch = handle.prepareBatch("""
                INSERT INTO "PACKAGE_HEALTH_SCORECARD_CHECK" (
                  "PURL"
                , "CHECK_NAME"
                , "DESCRIPTION"
                , "SCORE"
                , "REASON"
                , "DETAILS"
                , "DOCUMENTATION_URL"
                )
                VALUES (
                  :purl
                , :checkName
                , :description
                , :score
                , :reason
                , :details
                , :documentationUrl
                )
                """);

        for (final PackageHealthScorecardCheck check : checks) {
            batch.bind("purl", canonicalPurl)
                    .bind("checkName", check.name())
                    .bind("description", check.description())
                    .bind("score", check.score())
                    .bind("reason", check.reason())
                    .bindArray("details", String.class, check.details())
                    .bind("documentationUrl", check.documentationUrl())
                    .add();
        }

        batch.execute();
    }

    private static PackageHealthMetadata withScorecardChecks(
            final PackageHealthMetadata metadata, final List<PackageHealthScorecardCheck> checks) {

        return new PackageHealthMetadata(
                metadata.purl(),
                metadata.stars(),
                metadata.forks(),
                metadata.contributors(),
                metadata.commitFrequencyWeekly(),
                metadata.openIssues(),
                metadata.openPullRequests(),
                metadata.lastCommit(),
                metadata.busFactor(),
                metadata.hasReadme(),
                metadata.hasCodeOfConduct(),
                metadata.hasSecurityPolicy(),
                metadata.dependents(),
                metadata.files(),
                metadata.repositoryArchived(),
                metadata.scorecardScore(),
                metadata.scorecardReferenceVersion(),
                metadata.scorecardTimestamp(),
                metadata.averageIssueAgeDays(),
                metadata.lastFetch(),
                metadata.status(),
                checks);
    }
}
