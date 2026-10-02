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
package org.dependencytrack.pkghealth.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.packageurl.PackageURL;
import org.dependencytrack.model.PackageHealthScorecardCheck;
import org.dependencytrack.pkghealth.model.AnalyzedPackageHealth;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.StreamSupport;

public final class DepsDevApiClient extends ApiClient {

    private static final String DEFAULT_API_BASE_URL = "https://api.deps.dev";
    private static final String DEFAULT_WEBSITE_BASE_URL = "https://deps.dev";

    private final String apiBaseUrl;
    private final String websiteBaseUrl;

    public DepsDevApiClient() {
        super();
        this.apiBaseUrl = DEFAULT_API_BASE_URL;
        this.websiteBaseUrl = DEFAULT_WEBSITE_BASE_URL;
    }

    DepsDevApiClient(
            final java.net.http.HttpClient httpClient, final ObjectMapper objectMapper, final String apiBaseUrl) {
        this(httpClient, objectMapper, apiBaseUrl, apiBaseUrl);
    }

    DepsDevApiClient(
            final java.net.http.HttpClient httpClient,
            final ObjectMapper objectMapper,
            final String apiBaseUrl,
            final String websiteBaseUrl) {
        super(httpClient, objectMapper);
        this.apiBaseUrl = apiBaseUrl;
        this.websiteBaseUrl = websiteBaseUrl;
    }

    /**
     * Public deps.dev page for a package. {@code system} is the deps.dev system name, such as {@code NPM}.
     */
    public @Nullable String packagePageUrl(final @Nullable String system, final @Nullable String name) {
        if (system == null || system.isBlank() || name == null || name.isBlank()) {
            return null;
        }

        return "%s/%s/%s".formatted(websiteBaseUrl, system.toLowerCase(Locale.ROOT), urlEncode(name));
    }

    public Optional<String> fetchLatestVersion(final String system, final String name)
            throws IOException, InterruptedException {
        if (system == null || name == null) {
            return Optional.empty();
        }

        final String url = "%s/v3/systems/%s/packages/%s".formatted(apiBaseUrl, urlEncode(system), urlEncode(name));

        return requestParseJsonForResult(url, root -> {
            final JsonNode versions = root.get("versions");
            if (versions == null || !versions.isArray()) {
                return Optional.empty();
            }

            return StreamSupport.stream(versions.spliterator(), false)
                    .filter(node -> node.path("isDefault").asBoolean(false))
                    .map(node -> textOrNull(node.path("versionKey").get("version")))
                    .filter(Objects::nonNull)
                    .findFirst();
        });
    }

    public Optional<Long> fetchDependents(final String system, final String name, final String version)
            throws IOException, InterruptedException {
        if (system == null || name == null || version == null) {
            return Optional.empty();
        }

        final String url = "%s/v3alpha/systems/%s/packages/%s/versions/%s:dependents"
                .formatted(apiBaseUrl, urlEncode(system), urlEncode(name), urlEncode(version));

        return requestParseJsonForResult(url, root -> Optional.ofNullable(longOrNull(root.get("dependentCount"))));
    }

    public Optional<String> fetchSourceRepository(final String system, final String name, final String version)
            throws IOException, InterruptedException {
        if (system == null || name == null || version == null) {
            return Optional.empty();
        }

        final String url = "%s/v3/systems/%s/packages/%s/versions/%s"
                .formatted(apiBaseUrl, urlEncode(system), urlEncode(name), urlEncode(version));

        return requestParseJsonForResult(url, root -> {
            final JsonNode relatedProjects = root.get("relatedProjects");
            if (relatedProjects == null || !relatedProjects.isArray()) {
                return Optional.empty();
            }

            return StreamSupport.stream(relatedProjects.spliterator(), false)
                    .filter(node ->
                            "SOURCE_REPO".equals(node.path("relationType").asText()))
                    .map(node -> textOrNull(node.path("projectKey").get("id")))
                    .filter(Objects::nonNull)
                    .findFirst();
        });
    }

    public Optional<AnalyzedPackageHealth> fetchProjectMetadata(final PackageURL packagePurl, final String project)
            throws IOException, InterruptedException {
        if (packagePurl == null || project == null) {
            return Optional.empty();
        }

        final String url = "%s/v3/projects/%s".formatted(apiBaseUrl, urlEncode(project));

        return requestParseJsonForResult(url, root -> {
            final var health = new AnalyzedPackageHealth(packagePurl);

            health.setStars(longOrNull(root.get("starsCount")));
            health.setForks(longOrNull(root.get("forksCount")));
            health.setOpenIssues(longOrNull(root.get("openIssuesCount")));

            final JsonNode scorecard = root.get("scorecard");
            if (scorecard == null || !scorecard.isObject()) {
                return Optional.of(health);
            }

            health.setScorecardScore(floatOrNull(scorecard.get("overallScore")));
            health.setScorecardReferenceVersion(
                    textOrNull(scorecard.path("scorecard").get("version")));
            health.setScorecardTimestamp(instantOrNull(scorecard.get("date")));
            health.setScorecardChecks(mapScorecardChecks(packagePurl, scorecard));

            return Optional.of(health);
        });
    }

    private static List<PackageHealthScorecardCheck> mapScorecardChecks(
            final PackageURL packagePurl, final JsonNode scorecard) {
        final JsonNode checks = scorecard.get("checks");
        if (checks == null || !checks.isArray()) {
            return List.of();
        }

        return StreamSupport.stream(checks.spliterator(), false)
                .map(node -> mapScorecardCheck(packagePurl, node))
                .filter(Objects::nonNull)
                .toList();
    }

    private static @Nullable PackageHealthScorecardCheck mapScorecardCheck(
            final PackageURL packagePurl, final JsonNode node) {
        final String name = textOrNull(node.get("name"));
        if (name == null || name.isBlank()) {
            return null;
        }

        final JsonNode documentation = node.get("documentation");

        final List<String> details = node.path("details").isArray()
                ? StreamSupport.stream(node.path("details").spliterator(), false)
                        .map(JsonNode::asText)
                        .toList()
                : List.of();

        return new PackageHealthScorecardCheck(
                packagePurl,
                name,
                documentation != null ? textOrNull(documentation.get("shortDescription")) : null,
                floatOrNull(node.get("score")),
                textOrNull(node.get("reason")),
                details,
                documentation != null ? textOrNull(documentation.get("url")) : null);
    }

    private static @Nullable String textOrNull(final @Nullable JsonNode node) {
        return node != null && node.isTextual() ? node.textValue() : null;
    }

    private static @Nullable Long longOrNull(final @Nullable JsonNode node) {
        return node != null && node.isIntegralNumber() ? node.longValue() : null;
    }

    private static @Nullable Float floatOrNull(final @Nullable JsonNode node) {
        return node != null && node.isNumber() ? node.floatValue() : null;
    }

    private static @Nullable Instant instantOrNull(final @Nullable JsonNode node) {
        final String value = textOrNull(node);
        return value != null && !value.isBlank() ? Instant.parse(value) : null;
    }
}
