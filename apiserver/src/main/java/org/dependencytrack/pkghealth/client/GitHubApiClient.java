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
import org.dependencytrack.pkghealth.model.PackageHealthMetaModel;
import org.jspecify.annotations.Nullable;

import java.io.IOException;
import java.net.http.HttpRequest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

public final class GitHubApiClient extends ApiClient {

    private static final String DEFAULT_API_BASE_URL = "https://api.github.com";
    private static final int PAGE_SIZE = 100;

    private final String apiBaseUrl;
    private final String accessToken;
    private final Clock clock;

    public GitHubApiClient(final @Nullable String accessToken) {
        super();

        if (accessToken == null || accessToken.isBlank()) {
            throw new IllegalArgumentException("accessToken must not be blank");
        }

        this.accessToken = accessToken;
        this.clock = Clock.systemUTC();
        this.apiBaseUrl = DEFAULT_API_BASE_URL;
    }

    GitHubApiClient(
            final java.net.http.HttpClient httpClient,
            final ObjectMapper objectMapper,
            final @Nullable String accessToken,
            final Clock clock,
            final String apiBaseUrl) {

        super(httpClient, objectMapper);
        this.accessToken = accessToken;
        this.clock = clock;
        this.apiBaseUrl = apiBaseUrl;
    }

    @Override
    protected void configureRequest(final HttpRequest.Builder requestBuilder) {
        requestBuilder.setHeader("Accept", "application/vnd.github+json");
        requestBuilder.setHeader("X-GitHub-Api-Version", "2022-11-28");
        requestBuilder.setHeader("Authorization", "Bearer " + accessToken);
    }

    public Optional<PackageHealthMetaModel> fetchRepositoryMetadata(final PackageURL packagePurl, final String project)
            throws IOException, InterruptedException {
        final Optional<RepositoryCoordinates> coordinates = parseProject(project);

        if (coordinates.isEmpty()) {
            return Optional.empty();
        }

        final String repositoryUrl = repositoryUrl(coordinates.get());
        final Optional<JsonNode> repositoryResponse = requestJson(repositoryUrl);

        if (repositoryResponse.isEmpty()) {
            return Optional.empty();
        }

        final JsonNode repository = repositoryResponse.get();
        final var metadata = new PackageHealthMetaModel(packagePurl);

        metadata.setRepositoryArchived(booleanOrNull(repository.get("archived")));

        final IssueStatistics issues = fetchIssueStatistics(repositoryUrl);
        metadata.setOpenIssues(issues.openIssues());
        metadata.setOpenPullRequests(issues.openPullRequests());
        metadata.setAverageIssueAgeDays(issues.averageIssueAgeDays());

        final ContributorStatistics contributors = fetchContributorStatistics(repositoryUrl);
        metadata.setContributors(contributors.count());
        metadata.setCommitFrequencyWeekly(calculateCommitFrequency(
                contributors.totalContributions(), instantOrNull(repository.get("created_at"))));
        metadata.setBusFactor(calculateBusFactor(contributors.contributions()));

        final String defaultBranch = textOrNull(repository.get("default_branch"));

        metadata.setLastCommit(fetchLastCommit(repositoryUrl, defaultBranch));
        metadata.setFiles(fetchFileCount(repositoryUrl, defaultBranch));
        metadata.setHasReadme(resourceExists(repositoryUrl + "/readme"));
        metadata.setHasCodeOfConduct(resourceExistsAtAnyPath(
                repositoryUrl, "CODE_OF_CONDUCT.md", ".github/CODE_OF_CONDUCT.md", "docs/CODE_OF_CONDUCT.md"));
        metadata.setHasSecurityPolicy(
                resourceExistsAtAnyPath(repositoryUrl, "SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"));

        return Optional.of(metadata);
    }

    private IssueStatistics fetchIssueStatistics(final String repositoryUrl) throws IOException, InterruptedException {
        final List<JsonNode> issues = fetchAllPages(repositoryUrl + "/issues?state=open");

        long openIssues = 0;
        long openPullRequests = 0;
        double totalIssueAgeDays = 0;

        final Instant now = clock.instant();

        for (final JsonNode issue : issues) {
            if (issue.hasNonNull("pull_request")) {
                openPullRequests++;
                continue;
            }

            openIssues++;

            final Instant createdAt = instantOrNull(issue.get("created_at"));
            if (createdAt != null) {
                final long ageSeconds =
                        Math.max(0, Duration.between(createdAt, now).toSeconds());
                totalIssueAgeDays += ageSeconds / 86_400.0;
            }
        }

        final float averageIssueAgeDays = openIssues == 0 ? 0 : (float) (totalIssueAgeDays / openIssues);

        return new IssueStatistics(openIssues, openPullRequests, averageIssueAgeDays);
    }

    private ContributorStatistics fetchContributorStatistics(final String repositoryUrl)
            throws IOException, InterruptedException {
        final List<JsonNode> contributors = fetchAllPages(repositoryUrl + "/contributors?anon=1");

        final List<Long> contributions = contributors.stream()
                .map(node -> longOrNull(node.get("contributions")))
                .filter(value -> value != null)
                .toList();

        return new ContributorStatistics((long) contributors.size(), contributions);
    }

    private Instant fetchLastCommit(final String repositoryUrl, final @Nullable String defaultBranch)
            throws IOException, InterruptedException {
        if (defaultBranch == null) {
            return null;
        }

        final Optional<JsonNode> response =
                requestJson(repositoryUrl + "/commits?sha=" + urlEncode(defaultBranch) + "&per_page=1");

        if (response.isEmpty() || !response.get().isArray() || response.get().size() == 0) {
            return null;
        }

        final JsonNode commit = response.get().get(0).path("commit");

        final Instant committerDate = instantOrNull(commit.path("committer").get("date"));

        return committerDate != null
                ? committerDate
                : instantOrNull(commit.path("author").get("date"));
    }

    private Long fetchFileCount(final String repositoryUrl, final @Nullable String defaultBranch)
            throws IOException, InterruptedException {
        if (defaultBranch == null) {
            return null;
        }

        final Optional<JsonNode> response =
                requestJson(repositoryUrl + "/git/trees/" + urlEncode(defaultBranch) + "?recursive=1");

        if (response.isEmpty() || response.get().path("truncated").asBoolean(false)) {
            return null;
        }

        final JsonNode tree = response.get().get("tree");
        if (tree == null || !tree.isArray()) {
            return null;
        }

        long files = 0;
        for (final JsonNode entry : tree) {
            if ("blob".equals(entry.path("type").asText())) {
                files++;
            }
        }

        return files;
    }

    private boolean resourceExistsAtAnyPath(final String repositoryUrl, final String... paths)
            throws IOException, InterruptedException {
        for (final String path : paths) {
            if (resourceExists(repositoryUrl + "/contents/" + path)) {
                return true;
            }
        }

        return false;
    }

    private boolean resourceExists(final String url) throws IOException, InterruptedException {
        return requestJson(url).isPresent();
    }

    private List<JsonNode> fetchAllPages(final String baseUrl) throws IOException, InterruptedException {
        final var results = new ArrayList<JsonNode>();
        int page = 1;

        while (true) {
            final String separator = baseUrl.contains("?") ? "&" : "?";
            final Optional<JsonNode> response =
                    requestJson(baseUrl + separator + "per_page=" + PAGE_SIZE + "&page=" + page);

            if (response.isEmpty()) {
                break;
            }

            final JsonNode values = response.get();
            if (!values.isArray()) {
                throw new IOException("Expected GitHub response to be an array");
            }

            values.forEach(results::add);

            if (values.size() < PAGE_SIZE) {
                break;
            }

            page++;
        }

        return results;
    }

    private Float calculateCommitFrequency(final long totalContributions, final @Nullable Instant repositoryCreatedAt) {
        if (repositoryCreatedAt == null) {
            return null;
        }

        final long repositoryAgeDays = Math.max(0, ChronoUnit.DAYS.between(repositoryCreatedAt, clock.instant()));
        final long repositoryAgeWeeks = Math.max(1, repositoryAgeDays / 7);

        return (float) totalContributions / repositoryAgeWeeks;
    }

    private static Integer calculateBusFactor(final List<Long> contributions) {
        final long totalContributions =
                contributions.stream().mapToLong(Long::longValue).sum();

        if (totalContributions == 0) {
            return null;
        }

        final long threshold = (totalContributions + 1) / 2;
        final List<Long> descending =
                contributions.stream().sorted(Comparator.reverseOrder()).toList();

        long accumulated = 0;
        int busFactor = 0;

        for (final long contributionCount : descending) {
            accumulated += contributionCount;
            busFactor++;

            if (accumulated >= threshold) {
                return busFactor;
            }
        }

        return null;
    }

    private static Optional<RepositoryCoordinates> parseProject(final String project) {
        if (project == null || !project.toLowerCase(Locale.ROOT).startsWith("github.com/")) {
            return Optional.empty();
        }

        String path = project.substring("github.com/".length());
        path = path.replaceFirst("/+$", "").replaceFirst("(?i)\\.git$", "");

        final String[] segments = path.split("/");
        if (segments.length != 2 || segments[0].isBlank() || segments[1].isBlank()) {
            return Optional.empty();
        }

        return Optional.of(new RepositoryCoordinates(segments[0], segments[1]));
    }

    private String repositoryUrl(final RepositoryCoordinates coordinates) {
        return "%s/repos/%s/%s"
                .formatted(apiBaseUrl, urlEncode(coordinates.owner()), urlEncode(coordinates.repository()));
    }

    private static String textOrNull(final JsonNode node) {
        return node != null && node.isTextual() ? node.textValue() : null;
    }

    private static Long longOrNull(final JsonNode node) {
        return node != null && node.isIntegralNumber() ? node.longValue() : null;
    }

    private static Boolean booleanOrNull(final JsonNode node) {
        return node != null && node.isBoolean() ? node.booleanValue() : null;
    }

    private static Instant instantOrNull(final JsonNode node) {
        final String value = textOrNull(node);
        if (value == null || value.isBlank()) {
            return null;
        }

        try {
            return Instant.parse(value);
        } catch (RuntimeException ignored) {
            return null;
        }
    }

    private record RepositoryCoordinates(String owner, String repository) {}

    private record IssueStatistics(long openIssues, long openPullRequests, float averageIssueAgeDays) {}

    private record ContributorStatistics(long count, List<Long> contributions) {

        private long totalContributions() {
            return contributions.stream().mapToLong(Long::longValue).sum();
        }
    }
}
