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

import org.dependencytrack.model.Repository;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.secret.management.SecretManager;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;
import java.util.Optional;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public final class GitHubApiClientProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(GitHubApiClientProvider.class);

    private final SecretManager secretManager;

    private volatile @Nullable CachedClient cachedClient;

    public GitHubApiClientProvider(final SecretManager secretManager) {
        this.secretManager = Objects.requireNonNull(secretManager);
    }

    public Optional<GitHubApiClient> get() {
        final Optional<Repository> repository = withJdbiHandle(handle -> handle.createQuery("""
                                SELECT *
                                  FROM "REPOSITORY"
                                 WHERE "TYPE" = :type
                                   AND "ENABLED"
                                   AND "AUTHENTICATIONREQUIRED"
                                 ORDER BY "RESOLUTION_ORDER"
                                 LIMIT 1
                                """)
                .bind("type", RepositoryType.GITHUB.name())
                .mapToBean(Repository.class)
                .findOne());

        if (repository.isEmpty()) {
            LOGGER.debug("No authenticated GitHub repository is configured");
            return Optional.empty();
        }

        final String secretReference = repository.get().getPassword();

        if (secretReference == null || secretReference.isBlank()) {
            LOGGER.warn("GitHub authentication is enabled, but no token is configured");
            return Optional.empty();
        }

        final String accessToken = secretManager.getSecretValue(secretReference);

        if (accessToken == null || accessToken.isBlank()) {
            LOGGER.warn("Configured GitHub token could not be resolved");
            return Optional.empty();
        }

        return Optional.of(clientFor(accessToken));
    }

    private record CachedClient(String token, GitHubApiClient client) {}

    private GitHubApiClient clientFor(final String accessToken) {
        var current = cachedClient;
        if (current != null && current.token().equals(accessToken)) {
            return current.client();
        }

        synchronized (this) {
            current = cachedClient;
            if (current == null || !current.token().equals(accessToken)) {
                current = new CachedClient(accessToken, new GitHubApiClient(accessToken));
                cachedClient = current;
            }
            return current.client();
        }
    }
}
