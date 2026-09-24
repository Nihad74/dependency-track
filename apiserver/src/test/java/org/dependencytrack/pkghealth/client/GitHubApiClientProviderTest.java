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

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.model.RepositoryType;
import org.dependencytrack.secret.management.SecretManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class GitHubApiClientProviderTest extends PersistenceCapableTest {

    private SecretManager secretManager;
    private GitHubApiClientProvider provider;

    @BeforeEach
    void setUp() {
        secretManager = mock(SecretManager.class);
        provider = new GitHubApiClientProvider(secretManager);
    }

    @Test
    void shouldReturnEmptyWhenNoGitHubRepositoryIsConfigured() {
        final var result = provider.get();

        assertThat(result).isEmpty();
        verifyNoInteractions(secretManager);
    }

    @Test
    void shouldReturnEmptyWhenGitHubRepositoryIsDisabled() {
        createGitHubRepository(false, true, "github-token-reference");

        final var result = provider.get();

        assertThat(result).isEmpty();
        verifyNoInteractions(secretManager);
    }

    @Test
    void shouldReturnEmptyWhenAuthenticationIsDisabled() {
        createGitHubRepository(true, false, null);

        final var result = provider.get();

        assertThat(result).isEmpty();
        verifyNoInteractions(secretManager);
    }

    @Test
    void shouldReturnEmptyWhenSecretCannotBeResolved() {
        createGitHubRepository(true, true, "github-token-reference");

        when(secretManager.getSecretValue("github-token-reference")).thenReturn(null);

        final var result = provider.get();

        assertThat(result).isEmpty();

        verify(secretManager).getSecretValue("github-token-reference");
    }

    @Test
    void shouldCreateClientWithResolvedToken() {
        createGitHubRepository(true, true, "github-token-reference");

        when(secretManager.getSecretValue("github-token-reference")).thenReturn("resolved-github-token");

        final var result = provider.get();

        assertThat(result).isPresent();
        assertThat(result.orElseThrow()).isInstanceOf(GitHubApiClient.class);

        verify(secretManager).getSecretValue("github-token-reference");
    }

    private void createGitHubRepository(
            final boolean enabled, final boolean authenticationRequired, final String password) {
        qm.createRepository(
                RepositoryType.GITHUB,
                "github",
                "https://github.com",
                enabled,
                false,
                authenticationRequired,
                null,
                password);
    }
}
