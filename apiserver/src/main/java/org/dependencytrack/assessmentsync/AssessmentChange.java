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
package org.dependencytrack.assessmentsync;

import org.jspecify.annotations.Nullable;

import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

/// Finding or project invalidation. Scope-key derivation is pure and does not write SQL.
public record AssessmentChange(
        Scope scope,
        UUID projectUuid,
        @Nullable UUID componentUuid,
        @Nullable UUID vulnerabilityUuid,
        String reason,
        List<LookupKey> lookupKeys) {

    public AssessmentChange {
        Objects.requireNonNull(scope, "scope must not be null");
        Objects.requireNonNull(projectUuid, "projectUuid must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
        Objects.requireNonNull(lookupKeys, "lookupKeys must not be null");
        if (reason.isBlank()) {
            throw new IllegalArgumentException("reason must not be blank");
        }
        lookupKeys = dedupe(lookupKeys);
        switch (scope) {
            case PROJECT -> {
                if (componentUuid != null || vulnerabilityUuid != null) {
                    throw new IllegalArgumentException("PROJECT scope requires null component and vulnerability UUIDs");
                }
            }
            case FINDING -> {
                if (componentUuid == null || vulnerabilityUuid == null) {
                    throw new IllegalArgumentException("FINDING scope requires component and vulnerability UUIDs");
                }
            }
        }
    }

    /// {@code project:<uuid>} or {@code finding:<project>:<component>:<vulnerability>}.
    public String scopeKey() {
        return switch (scope) {
            case PROJECT -> "project:" + projectUuid;
            case FINDING ->
                "finding:" + projectUuid + ":" + Objects.requireNonNull(componentUuid) + ":"
                        + Objects.requireNonNull(vulnerabilityUuid);
        };
    }

    public enum Scope {
        FINDING,
        PROJECT
    }

    /// Project name and version observed before or after a change.
    public record LookupKey(String name, String version) {

        public LookupKey {
            Objects.requireNonNull(name, "name must not be null");
            Objects.requireNonNull(version, "version must not be null");
            if (name.isBlank() || version.isBlank()) {
                throw new IllegalArgumentException("lookup key name and version must not be blank");
            }
        }
    }

    private static List<LookupKey> dedupe(final List<LookupKey> keys) {
        final var seen = new LinkedHashSet<LookupKey>();
        for (final LookupKey key : keys) {
            seen.add(Objects.requireNonNull(key, "lookup key must not be null"));
        }
        return List.copyOf(seen);
    }
}
