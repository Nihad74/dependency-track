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

/// Finding or project invalidation.
public record AssessmentChange(
        Scope scope,
        UUID projectUuid,
        @Nullable UUID componentUuid,
        @Nullable UUID vulnerabilityUuid,
        Reason reason,
        List<LookupKey> lookupKeys) {

    public AssessmentChange {
        Objects.requireNonNull(scope, "scope must not be null");
        Objects.requireNonNull(projectUuid, "projectUuid must not be null");
        Objects.requireNonNull(reason, "reason must not be null");
        Objects.requireNonNull(lookupKeys, "lookupKeys must not be null");
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

    /// A change to a whole project, keyed by the project's name and version when both are known.
    public static AssessmentChange project(
            final UUID projectUuid,
            final Reason reason,
            final @Nullable String projectName,
            final @Nullable String projectVersion) {
        return new AssessmentChange(
                Scope.PROJECT, projectUuid, null, null, reason, LookupKey.listOf(projectName, projectVersion));
    }

    /// A change to one finding, keyed by its project's name and version when both are known.
    public static AssessmentChange finding(
            final UUID projectUuid,
            final UUID componentUuid,
            final UUID vulnerabilityUuid,
            final Reason reason,
            final @Nullable String projectName,
            final @Nullable String projectVersion) {
        return new AssessmentChange(
                Scope.FINDING,
                projectUuid,
                componentUuid,
                vulnerabilityUuid,
                reason,
                LookupKey.listOf(projectName, projectVersion));
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

    /// The writer that recorded the change. Stored for diagnostics only; expansion ignores it.
    public enum Reason {
        AUTHORED,
        POLICY,
        POLICY_UNASSIGNED,
        BOM_IMPORT,
        PROJECT_CREATED,
        PROJECT_UPDATED,
        COMPONENT_CHANGED,
        PROJECT_DELETED,
        PROJECT_CLONED,
        ATTRIBUTION,
        ACCESS_CHANGED
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

        /// One key when both name and version are present, otherwise none.
        public static List<LookupKey> listOf(final @Nullable String name, final @Nullable String version) {
            if (name == null || version == null || name.isBlank() || version.isBlank()) {
                return List.of();
            }
            return List.of(new LookupKey(name, version));
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
