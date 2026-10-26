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

import org.dependencytrack.assessmentsync.AssessmentChange.LookupKey;
import org.dependencytrack.assessmentsync.AssessmentChange.Scope;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/// Records project and finding invalidations on the caller's handle.
///
/// Embedding replacement and outbox inserts run only while the mode records.
/// The caller still locks the project before mutating it.
public final class AssessmentStructureCapture {

    public static final String BOM_IMPORT = "BOM_IMPORT";
    public static final String PROJECT_CREATED = "PROJECT_CREATED";
    public static final String PROJECT_UPDATED = "PROJECT_UPDATED";
    public static final String COMPONENT_CHANGED = "COMPONENT_CHANGED";
    public static final String PROJECT_DELETED = "PROJECT_DELETED";
    public static final String PROJECT_CLONED = "PROJECT_CLONED";
    public static final String ATTRIBUTION = "ATTRIBUTION";

    private AssessmentStructureCapture() {}

    public static List<LookupKey> keys(final @Nullable String name, final @Nullable String version) {
        return AssessmentChangeRecorder.lookupKeys(name, version);
    }

    public static List<LookupKey> keys(
            final @Nullable String oldName,
            final @Nullable String oldVersion,
            final @Nullable String newName,
            final @Nullable String newVersion) {
        final var combined = new ArrayList<LookupKey>(2);
        combined.addAll(keys(oldName, oldVersion));
        combined.addAll(keys(newName, newVersion));
        return combined;
    }

    /// One project invalidation. Does not rebuild embeddings.
    public static void recordProject(
            final Handle handle, final UUID projectUuid, final String reason, final List<LookupKey> lookupKeys) {
        requireNonNull(handle, "handle must not be null");
        requireNonNull(projectUuid, "projectUuid must not be null");
        requireNonNull(reason, "reason must not be null");
        requireNonNull(lookupKeys, "lookupKeys must not be null");
        if (!AssessmentSyncMode.current().recordsOutbox()) {
            return;
        }
        new AssessmentChangeRecorder(handle)
                .record(new AssessmentChange(Scope.PROJECT, projectUuid, null, null, reason, lookupKeys));
    }

    /// Replaces the project's embedding index and records one project invalidation.
    public static void rebuildAndRecord(
            final Handle handle,
            final UUID projectUuid,
            final String reason,
            final @Nullable String oldName,
            final @Nullable String oldVersion,
            final @Nullable String newName,
            final @Nullable String newVersion) {
        requireNonNull(handle, "handle must not be null");
        if (!AssessmentSyncMode.current().recordsOutbox()) {
            return;
        }
        new AssessmentEmbeddingIndexer(handle).rebuild(projectUuid);
        recordProject(handle, projectUuid, reason, keys(oldName, oldVersion, newName, newVersion));
    }

    public static void recordProjects(final Handle handle, final Collection<AssessmentChange> changes) {
        requireNonNull(handle, "handle must not be null");
        requireNonNull(changes, "changes must not be null");
        if (changes.isEmpty() || !AssessmentSyncMode.current().recordsOutbox()) {
            return;
        }
        new AssessmentChangeRecorder(handle).recordAll(changes);
    }

    public static void recordFindings(final Handle handle, final Collection<AssessmentChange> changes) {
        recordProjects(handle, changes);
    }
}
