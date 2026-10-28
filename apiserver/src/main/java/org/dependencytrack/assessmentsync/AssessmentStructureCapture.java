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
import org.jdbi.v3.core.statement.SqlStatements;
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
    public static final String ACCESS_CHANGED = "ACCESS_CHANGED";

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

    /// Records the projects and all their descendants, because access through a parent counts.
    ///
    /// Source eligibility depends on team access (ADR 044). Each event reaches the project as a target,
    /// the targets that embed it, and the targets whose marker names it, so all affected pairs re-index.
    public static void recordAccessChange(final Handle handle, final Collection<UUID> projectUuids) {
        requireNonNull(handle, "handle must not be null");
        requireNonNull(projectUuids, "projectUuids must not be null");
        if (projectUuids.isEmpty() || !AssessmentSyncMode.current().recordsOutbox()) {
            return;
        }
        final List<AssessmentChange> changes = handle.createQuery(/* language=SQL */ """
                        SELECT DISTINCT project."UUID"
                             , project."NAME"
                             , project."VERSION"
                          FROM "PROJECT" AS root
                         INNER JOIN "PROJECT_HIERARCHY" AS hierarchy
                            ON hierarchy."PARENT_PROJECT_ID" = root."ID"
                         INNER JOIN "PROJECT" AS project
                            ON project."ID" = hierarchy."CHILD_PROJECT_ID"
                         WHERE root."UUID" = ANY(:projectUuids)
                        """)
                .bindArray("projectUuids", UUID.class, projectUuids.toArray(UUID[]::new))
                .map((rs, ctx) ->
                        accessChange(rs.getObject("UUID", UUID.class), rs.getString("NAME"), rs.getString("VERSION")))
                .list();
        new AssessmentChangeRecorder(handle).recordAll(changes);
    }

    /// Records every project that a team can access, before the team is deleted.
    public static void recordTeamAccessRemoved(final Handle handle, final long teamId) {
        requireNonNull(handle, "handle must not be null");
        if (!AssessmentSyncMode.current().recordsOutbox()) {
            return;
        }
        final List<UUID> projectUuids = handle.createQuery(/* language=SQL */ """
                        SELECT project."UUID"
                          FROM "PROJECT_ACCESS_TEAMS" AS access
                         INNER JOIN "PROJECT" AS project
                            ON project."ID" = access."PROJECT_ID"
                         WHERE access."TEAM_ID" = :teamId
                        """)
                .bind("teamId", teamId)
                .mapTo(UUID.class)
                .list();
        recordAccessChange(handle, projectUuids);
    }

    /// Records every target with a marker after portfolio access control is turned on or off.
    ///
    /// Every source-target pair has a target with an embedding row, so target events cover all pairs.
    public static void recordAccessControlToggled(final Handle handle) {
        requireNonNull(handle, "handle must not be null");
        if (!AssessmentSyncMode.current().recordsOutbox()) {
            return;
        }
        final List<AssessmentChange> changes = handle.createQuery(/* language=SQL */ """
                        SELECT DISTINCT project."UUID"
                          FROM "ASSESSMENT_EMBEDDING" AS embedding
                         INNER JOIN "PROJECT" AS project
                            ON project."ID" = embedding."TARGET_PROJECT_ID"
                        """)
                // Request-scoped handles bind pagination to every statement. This query declares no
                // parameters, and JDBI rejects unused bindings only in that case.
                .configure(SqlStatements.class, config -> config.setUnusedBindingAllowed(true))
                .map((rs, ctx) -> new AssessmentChange(
                        Scope.PROJECT, rs.getObject("UUID", UUID.class), null, null, ACCESS_CHANGED, List.of()))
                .list();
        new AssessmentChangeRecorder(handle).recordAll(changes);
    }

    private static AssessmentChange accessChange(
            final UUID projectUuid, final @Nullable String name, final @Nullable String version) {
        return new AssessmentChange(Scope.PROJECT, projectUuid, null, null, ACCESS_CHANGED, keys(name, version));
    }
}
