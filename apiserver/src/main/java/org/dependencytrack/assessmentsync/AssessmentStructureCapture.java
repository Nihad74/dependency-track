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
import org.dependencytrack.assessmentsync.AssessmentChange.Reason;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.SqlStatements;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.UUID;

/// Records project and finding invalidations on the caller's handle.
///
/// Embedding replacement and outbox inserts run only while the mode records.
/// The caller still locks the project before mutating it.
public final class AssessmentStructureCapture {

    private AssessmentStructureCapture() {}

    public static List<LookupKey> keys(
            final @Nullable String oldName,
            final @Nullable String oldVersion,
            final @Nullable String newName,
            final @Nullable String newVersion) {
        final var combined = new ArrayList<LookupKey>(2);
        combined.addAll(LookupKey.listOf(oldName, oldVersion));
        combined.addAll(LookupKey.listOf(newName, newVersion));
        return combined;
    }

    /// One project invalidation. Does not rebuild embeddings.
    public static void recordProject(
            final Handle handle, final UUID projectUuid, final Reason reason, final List<LookupKey> lookupKeys) {
        new AssessmentChangeRecorder(handle)
                .record(new AssessmentChange(
                        AssessmentChange.Scope.PROJECT, projectUuid, null, null, reason, lookupKeys));
    }

    /// Replaces the project's embedding index and records one project invalidation.
    public static void rebuildAndRecord(
            final Handle handle, final UUID projectUuid, final Reason reason, final List<LookupKey> lookupKeys) {
        if (!AssessmentSyncMode.current().recordsOutbox()) {
            return;
        }
        new AssessmentEmbeddingIndexer(handle).rebuild(projectUuid);
        recordProject(handle, projectUuid, reason, lookupKeys);
    }

    /// Records one finding change for each component and vulnerability pair of the project whose attribution
    /// was added or removed. Pairs whose component or vulnerability is gone are skipped.
    public static void recordAttributionChanges(
            final Handle handle, final UUID projectUuid, final Collection<FindingRef> findings) {
        if (findings.isEmpty() || !AssessmentSyncMode.current().recordsOutbox()) {
            return;
        }
        final var componentIds = new long[findings.size()];
        final var vulnerabilityIds = new long[findings.size()];
        int i = 0;
        for (final FindingRef finding : findings) {
            componentIds[i] = finding.componentId();
            vulnerabilityIds[i] = finding.vulnerabilityId();
            i++;
        }
        final List<AssessmentChange> changes = handle.createQuery(/* language=SQL */ """
                        SELECT DISTINCT p."NAME"
                             , p."VERSION"
                             , c."UUID" AS component_uuid
                             , v."UUID" AS vulnerability_uuid
                          FROM UNNEST(:componentIds, :vulnerabilityIds) AS t(component_id, vulnerability_id)
                         INNER JOIN "COMPONENT" AS c
                            ON c."ID" = t.component_id
                         INNER JOIN "PROJECT" AS p
                            ON p."ID" = c."PROJECT_ID"
                         INNER JOIN "VULNERABILITY" AS v
                            ON v."ID" = t.vulnerability_id
                         WHERE p."UUID" = :projectUuid
                        """)
                .bind("componentIds", componentIds)
                .bind("vulnerabilityIds", vulnerabilityIds)
                .bind("projectUuid", projectUuid)
                .map((rs, ctx) -> AssessmentChange.finding(
                        projectUuid,
                        rs.getObject("component_uuid", UUID.class),
                        rs.getObject("vulnerability_uuid", UUID.class),
                        Reason.ATTRIBUTION,
                        rs.getString("NAME"),
                        rs.getString("VERSION")))
                .list();
        new AssessmentChangeRecorder(handle).recordAll(changes);
    }

    /// Records the projects and all their descendants, because access through a parent counts.
    ///
    /// Source eligibility depends on team access (ADR 044). Each event reaches the project as a target,
    /// the targets that embed it, and the targets whose marker names it, so all affected pairs re-index.
    public static void recordAccessChange(final Handle handle, final Collection<UUID> projectUuids) {
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
                .map((rs, ctx) -> AssessmentChange.project(
                        rs.getObject("UUID", UUID.class),
                        Reason.ACCESS_CHANGED,
                        rs.getString("NAME"),
                        rs.getString("VERSION")))
                .list();
        new AssessmentChangeRecorder(handle).recordAll(changes);
    }

    /// Records every project that a team can access, before the team is deleted.
    public static void recordTeamAccessRemoved(final Handle handle, final long teamId) {
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
                .map((rs, ctx) ->
                        AssessmentChange.project(rs.getObject("UUID", UUID.class), Reason.ACCESS_CHANGED, null, null))
                .list();
        new AssessmentChangeRecorder(handle).recordAll(changes);
    }

    /// A finding by database ids.
    public record FindingRef(long componentId, long vulnerabilityId) {}
}
