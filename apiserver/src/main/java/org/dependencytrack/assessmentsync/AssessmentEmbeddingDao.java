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

import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/// Target marker index and descendant membership. Source projects are not foreign keys.
public final class AssessmentEmbeddingDao {

    private final Handle handle;

    public AssessmentEmbeddingDao(final Handle handle) {
        this.handle = requireNonNull(handle, "handle must not be null");
    }

    /// Replaces markers and descendants for one target project. A null source UUID is kept.
    public void replaceMembership(final long targetProjectId, final Collection<MarkerMembership> membership) {
        if (targetProjectId <= 0) {
            throw new IllegalArgumentException("targetProjectId must be positive");
        }
        requireNonNull(membership, "membership must not be null");
        requireTransaction();

        final var markers = new LinkedHashSet<Long>();
        for (final MarkerMembership marker : membership) {
            requireNonNull(marker, "marker must not be null");
            if (!markers.add(marker.markerComponentId())) {
                throw new IllegalArgumentException("Duplicate marker component " + marker.markerComponentId());
            }
        }

        handle.createUpdate(/* language=SQL */ """
                        DELETE FROM "ASSESSMENT_EMBEDDING"
                         WHERE "TARGET_PROJECT_ID" = :targetProjectId
                        """)
                .bind("targetProjectId", targetProjectId)
                .execute();
        if (membership.isEmpty()) {
            return;
        }

        final var markerIds = new long[membership.size()];
        final var names = new String[membership.size()];
        final var versions = new String[membership.size()];
        final var sourceUuids = new @Nullable UUID[membership.size()];
        int markerIndex = 0;
        int memberCount = 0;
        for (final MarkerMembership marker : membership) {
            markerIds[markerIndex] = marker.markerComponentId();
            names[markerIndex] = marker.markerName();
            versions[markerIndex] = marker.markerVersion();
            sourceUuids[markerIndex] = marker.sourceProjectUuid();
            memberCount += dedupeMembers(marker).size();
            markerIndex++;
        }
        handle.createUpdate(/* language=SQL */ """
                        INSERT INTO "ASSESSMENT_EMBEDDING" (
                          "TARGET_PROJECT_ID"
                        , "MARKER_COMPONENT_ID"
                        , "MARKER_NAME"
                        , "MARKER_VERSION"
                        , "SOURCE_PROJECT_UUID"
                        )
                        SELECT :targetProjectId
                             , t.marker_component_id
                             , t.marker_name
                             , t.marker_version
                             , t.source_project_uuid
                          FROM UNNEST(
                                 :markerIds
                               , :names
                               , :versions
                               , :sourceUuids
                               ) AS t(
                                 marker_component_id
                               , marker_name
                               , marker_version
                               , source_project_uuid
                               )
                        """)
                .bind("targetProjectId", targetProjectId)
                .bind("markerIds", markerIds)
                .bind("names", names)
                .bind("versions", versions)
                .bind("sourceUuids", sourceUuids)
                .execute();

        if (memberCount == 0) {
            return;
        }
        final var memberMarkerIds = new long[memberCount];
        final var memberComponentIds = new long[memberCount];
        int memberIndex = 0;
        for (final MarkerMembership marker : membership) {
            for (final long componentId : dedupeMembers(marker)) {
                memberMarkerIds[memberIndex] = marker.markerComponentId();
                memberComponentIds[memberIndex] = componentId;
                memberIndex++;
            }
        }
        handle.createUpdate(/* language=SQL */ """
                        INSERT INTO "ASSESSMENT_EMBEDDING_MEMBER" (
                          "TARGET_PROJECT_ID"
                        , "MARKER_COMPONENT_ID"
                        , "COMPONENT_ID"
                        )
                        SELECT :targetProjectId
                             , t.marker_component_id
                             , t.component_id
                          FROM UNNEST(:memberMarkerIds, :memberComponentIds)
                            AS t(marker_component_id, component_id)
                        """)
                .bind("targetProjectId", targetProjectId)
                .bind("memberMarkerIds", memberMarkerIds)
                .bind("memberComponentIds", memberComponentIds)
                .execute();
    }

    public List<Embedding> findByMarkerNameAndVersion(final String name, final String version) {
        requireNonNull(name, "name must not be null");
        requireNonNull(version, "version must not be null");
        return handle.createQuery(/* language=SQL */ """
                        SELECT "TARGET_PROJECT_ID"
                             , "MARKER_COMPONENT_ID"
                             , "MARKER_NAME"
                             , "MARKER_VERSION"
                             , "SOURCE_PROJECT_UUID"
                          FROM "ASSESSMENT_EMBEDDING"
                         WHERE "MARKER_NAME" = :name
                           AND "MARKER_VERSION" = :version
                         ORDER BY "TARGET_PROJECT_ID", "MARKER_COMPONENT_ID"
                        """)
                .bind("name", name)
                .bind("version", version)
                .map((rs, ctx) -> new Embedding(
                        rs.getLong("TARGET_PROJECT_ID"),
                        rs.getLong("MARKER_COMPONENT_ID"),
                        rs.getString("MARKER_NAME"),
                        rs.getString("MARKER_VERSION"),
                        rs.getObject("SOURCE_PROJECT_UUID", UUID.class)))
                .list();
    }

    public List<Embedding> findBySourceProject(final UUID sourceProjectUuid) {
        requireNonNull(sourceProjectUuid, "sourceProjectUuid must not be null");
        return handle.createQuery(/* language=SQL */ """
                        SELECT "TARGET_PROJECT_ID"
                             , "MARKER_COMPONENT_ID"
                             , "MARKER_NAME"
                             , "MARKER_VERSION"
                             , "SOURCE_PROJECT_UUID"
                          FROM "ASSESSMENT_EMBEDDING"
                         WHERE "SOURCE_PROJECT_UUID" = :sourceProjectUuid
                         ORDER BY "TARGET_PROJECT_ID", "MARKER_COMPONENT_ID"
                        """)
                .bind("sourceProjectUuid", sourceProjectUuid)
                .map((rs, ctx) -> new Embedding(
                        rs.getLong("TARGET_PROJECT_ID"),
                        rs.getLong("MARKER_COMPONENT_ID"),
                        rs.getString("MARKER_NAME"),
                        rs.getString("MARKER_VERSION"),
                        rs.getObject("SOURCE_PROJECT_UUID", UUID.class)))
                .list();
    }

    public List<Membership> findMembership(final long targetProjectId, final long componentId) {
        if (targetProjectId <= 0 || componentId <= 0) {
            throw new IllegalArgumentException("targetProjectId and componentId must be positive");
        }
        return handle.createQuery(/* language=SQL */ """
                        SELECT "TARGET_PROJECT_ID"
                             , "MARKER_COMPONENT_ID"
                             , "COMPONENT_ID"
                          FROM "ASSESSMENT_EMBEDDING_MEMBER"
                         WHERE "TARGET_PROJECT_ID" = :targetProjectId
                           AND "COMPONENT_ID" = :componentId
                         ORDER BY "MARKER_COMPONENT_ID"
                        """)
                .bind("targetProjectId", targetProjectId)
                .bind("componentId", componentId)
                .map((rs, ctx) -> new Membership(
                        rs.getLong("TARGET_PROJECT_ID"), rs.getLong("MARKER_COMPONENT_ID"), rs.getLong("COMPONENT_ID")))
                .list();
    }

    private static LinkedHashSet<Long> dedupeMembers(final MarkerMembership marker) {
        final var componentIds = new LinkedHashSet<Long>();
        for (final long componentId : marker.componentIds()) {
            if (componentId <= 0) {
                throw new IllegalArgumentException("componentId must be positive");
            }
            componentIds.add(componentId);
        }
        return componentIds;
    }

    private void requireTransaction() {
        if (!handle.isInTransaction()) {
            throw new IllegalStateException("Embedding replacement requires an active transaction");
        }
    }

    /// One marker row. {@code sourceProjectUuid} is null when the source project is unresolved.
    public record Embedding(
            long targetProjectId,
            long markerComponentId,
            String markerName,
            String markerVersion,
            @Nullable UUID sourceProjectUuid) {

        public Embedding {
            requireNonNull(markerName, "markerName must not be null");
            requireNonNull(markerVersion, "markerVersion must not be null");
        }
    }

    /// One descendant stored under a marker.
    public record Membership(long targetProjectId, long markerComponentId, long componentId) {}

    /// Desired marker plus its descendant component ids.
    public record MarkerMembership(
            long markerComponentId,
            String markerName,
            String markerVersion,
            @Nullable UUID sourceProjectUuid,
            List<Long> componentIds) {

        // Explicit canonical constructor: NullAway does not carry the component's @Nullable
        // onto the parameters of a compact constructor.
        public MarkerMembership(
                final long markerComponentId,
                final String markerName,
                final String markerVersion,
                final @Nullable UUID sourceProjectUuid,
                final List<Long> componentIds) {
            if (markerComponentId <= 0) {
                throw new IllegalArgumentException("markerComponentId must be positive");
            }
            requireNonNull(markerName, "markerName must not be null");
            requireNonNull(markerVersion, "markerVersion must not be null");
            requireNonNull(componentIds, "componentIds must not be null");
            if (markerName.isBlank() || markerVersion.isBlank()) {
                throw new IllegalArgumentException("marker name and version must not be blank");
            }
            this.markerComponentId = markerComponentId;
            this.markerName = markerName;
            this.markerVersion = markerVersion;
            this.sourceProjectUuid = sourceProjectUuid;
            this.componentIds = List.copyOf(componentIds);
        }
    }
}
