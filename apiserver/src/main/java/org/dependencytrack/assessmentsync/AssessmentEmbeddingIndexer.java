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

import com.fasterxml.jackson.databind.JsonNode;
import org.dependencytrack.assessmentsync.AssessmentEmbeddingDao.MarkerMembership;
import org.dependencytrack.assessmentsync.AssessmentGraph.Edge;
import org.dependencytrack.assessmentsync.AssessmentGraph.Graph;
import org.dependencytrack.assessmentsync.AssessmentGraph.Node;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.model.Classifier;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/// Rebuilds one target project's marker index from the persisted dependency graph.
///
/// Source projects are resolved by exact, case-sensitive name and version.
/// The target itself, inactive projects, and collection projects are not sources.
/// Organizational parent projects are not consulted. Services are not members.
public final class AssessmentEmbeddingIndexer {

    private final Handle handle;

    public AssessmentEmbeddingIndexer(final Handle handle) {
        this.handle = requireNonNull(handle, "handle must not be null");
    }

    /// Replaces embeddings for {@code projectUuid}. A missing project is a no-op.
    public void rebuild(final UUID projectUuid) {
        final LoadedGraph loaded = loadGraph(projectUuid);
        if (loaded == null) {
            return;
        }
        new AssessmentEmbeddingDao(handle).replaceMembership(loaded.projectId(), loaded.membership());
    }

    /// Rebuilds from persisted dependency edges when a reachable marker has no index row.
    ///
    /// An empty index is not a reason to skip inheritance. A graph with no markers is left untouched.
    public void ensureMarkersPresent(final UUID projectUuid) {
        final LoadedGraph loaded = loadGraph(projectUuid);
        if (loaded == null || loaded.membership().isEmpty()) {
            return;
        }
        final Set<Long> indexed = indexedMarkerIds(loaded.projectId());
        for (final MarkerMembership marker : loaded.membership()) {
            if (!indexed.contains(marker.markerComponentId())) {
                new AssessmentEmbeddingDao(handle).replaceMembership(loaded.projectId(), loaded.membership());
                return;
            }
        }
    }

    private @Nullable LoadedGraph loadGraph(final UUID projectUuid) {
        requireNonNull(projectUuid, "projectUuid must not be null");
        if (!handle.isInTransaction()) {
            throw new IllegalStateException("Embedding rebuild requires an active transaction");
        }

        final ProjectRow project = handle.createQuery(/* language=SQL */ """
                        SELECT "ID"
                             , "UUID"
                             , "DIRECT_DEPENDENCIES"
                          FROM "PROJECT"
                         WHERE "UUID" = :projectUuid
                        """)
                .bind("projectUuid", projectUuid)
                .map((rs, ctx) -> new ProjectRow(
                        rs.getLong("ID"), rs.getObject("UUID", UUID.class), rs.getString("DIRECT_DEPENDENCIES")))
                .findOne()
                .orElse(null);
        if (project == null || project.uuid() == null) {
            return null;
        }

        final List<ComponentRow> components = handle.createQuery(/* language=SQL */ """
                        SELECT "ID"
                             , "UUID"
                             , "NAME"
                             , "VERSION"
                             , "CLASSIFIER"
                             , "DIRECT_DEPENDENCIES"
                          FROM "COMPONENT"
                         WHERE "PROJECT_ID" = :projectId
                         ORDER BY "ID"
                        """)
                .bind("projectId", project.id())
                .map((rs, ctx) -> new ComponentRow(
                        rs.getLong("ID"),
                        rs.getObject("UUID", UUID.class),
                        rs.getString("NAME"),
                        rs.getString("VERSION"),
                        rs.getString("CLASSIFIER"),
                        rs.getString("DIRECT_DEPENDENCIES")))
                .list();

        final var nodes = new LinkedHashMap<Long, ComponentRow>();
        final var idByUuid = new HashMap<UUID, Long>();
        for (final ComponentRow component : components) {
            if (component.uuid() == null || component.id() <= 0) {
                continue;
            }
            nodes.put(component.id(), component);
            idByUuid.put(component.uuid(), component.id());
        }

        final var graphNodes = new HashMap<Long, Node>(nodes.size());
        final var edges = new ArrayList<Edge>();
        for (final ComponentRow component : nodes.values()) {
            graphNodes.put(component.id(), new Node(component.id(), project.uuid(), false));
            for (final UUID dependencyUuid : dependencyUuids(component.directDependencies())) {
                final Long childId = idByUuid.get(dependencyUuid);
                if (childId != null) {
                    edges.add(new Edge(project.uuid(), component.id(), childId));
                }
            }
        }
        final var graph = new Graph(project.uuid(), graphNodes, edges);

        final Set<Long> reachable = reachableComponentIds(project, idByUuid, nodes);
        final var markers = new ArrayList<ComponentRow>();
        for (final long componentId : reachable) {
            final ComponentRow component = nodes.get(componentId);
            if (component != null && isMarker(component)) {
                markers.add(component);
            }
        }

        if (markers.isEmpty()) {
            return new LoadedGraph(project.id(), List.of());
        }

        final Map<NameVersion, UUID> sourceByIdentity = resolveSources(project.uuid(), markers);
        final var membership = new ArrayList<MarkerMembership>(markers.size());
        for (final ComponentRow marker : markers) {
            final String markerName = requireNonNull(marker.name());
            final String markerVersion = requireNonNull(marker.version());
            final Set<Long> descendants = AssessmentGraph.descendants(graph, marker.id());
            membership.add(new MarkerMembership(
                    marker.id(),
                    markerName,
                    markerVersion,
                    sourceByIdentity.get(new NameVersion(markerName, markerVersion)),
                    List.copyOf(descendants)));
        }
        return new LoadedGraph(project.id(), membership);
    }

    private Set<Long> indexedMarkerIds(final long projectId) {
        return new LinkedHashSet<>(handle.createQuery(/* language=SQL */ """
                        SELECT "MARKER_COMPONENT_ID"
                          FROM "ASSESSMENT_EMBEDDING"
                         WHERE "TARGET_PROJECT_ID" = :projectId
                        """)
                .bind("projectId", projectId)
                .mapTo(long.class)
                .list());
    }

    private static boolean isMarker(final ComponentRow component) {
        return Classifier.OPERATING_SYSTEM.name().equals(component.classifier())
                && component.name() != null
                && component.version() != null
                && !component.name().isBlank()
                && !component.version().isBlank();
    }

    private static Set<Long> reachableComponentIds(
            final ProjectRow project, final Map<UUID, Long> idByUuid, final Map<Long, ComponentRow> nodes) {
        final var reachable = new LinkedHashSet<Long>();
        final var pending = new ArrayDeque<Long>();
        for (final UUID rootUuid : dependencyUuids(project.directDependencies())) {
            final Long rootId = idByUuid.get(rootUuid);
            if (rootId != null && reachable.add(rootId)) {
                pending.add(rootId);
            }
        }
        while (!pending.isEmpty()) {
            final long current = pending.removeFirst();
            final ComponentRow component = nodes.get(current);
            if (component == null) {
                continue;
            }
            for (final UUID dependencyUuid : dependencyUuids(component.directDependencies())) {
                final Long childId = idByUuid.get(dependencyUuid);
                if (childId != null && reachable.add(childId)) {
                    pending.add(childId);
                }
            }
        }
        return reachable;
    }

    private Map<NameVersion, UUID> resolveSources(final UUID targetUuid, final List<ComponentRow> markers) {
        final var identities = new LinkedHashSet<NameVersion>();
        for (final ComponentRow marker : markers) {
            identities.add(new NameVersion(requireNonNull(marker.name()), requireNonNull(marker.version())));
        }
        final var names = new String[identities.size()];
        final var versions = new String[identities.size()];
        int index = 0;
        for (final NameVersion identity : identities) {
            names[index] = identity.name();
            versions[index] = identity.version();
            index++;
        }

        final var matches = new HashMap<NameVersion, List<UUID>>();
        final List<SourceMatch> rows = handle.createQuery(/* language=SQL */ """
                        SELECT "NAME"
                             , "VERSION"
                             , "UUID"
                          FROM "PROJECT"
                         WHERE "INACTIVE_SINCE" IS NULL
                           AND "COLLECTION_LOGIC" IS NULL
                           AND "UUID" <> :targetUuid
                           AND ("NAME", "VERSION") IN (
                                 SELECT name, version
                                   FROM UNNEST(:names, :versions) AS marker(name, version)
                               )
                        """)
                .bind("targetUuid", targetUuid)
                .bindArray("names", String.class, names)
                .bindArray("versions", String.class, versions)
                .map((rs, ctx) -> new SourceMatch(
                        rs.getString("NAME"), rs.getString("VERSION"), rs.getObject("UUID", UUID.class)))
                .list();
        for (final SourceMatch row : rows) {
            if (row.name() == null || row.version() == null || row.uuid() == null) {
                continue;
            }
            matches.computeIfAbsent(new NameVersion(row.name(), row.version()), ignored -> new ArrayList<>())
                    .add(row.uuid());
        }

        final var resolved = new HashMap<NameVersion, UUID>();
        for (final Map.Entry<NameVersion, List<UUID>> entry : matches.entrySet()) {
            if (entry.getValue().size() == 1) {
                resolved.put(entry.getKey(), entry.getValue().getFirst());
            }
        }
        return resolved;
    }

    private static List<UUID> dependencyUuids(final @Nullable String directDependencies) {
        if (directDependencies == null || directDependencies.isBlank()) {
            return List.of();
        }
        final JsonNode node;
        try {
            node = Mappers.jsonMapper().readTree(directDependencies);
        } catch (Exception e) {
            throw new IllegalStateException("Could not read direct dependencies", e);
        }
        if (!node.isArray()) {
            return List.of();
        }
        final var uuids = new ArrayList<UUID>();
        for (final JsonNode item : node) {
            final JsonNode uuid = item.get("uuid");
            if (uuid == null || !uuid.isTextual() || uuid.asText().isBlank()) {
                continue;
            }
            try {
                uuids.add(UUID.fromString(uuid.asText()));
            } catch (IllegalArgumentException e) {
                throw new IllegalStateException("Could not read dependency uuid " + uuid.asText(), e);
            }
        }
        return uuids;
    }

    private record LoadedGraph(long projectId, List<MarkerMembership> membership) {}

    private record ProjectRow(
            long id, @Nullable UUID uuid, @Nullable String directDependencies) {}

    private record ComponentRow(
            long id,
            @Nullable UUID uuid,
            @Nullable String name,
            @Nullable String version,
            @Nullable String classifier,
            @Nullable String directDependencies) {}

    private record NameVersion(String name, String version) {}

    private record SourceMatch(
            @Nullable String name,
            @Nullable String version,
            @Nullable UUID uuid) {}
}
