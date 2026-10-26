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

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;

/// Project-local reachability beneath a marker. The caller supplies the graph.
public final class AssessmentGraph {

    private AssessmentGraph() {}

    /// Package component ids strictly beneath {@code markerId}. The marker itself is omitted.
    ///
    /// An empty graph or a marker that is not in the graph yields an empty set.
    public static Set<Long> descendants(final Graph graph, final long markerId) {
        Objects.requireNonNull(graph, "graph must not be null");
        final Node marker = graph.nodes().get(markerId);
        if (marker == null || !graph.projectId().equals(marker.projectId())) {
            return Set.of();
        }

        final Map<Long, List<Edge>> edgesByParent = new HashMap<>();
        for (final Edge edge : graph.edges()) {
            List<Edge> children = edgesByParent.get(edge.fromComponentId());
            if (children == null) {
                children = new ArrayList<>();
                edgesByParent.put(edge.fromComponentId(), children);
            }
            children.add(edge);
        }

        final Set<Long> visited = new HashSet<>();
        final Set<Long> descendants = new LinkedHashSet<>();
        final ArrayDeque<Long> pending = new ArrayDeque<>();
        visited.add(markerId);
        pending.add(markerId);
        while (!pending.isEmpty()) {
            final long current = pending.removeFirst();
            final List<Edge> children = edgesByParent.get(current);
            if (children == null) {
                continue;
            }
            for (final Edge edge : children) {
                if (!graph.projectId().equals(edge.projectId())) {
                    continue;
                }
                final Node child = graph.nodes().get(edge.toComponentId());
                if (child == null || !graph.projectId().equals(child.projectId())) {
                    continue;
                }
                if (!visited.add(child.componentId())) {
                    continue;
                }
                if (!child.service()) {
                    descendants.add(child.componentId());
                }
                pending.addLast(child.componentId());
            }
        }
        return Set.copyOf(descendants);
    }

    /// Immutable dependency graph for one target project. Foreign nodes and edges may be present.
    public record Graph(UUID projectId, Map<Long, Node> nodes, List<Edge> edges) {

        public Graph {
            Objects.requireNonNull(projectId, "projectId must not be null");
            Objects.requireNonNull(nodes, "nodes must not be null");
            Objects.requireNonNull(edges, "edges must not be null");
            nodes = Map.copyOf(nodes);
            edges = List.copyOf(edges);
            for (final Map.Entry<Long, Node> entry : nodes.entrySet()) {
                if (entry.getKey().longValue() != entry.getValue().componentId()) {
                    throw new IllegalArgumentException("node map key must equal the component id");
                }
            }
        }
    }

    public record Node(long componentId, UUID projectId, boolean service) {

        public Node {
            Objects.requireNonNull(projectId, "projectId must not be null");
        }
    }

    /// Directed dependency from parent to child. {@code projectId} is the project that owns the edge.
    public record Edge(UUID projectId, long fromComponentId, long toComponentId) {

        public Edge {
            Objects.requireNonNull(projectId, "projectId must not be null");
        }
    }
}
