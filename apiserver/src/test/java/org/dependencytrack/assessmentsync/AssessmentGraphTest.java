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

import org.dependencytrack.assessmentsync.AssessmentGraph.Edge;
import org.dependencytrack.assessmentsync.AssessmentGraph.Graph;
import org.dependencytrack.assessmentsync.AssessmentGraph.Node;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class AssessmentGraphTest {

    private static final UUID PROJECT = UUID.fromString("aaaaaaaa-0000-0000-0000-000000000001");
    private static final UUID OTHER_PROJECT = UUID.fromString("bbbbbbbb-0000-0000-0000-000000000002");

    @Test
    void shouldReachBeyondDepthThree() {
        final Graph graph = graph(
                Map.of(
                        1L, node(1),
                        2L, node(2),
                        3L, node(3),
                        4L, node(4),
                        5L, node(5),
                        6L, node(6)),
                edge(1, 2),
                edge(2, 3),
                edge(3, 4),
                edge(4, 5),
                edge(5, 6));

        assertThat(AssessmentGraph.descendants(graph, 1L)).containsExactlyInAnyOrder(2L, 3L, 4L, 5L, 6L);
    }

    @Test
    void shouldTerminateCycles() {
        final Graph graph = graph(Map.of(1L, node(1), 2L, node(2), 3L, node(3)), edge(1, 2), edge(2, 3), edge(3, 1));

        final Set<Long> descendants = AssessmentGraph.descendants(graph, 1L);

        assertThat(descendants).containsExactlyInAnyOrder(2L, 3L);
        assertThat(descendants).doesNotContain(1L);
    }

    @Test
    void shouldIncludeANodeReachedByTwoPathsOnce() {
        final Graph graph = graph(
                Map.of(1L, node(1), 2L, node(2), 3L, node(3), 4L, node(4)),
                edge(1, 2),
                edge(2, 4),
                edge(1, 3),
                edge(3, 4));

        final Set<Long> descendants = AssessmentGraph.descendants(graph, 1L);

        assertThat(descendants).containsExactlyInAnyOrder(2L, 3L, 4L);
        assertThat(descendants).hasSize(3);
    }

    @Test
    void shouldNotIncludeTheMarker() {
        final Graph graph = graph(Map.of(1L, node(1), 2L, node(2)), edge(1, 2));

        final Set<Long> descendants = AssessmentGraph.descendants(graph, 1L);

        assertThat(descendants).containsExactly(2L);
        assertThat(descendants).doesNotContain(1L);
    }

    @Test
    void shouldReturnEmptyForUnreachableMarker() {
        final Graph graph = graph(Map.of(1L, node(1)), edge(1, 1));

        assertThat(AssessmentGraph.descendants(graph, 99L)).isEmpty();
    }

    @Test
    void shouldIncludeSharedPath() {
        final Graph graph = graph(Map.of(1L, node(1), 2L, node(2), 9L, node(9)), edge(1, 2), edge(9, 2));

        assertThat(AssessmentGraph.descendants(graph, 1L)).containsExactly(2L);
    }

    @Test
    void shouldIgnoreCrossProjectEdge() {
        final Node foreign = new Node(2L, OTHER_PROJECT, false);
        final Graph graph = new Graph(
                PROJECT,
                Map.of(1L, node(1), 2L, foreign, 3L, node(3)),
                List.of(new Edge(OTHER_PROJECT, 1L, 2L), new Edge(PROJECT, 1L, 2L), edge(1, 3)));

        assertThat(AssessmentGraph.descendants(graph, 1L)).containsExactly(3L);
    }

    @Test
    void shouldExcludeServiceNodes() {
        final Graph graph =
                graph(Map.of(1L, node(1), 2L, new Node(2L, PROJECT, true), 3L, node(3)), edge(1, 2), edge(2, 3));

        final Set<Long> descendants = AssessmentGraph.descendants(graph, 1L);

        assertThat(descendants).containsExactly(3L);
        assertThat(descendants).doesNotContain(2L, 1L);
    }

    @Test
    void shouldReturnEmptyForEmptyGraph() {
        final Graph graph = new Graph(PROJECT, Map.of(), List.of());

        assertThat(AssessmentGraph.descendants(graph, 1L)).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenMarkerHasNoEdges() {
        final Graph graph = graph(Map.of(1L, node(1)));

        assertThat(AssessmentGraph.descendants(graph, 1L)).isEmpty();
    }

    @Test
    void shouldOmitChildrenOfARemovedIntermediateNode() {
        final Map<Long, Node> withIntermediate = Map.of(1L, node(1), 2L, node(2), 3L, node(3));
        final Map<Long, Node> intermediateRemoved = Map.of(1L, node(1), 3L, node(3));
        final List<Edge> edges = List.of(edge(1, 2), edge(2, 3));

        assertThat(AssessmentGraph.descendants(new Graph(PROJECT, withIntermediate, edges), 1L))
                .containsExactlyInAnyOrder(2L, 3L);
        assertThat(AssessmentGraph.descendants(new Graph(PROJECT, intermediateRemoved, edges), 1L))
                .isEmpty();
    }

    private static Graph graph(final Map<Long, Node> nodes, final Edge... edges) {
        return new Graph(PROJECT, nodes, List.of(edges));
    }

    private static Node node(final long id) {
        return new Node(id, PROJECT, false);
    }

    private static Edge edge(final long from, final long to) {
        return new Edge(PROJECT, from, to);
    }
}
