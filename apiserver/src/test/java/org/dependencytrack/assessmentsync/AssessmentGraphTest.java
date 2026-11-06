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

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AssessmentGraphTest {

    @Test
    void graphTakesAnImmutableSnapshotOfEdgesAndNodes() {
        final var edges = new java.util.ArrayList<>(List.of(2L));
        final var nodes = new HashMap<Long, List<Long>>();
        nodes.put(1L, edges);
        nodes.put(2L, List.of());
        final var graph = new AssessmentGraph(nodes);
        edges.clear();
        nodes.clear();
        assertThat(graph.reachableFrom(List.of(1L))).containsExactlyInAnyOrder(1L, 2L);
        assertThat(graph.descendants(1L)).containsExactly(2L);
    }

    @Test
    void shouldReachBeyondDepthThree() {
        final AssessmentGraph graph =
                graph(nodes(1, 2, 3, 4, 5, 6), edge(1, 2), edge(2, 3), edge(3, 4), edge(4, 5), edge(5, 6));

        assertThat(graph.descendants(1L)).containsExactlyInAnyOrder(2L, 3L, 4L, 5L, 6L);
    }

    @Test
    void shouldTerminateCycles() {
        final AssessmentGraph graph = graph(nodes(1, 2, 3), edge(1, 2), edge(2, 3), edge(3, 1));

        assertThat(graph.descendants(1L)).containsExactlyInAnyOrder(2L, 3L);
    }

    @Test
    void shouldIncludeANodeReachedByTwoPathsOnce() {
        final AssessmentGraph graph = graph(nodes(1, 2, 3, 4), edge(1, 2), edge(2, 4), edge(1, 3), edge(3, 4));

        assertThat(graph.descendants(1L)).containsExactlyInAnyOrder(2L, 3L, 4L);
    }

    @Test
    void shouldNotIncludeTheMarker() {
        final AssessmentGraph graph = graph(nodes(1, 2), edge(1, 2));

        assertThat(graph.descendants(1L)).containsExactly(2L);
    }

    @Test
    void shouldReturnEmptyForUnknownMarker() {
        final AssessmentGraph graph = graph(nodes(1), edge(1, 1));

        assertThat(graph.descendants(99L)).isEmpty();
    }

    @Test
    void shouldIncludeSharedPath() {
        final AssessmentGraph graph = graph(nodes(1, 2, 9), edge(1, 2), edge(9, 2));

        assertThat(graph.descendants(1L)).containsExactly(2L);
    }

    @Test
    void shouldReturnEmptyForEmptyGraph() {
        assertThat(new AssessmentGraph(Map.of()).descendants(1L)).isEmpty();
    }

    @Test
    void shouldReturnEmptyWhenMarkerHasNoEdges() {
        assertThat(graph(nodes(1)).descendants(1L)).isEmpty();
    }

    @Test
    void shouldOmitChildrenOfARemovedIntermediateNode() {
        assertThat(graph(nodes(1, 2, 3), edge(1, 2), edge(2, 3)).descendants(1L))
                .containsExactlyInAnyOrder(2L, 3L);
        assertThat(graph(nodes(1, 3), edge(1, 2), edge(2, 3)).descendants(1L)).isEmpty();
    }

    @Test
    void shouldReachFromRootsIncludingTheRootsThemselves() {
        final AssessmentGraph graph = graph(nodes(1, 2, 3, 4), edge(1, 2), edge(3, 4));

        assertThat(graph.reachableFrom(List.of(1L, 99L))).containsExactlyInAnyOrder(1L, 2L);
    }

    private static List<Long> nodes(final long... ids) {
        return java.util.Arrays.stream(ids).boxed().toList();
    }

    private static long[] edge(final long from, final long to) {
        return new long[] {from, to};
    }

    private static AssessmentGraph graph(final List<Long> nodes, final long[]... edges) {
        final var children = new HashMap<Long, List<Long>>();
        for (final long node : nodes) {
            children.put(node, new java.util.ArrayList<>());
        }
        for (final long[] edge : edges) {
            if (children.containsKey(edge[0])) {
                children.get(edge[0]).add(edge[1]);
            }
        }
        return new AssessmentGraph(children);
    }
}
