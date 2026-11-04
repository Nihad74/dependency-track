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
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Dependency graph of one project's components. Every node is a key; an edge to an id that is not a key is
 * ignored, so a removed component also hides what was only reachable through it.
 */
public final class AssessmentGraph {

    private final Map<Long, List<Long>> childrenByNode;

    public AssessmentGraph(final Map<Long, List<Long>> childrenByNode) {
        final var copy = new HashMap<Long, List<Long>>(childrenByNode.size());
        childrenByNode.forEach((node, children) -> copy.put(node, List.copyOf(children)));
        this.childrenByNode = copy;
    }

    /**
     * Every node reachable from {@code roots}, roots included. Roots that are not nodes are ignored.
     */
    public Set<Long> reachableFrom(final Collection<Long> roots) {
        final var visited = new LinkedHashSet<Long>();
        for (final long root : roots) {
            if (childrenByNode.containsKey(root)) {
                visited.add(root);
            }
        }
        walk(visited, List.copyOf(visited));
        return Set.copyOf(visited);
    }

    /**
     * Components strictly beneath {@code markerId}. The marker itself is omitted, even on a cycle.
     */
    public Set<Long> descendants(final long markerId) {
        if (!childrenByNode.containsKey(markerId)) {
            return Set.of();
        }
        final var visited = new LinkedHashSet<Long>();
        visited.add(markerId);
        walk(visited, List.of(markerId));
        visited.remove(markerId);
        return Set.copyOf(visited);
    }

    /**
     * Breadth-first from {@code start}, whose nodes are already in {@code visited}.
     */
    private void walk(final Set<Long> visited, final List<Long> start) {
        final var pending = new ArrayDeque<Long>(start);
        while (!pending.isEmpty()) {
            for (final long child : childrenByNode.getOrDefault(pending.removeFirst(), List.of())) {
                if (childrenByNode.containsKey(child) && visited.add(child)) {
                    pending.add(child);
                }
            }
        }
    }
}
