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
package org.dependencytrack.persistence;

import org.datanucleus.api.jdo.JDOPersistenceManager;
import org.datanucleus.state.DNStateManager;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;

import javax.jdo.PersistenceManager;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;

/** Invalidates legacy JDO copies after a transactional JDBI analysis write. */
public final class AnalysisCache {
    private AnalysisCache() {}
    /** Invalidates only these findings, keeping unrelated analyses loaded by the caller intact. */
    public static void evict(final PersistenceManager pm, final Collection<Long> analysisIds) {
        final var ids = Set.copyOf(analysisIds);
        if (ids.isEmpty()) {
            return;
        }
        final var affected = new ArrayList<Object>();
        // DataNucleus getManagedObjects only returns objects enlisted in an active transaction.
        // Its first-level cache also contains values retained across commits. Snapshot it before
        // inspecting relationships, whose lazy loading can add entries to the cache.
        final var cached = ((JDOPersistenceManager) pm)
                .getExecutionContext().getLevel1Cache().values().stream()
                        .map(DNStateManager::getObject)
                        .toList();
        for (final Object object : cached) {
            if (object instanceof final AnalysisComment comment) {
                if (ids.contains(comment.getAnalysis().getId())) {
                    affected.add(comment);
                }
            } else if (object instanceof final Analysis analysis && ids.contains(analysis.getId())) {
                affected.add(analysis);
            }
        }
        pm.evictAll(affected);
    }
}
