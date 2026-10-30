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

import org.dependencytrack.persistence.jdbi.ProjectDao;

import java.util.List;
import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/// Reads what writers record for assessment synchronization, through the same DAO methods its consumers use.
public final class AssessmentSyncTestSupport {

    private AssessmentSyncTestSupport() {}

    /// What writers hand to the relay, read the way the relay reads it.
    public static List<AssessmentChange> recordedChanges() {
        return inJdbiTransaction(handle -> new AssessmentSyncOutboxDao(handle)
                .pollDue(1000).stream()
                        .map(AssessmentSyncOutboxDao.OutboxEntry::change)
                        .toList());
    }

    public static List<AssessmentChange> recordedChanges(final UUID projectUuid) {
        return recordedChanges().stream()
                .filter(change -> change.projectUuid().equals(projectUuid))
                .toList();
    }

    /// Null when the analysis has no origin record, as before the feature.
    public static AssessmentOwnership owner(final long analysisId) {
        final AssessmentOriginDao.Origin origin =
                withJdbiHandle(handle -> new AssessmentOriginDao(handle).findOrigin(analysisId));
        return origin == null ? null : origin.owner();
    }

    /// The embeddings of a target that resolve the marker name and version to a source.
    public static List<AssessmentEmbeddingDao.Embedding> embeddings(
            final UUID targetUuid, final String markerName, final String markerVersion) {
        return withJdbiHandle(handle -> {
            final Long targetId = handle.attach(ProjectDao.class).getProjectId(targetUuid);
            return new AssessmentEmbeddingDao(handle)
                    .findByMarkerNameAndVersion(markerName, markerVersion).stream()
                            .filter(embedding -> targetId != null && embedding.targetProjectId() == targetId)
                            .toList();
        });
    }

    /// Whether the component is inside an embedded scope of the target.
    public static boolean isEmbeddedMember(final UUID targetUuid, final long componentId) {
        return withJdbiHandle(handle -> {
            final Long targetId = handle.attach(ProjectDao.class).getProjectId(targetUuid);
            return targetId != null
                    && !new AssessmentEmbeddingDao(handle)
                            .findMembership(targetId, componentId)
                            .isEmpty();
        });
    }
}
