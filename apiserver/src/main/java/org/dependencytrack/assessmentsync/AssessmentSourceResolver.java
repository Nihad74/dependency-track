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

import org.dependencytrack.model.ConfigPropertyConstants;
import org.jdbi.v3.core.Handle;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/// The single rule that turns a marker identity into a source project (ADR 044).
///
/// A source has exactly the marker's name and version, is active, is not a collection project,
/// and is not the target. An identity that matches more than one project resolves to nothing.
/// With portfolio access control on, a source is eligible only when every team that can access the
/// target can also access the source, directly or through a parent. Otherwise its decided values would
/// reach viewers of the target who cannot see the source.
final class AssessmentSourceResolver {

    private AssessmentSourceResolver() {}

    static Map<Identity, UUID> resolve(final Handle handle, final UUID targetUuid, final Collection<Identity> markers) {
        requireNonNull(handle, "handle must not be null");
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireNonNull(markers, "markers must not be null");
        if (markers.isEmpty()) {
            return Map.of();
        }
        final var names = new String[markers.size()];
        final var versions = new String[markers.size()];
        int index = 0;
        for (final Identity marker : markers) {
            names[index] = marker.name();
            versions[index] = marker.version();
            index++;
        }

        final var candidates = new HashMap<Identity, List<Candidate>>();
        handle.createQuery(/* language=SQL */ """
                        WITH acl AS (
                          SELECT EXISTS (
                                   SELECT 1
                                     FROM "CONFIGPROPERTY"
                                    WHERE "GROUPNAME" = :aclGroup
                                      AND "PROPERTYNAME" = :aclProperty
                                      AND LOWER(TRIM("PROPERTYVALUE")) IN ('true', '1')
                                 ) AS enabled
                        ),
                        target_team AS (
                          SELECT DISTINCT access."TEAM_ID"
                            FROM "PROJECT" AS target
                           INNER JOIN "PROJECT_HIERARCHY" AS hierarchy
                              ON hierarchy."CHILD_PROJECT_ID" = target."ID"
                           INNER JOIN "PROJECT_ACCESS_TEAMS" AS access
                              ON access."PROJECT_ID" = hierarchy."PARENT_PROJECT_ID"
                           WHERE target."UUID" = :targetUuid
                        )
                        SELECT source."NAME"
                             , source."VERSION"
                             , source."UUID"
                             , (
                                 NOT (SELECT enabled FROM acl)
                                 OR NOT EXISTS (
                                      SELECT 1
                                        FROM target_team
                                       WHERE NOT EXISTS (
                                               SELECT 1
                                                 FROM "PROJECT_HIERARCHY" AS source_hierarchy
                                                INNER JOIN "PROJECT_ACCESS_TEAMS" AS source_access
                                                   ON source_access."PROJECT_ID" = source_hierarchy."PARENT_PROJECT_ID"
                                                WHERE source_hierarchy."CHILD_PROJECT_ID" = source."ID"
                                                  AND source_access."TEAM_ID" = target_team."TEAM_ID"
                                             )
                                    )
                               ) AS eligible
                          FROM "PROJECT" AS source
                         WHERE source."INACTIVE_SINCE" IS NULL
                           AND source."COLLECTION_LOGIC" IS NULL
                           AND source."UUID" <> :targetUuid
                           AND (source."NAME", source."VERSION") IN (
                                 SELECT name, version
                                   FROM UNNEST(:names, :versions) AS marker(name, version)
                               )
                        """)
                .bind("targetUuid", targetUuid)
                .bind("aclGroup", ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName())
                .bind("aclProperty", ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName())
                .bind("names", names)
                .bind("versions", versions)
                .map((rs, ctx) -> {
                    final String name = rs.getString("NAME");
                    final String version = rs.getString("VERSION");
                    final UUID uuid = rs.getObject("UUID", UUID.class);
                    if (name != null && version != null && uuid != null) {
                        candidates
                                .computeIfAbsent(new Identity(name, version), ignored -> new ArrayList<>())
                                .add(new Candidate(uuid, rs.getBoolean("eligible")));
                    }
                    return uuid;
                })
                .list();

        final var resolved = new HashMap<Identity, UUID>();
        for (final Map.Entry<Identity, List<Candidate>> entry : candidates.entrySet()) {
            // Ambiguity is judged before the access gate, so a hidden duplicate never makes a match unique.
            if (entry.getValue().size() == 1 && entry.getValue().getFirst().eligible()) {
                resolved.put(entry.getKey(), entry.getValue().getFirst().uuid());
            }
        }
        return resolved;
    }

    record Identity(String name, String version) {

        Identity {
            requireNonNull(name, "name must not be null");
            requireNonNull(version, "version must not be null");
        }
    }

    private record Candidate(UUID uuid, boolean eligible) {}
}
