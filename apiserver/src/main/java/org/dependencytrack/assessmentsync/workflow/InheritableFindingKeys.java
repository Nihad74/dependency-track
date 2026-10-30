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
package org.dependencytrack.assessmentsync.workflow;

import org.dependencytrack.model.FindingKey;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.Query;
import org.jspecify.annotations.Nullable;

import java.util.List;

/// Keyset pages of the findings a full pass or verification must look at: findings on embedded members,
/// which can inherit, and inherited rows, which may need withdrawal. The marker itself is not a member.
final class InheritableFindingKeys {

    private InheritableFindingKeys() {}

    /// Keyset predicate "after the cursor" over the given columns. Bind it with {@link #bindCursor}.
    static String afterCursor(final String componentColumn, final String vulnerabilityColumn) {
        return """
                (:hasCursor = FALSE
                 OR %1$s > :cursorComponentId
                 OR (%1$s = :cursorComponentId AND %2$s > :cursorVulnerabilityId))\
                """.formatted(componentColumn, vulnerabilityColumn);
    }

    static Query bindCursor(final Query query, final @Nullable FindingKey cursor) {
        return query.bind("hasCursor", cursor != null)
                .bind("cursorComponentId", cursor == null ? 0L : cursor.componentId())
                .bind("cursorVulnerabilityId", cursor == null ? 0L : cursor.vulnDbId());
    }

    static List<FindingKey> page(
            final Handle handle, final long projectId, final @Nullable FindingKey cursor, final int limit) {
        return bindCursor(
                        handle.createQuery(
                                /* language=SQL */ """
                        SELECT component_id
                             , vulnerability_id
                          FROM (
                                SELECT DISTINCT fa."COMPONENT_ID" AS component_id
                                     , fa."VULNERABILITY_ID" AS vulnerability_id
                                  FROM "FINDINGATTRIBUTION" AS fa
                                 INNER JOIN "COMPONENT" AS c
                                    ON c."ID" = fa."COMPONENT_ID"
                                 WHERE c."PROJECT_ID" = :projectId
                                   AND fa."DELETED_AT" IS NULL
                                   AND EXISTS (
                                     SELECT 1
                                       FROM "ASSESSMENT_EMBEDDING_MEMBER" AS m
                                      WHERE m."TARGET_PROJECT_ID" = :projectId
                                        AND m."COMPONENT_ID" = fa."COMPONENT_ID"
                                   )
                                UNION
                                SELECT a."COMPONENT_ID"
                                     , a."VULNERABILITY_ID"
                                  FROM "ANALYSIS" AS a
                                 INNER JOIN "ASSESSMENT_ORIGIN" AS o
                                    ON o."ANALYSIS_ID" = a."ID"
                                 WHERE a."PROJECT_ID" = :projectId
                                   AND o."OWNER" = 'INHERITED'
                                   AND a."COMPONENT_ID" IS NOT NULL
                               ) AS keys
                         WHERE %s
                         ORDER BY component_id, vulnerability_id
                         LIMIT :limit
                        """.formatted(afterCursor("component_id", "vulnerability_id"))),
                        cursor)
                .bind("projectId", projectId)
                .bind("limit", limit)
                .map((rs, ctx) -> new FindingKey(rs.getLong("component_id"), rs.getLong("vulnerability_id")))
                .list();
    }
}
