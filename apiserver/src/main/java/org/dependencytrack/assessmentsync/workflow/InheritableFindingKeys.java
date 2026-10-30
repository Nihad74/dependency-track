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
import org.jspecify.annotations.Nullable;

import java.util.List;

/// Keyset pages of the findings a full pass or verification must look at: findings on embedded members,
/// which can inherit, and inherited rows, which may need withdrawal. The marker itself is not a member.
final class InheritableFindingKeys {

    private InheritableFindingKeys() {}

    static List<FindingKey> page(
            final Handle handle,
            final long projectId,
            final @Nullable Long cursorComponentId,
            final @Nullable Long cursorVulnerabilityId,
            final int limit) {
        final boolean hasCursor = cursorComponentId != null && cursorVulnerabilityId != null;
        return handle.createQuery(/* language=SQL */ """
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
                         WHERE :hasCursor = FALSE
                            OR component_id > :cursorComponentId
                            OR (
                              component_id = :cursorComponentId
                              AND vulnerability_id > :cursorVulnerabilityId
                            )
                         ORDER BY component_id, vulnerability_id
                         LIMIT :limit
                        """)
                .bind("projectId", projectId)
                .bind("hasCursor", hasCursor)
                .bind("cursorComponentId", cursorComponentId == null ? 0L : cursorComponentId)
                .bind("cursorVulnerabilityId", cursorVulnerabilityId == null ? 0L : cursorVulnerabilityId)
                .bind("limit", limit)
                .map((rs, ctx) -> new FindingKey(rs.getLong("component_id"), rs.getLong("vulnerability_id")))
                .list();
    }
}
