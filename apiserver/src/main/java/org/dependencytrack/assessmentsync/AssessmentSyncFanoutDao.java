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

import org.jdbi.v3.core.Handle;

import java.util.List;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/// Paged discovery of targets affected by one outbox row. Reads the durable cursor from that row.
public final class AssessmentSyncFanoutDao {

    private static final String EVENT = """
            event AS (
              SELECT "PROJECT_UUID" AS source_uuid
                   , "COMPONENT_UUID" AS source_component_uuid
                   , "VULNERABILITY_UUID" AS source_vulnerability_uuid
                   , "FANOUT_CURSOR" AS cursor_uuid
                   , "LOOKUP_KEYS" AS lookup_keys
                FROM "ASSESSMENT_SYNC_OUTBOX"
               WHERE "ID" = :outboxId
            )
            """;

    private static final String PROJECT_TARGETS = """
            lookup AS (
              SELECT lookup_key.name AS name
                   , lookup_key.version AS version
                FROM event
               CROSS JOIN LATERAL jsonb_to_recordset(
                      CASE
                        WHEN jsonb_typeof(event.lookup_keys) = 'array' THEN event.lookup_keys
                        ELSE CAST('[]' AS jsonb)
                      END
                    ) AS lookup_key(name text, version text)
               WHERE lookup_key.name IS NOT NULL
                 AND lookup_key.version IS NOT NULL
            ),
            project_target AS (
              SELECT project."UUID" AS target_uuid
                FROM event
                JOIN "PROJECT" AS project
                  ON project."UUID" = event.source_uuid
              UNION
              SELECT project."UUID"
                FROM event
                JOIN "ASSESSMENT_EMBEDDING" AS embedding
                  ON embedding."SOURCE_PROJECT_UUID" = event.source_uuid
                JOIN "PROJECT" AS project
                  ON project."ID" = embedding."TARGET_PROJECT_ID"
              UNION
              SELECT project."UUID"
                FROM "ASSESSMENT_EMBEDDING" AS embedding
                JOIN "PROJECT" AS project
                  ON project."ID" = embedding."TARGET_PROJECT_ID"
                JOIN lookup
                  ON lookup.name = embedding."MARKER_NAME"
                 AND lookup.version = embedding."MARKER_VERSION"
              UNION
              SELECT project."UUID"
                FROM event
                JOIN "ASSESSMENT_SOURCE_CONTRIBUTION" AS contribution
                  ON contribution."SOURCE_PROJECT_UUID" = event.source_uuid
                JOIN "ANALYSIS" AS analysis
                  ON analysis."ID" = contribution."TARGET_ANALYSIS_ID"
                JOIN "PROJECT" AS project
                  ON project."ID" = analysis."PROJECT_ID"
            )
            """;

    private static final String FINDING_KEYS = """
            finding_key AS (
              SELECT project."UUID" AS target_uuid
                   , component."ID" AS component_id
                   , vulnerability."ID" AS vulnerability_id
                FROM event
                JOIN "PROJECT" AS project
                  ON project."UUID" = event.source_uuid
                JOIN "COMPONENT" AS component
                  ON component."PROJECT_ID" = project."ID"
                 AND component."UUID" = event.source_component_uuid
                JOIN "VULNERABILITY" AS vulnerability
                  ON vulnerability."UUID" = event.source_vulnerability_uuid
              UNION
              SELECT project."UUID"
                   , member."COMPONENT_ID"
                   , vulnerability."ID"
                FROM event
                JOIN "ASSESSMENT_EMBEDDING" AS embedding
                  ON embedding."SOURCE_PROJECT_UUID" = event.source_uuid
                JOIN "PROJECT" AS project
                  ON project."ID" = embedding."TARGET_PROJECT_ID"
                JOIN "ASSESSMENT_EMBEDDING_MEMBER" AS member
                  ON member."TARGET_PROJECT_ID" = embedding."TARGET_PROJECT_ID"
                 AND member."MARKER_COMPONENT_ID" = embedding."MARKER_COMPONENT_ID"
                JOIN "VULNERABILITY" AS vulnerability
                  ON vulnerability."UUID" = event.source_vulnerability_uuid
               WHERE EXISTS (
                       SELECT 1
                         FROM "ANALYSIS" AS analysis
                        WHERE analysis."COMPONENT_ID" = member."COMPONENT_ID"
                          AND analysis."VULNERABILITY_ID" = vulnerability."ID"
                     )
                  OR EXISTS (
                       SELECT 1
                         FROM "COMPONENTS_VULNERABILITIES" AS component_vulnerability
                        WHERE component_vulnerability."COMPONENT_ID" = member."COMPONENT_ID"
                          AND component_vulnerability."VULNERABILITY_ID" = vulnerability."ID"
                     )
                  OR EXISTS (
                       SELECT 1
                         FROM "FINDINGATTRIBUTION" AS attribution
                        WHERE attribution."COMPONENT_ID" = member."COMPONENT_ID"
                          AND attribution."VULNERABILITY_ID" = vulnerability."ID"
                     )
              UNION
              SELECT project."UUID"
                   , analysis."COMPONENT_ID"
                   , analysis."VULNERABILITY_ID"
                FROM event
                JOIN "ASSESSMENT_SOURCE_CONTRIBUTION" AS contribution
                  ON contribution."SOURCE_PROJECT_UUID" = event.source_uuid
                 AND contribution."SOURCE_COMPONENT_UUID" = event.source_component_uuid
                 AND contribution."SOURCE_VULNERABILITY_UUID" = event.source_vulnerability_uuid
                JOIN "ANALYSIS" AS analysis
                  ON analysis."ID" = contribution."TARGET_ANALYSIS_ID"
                JOIN "PROJECT" AS project
                  ON project."ID" = analysis."PROJECT_ID"
            )
            """;

    private final Handle handle;

    public AssessmentSyncFanoutDao(final Handle handle) {
        this.handle = requireNonNull(handle, "handle must not be null");
    }

    /// Next project-scope targets after the row's stored cursor, in UUID order.
    public List<UUID> pageProjectTargets(final long outboxId, final int limit) {
        requireLimit(limit);
        requireTransaction();
        return handle.createQuery("WITH\n" + EVENT + ",\n" + PROJECT_TARGETS + """
                        SELECT project_target.target_uuid AS "TARGET_UUID"
                          FROM project_target
                         CROSS JOIN event
                         WHERE event.cursor_uuid IS NULL
                            OR project_target.target_uuid > event.cursor_uuid
                         ORDER BY project_target.target_uuid
                         LIMIT :limit
                        """)
                .bind("outboxId", outboxId)
                .bind("limit", limit)
                .map((rs, ctx) -> rs.getObject("TARGET_UUID", UUID.class))
                .list();
    }

    /// Next finding-scope targets that have at least one matching key.
    public List<UUID> pageFindingTargets(final long outboxId, final int limit) {
        requireLimit(limit);
        requireTransaction();
        return handle.createQuery("WITH\n" + EVENT + ",\n" + FINDING_KEYS + """
                        SELECT finding_key.target_uuid AS "TARGET_UUID"
                          FROM finding_key
                         CROSS JOIN event
                         WHERE event.cursor_uuid IS NULL
                            OR finding_key.target_uuid > event.cursor_uuid
                         GROUP BY finding_key.target_uuid
                         ORDER BY finding_key.target_uuid
                         LIMIT :limit
                        """)
                .bind("outboxId", outboxId)
                .bind("limit", limit)
                .map((rs, ctx) -> rs.getObject("TARGET_UUID", UUID.class))
                .list();
    }

    /// At most {@code limitPerTarget} keys for each requested target, in component/vulnerability order.
    public List<TargetFinding> findingKeys(
            final long outboxId, final List<UUID> targetUuids, final int limitPerTarget) {
        requireNonNull(targetUuids, "targetUuids must not be null");
        requireLimit(limitPerTarget);
        requireTransaction();
        if (targetUuids.isEmpty()) {
            return List.of();
        }
        return handle.createQuery("WITH\n" + EVENT + ",\n" + FINDING_KEYS + """
                        , ranked AS (
                          SELECT finding_key.target_uuid
                               , finding_key.component_id
                               , finding_key.vulnerability_id
                               , row_number() OVER (
                                   PARTITION BY finding_key.target_uuid
                                   ORDER BY finding_key.component_id, finding_key.vulnerability_id
                                 ) AS rn
                            FROM finding_key
                            JOIN UNNEST(:targetUuids) AS page(target_uuid)
                              ON page.target_uuid = finding_key.target_uuid
                        )
                        SELECT ranked.target_uuid AS "TARGET_UUID"
                             , ranked.component_id AS "COMPONENT_ID"
                             , ranked.vulnerability_id AS "VULNERABILITY_ID"
                          FROM ranked
                         WHERE ranked.rn <= :limitPerTarget
                         ORDER BY ranked.target_uuid, ranked.component_id, ranked.vulnerability_id
                        """)
                .bind("outboxId", outboxId)
                .bind("targetUuids", targetUuids.toArray(UUID[]::new))
                .bind("limitPerTarget", limitPerTarget)
                .map((rs, ctx) -> new TargetFinding(
                        rs.getObject("TARGET_UUID", UUID.class),
                        rs.getLong("COMPONENT_ID"),
                        rs.getLong("VULNERABILITY_ID")))
                .list();
    }

    private void requireTransaction() {
        if (!handle.isInTransaction()) {
            throw new IllegalStateException("Assessment fan-out reads require an active transaction");
        }
    }

    private static void requireLimit(final int limit) {
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be positive");
        }
    }

    /// One candidate finding on a target project.
    public record TargetFinding(UUID targetUuid, long componentId, long vulnerabilityId) {

        public TargetFinding {
            requireNonNull(targetUuid, "targetUuid must not be null");
            if (componentId <= 0 || vulnerabilityId <= 0) {
                throw new IllegalArgumentException("component and vulnerability ids must be positive");
            }
        }
    }
}
