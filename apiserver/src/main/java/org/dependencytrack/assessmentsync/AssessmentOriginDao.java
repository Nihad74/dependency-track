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
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.assessmentsync.DaoSupport.requirePositive;
import static org.dependencytrack.assessmentsync.DaoSupport.requireTransaction;

/// Ownership records of target analyses, as authored writers and backfill set them. Uses the caller's transaction.
public final class AssessmentOriginDao {

    /// SQL form of {@link AssessmentOwnership#ofUnlabeled(boolean)} for an analysis aliased {@code a}.
    private static final String UNLABELED_OWNER_SQL = """
            CASE WHEN a."VULNERABILITY_POLICY_ID" IS NOT NULL THEN 'POLICY' ELSE 'LOCAL' END""";

    private final Handle handle;

    public AssessmentOriginDao(final Handle handle) {
        this.handle = handle;
    }

    public void upsertOrigin(final long analysisId, final AssessmentOwnership owner, final boolean decisionChanged) {
        upsertOrigins(List.of(new OriginUpdate(analysisId, owner, decisionChanged)));
    }

    /// Inserts or updates origins in one statement, and clears the worker's last reason. On an existing row the
    /// version moves by one when ownership or the decision changes. A new row starts at 1 when the decision
    /// changed, else at 0. A caller that takes over an unlabeled row passes {@code decisionChanged}, because the
    /// owner the row had is not stored. Analyses that no longer exist are skipped.
    public void upsertOrigins(final Collection<OriginUpdate> updates) {
        requireTransaction(handle);
        if (updates.isEmpty()) {
            return;
        }
        final var analysisIds = new long[updates.size()];
        final var owners = new String[updates.size()];
        final var decisionChanged = new boolean[updates.size()];
        final var seen = new HashSet<Long>();
        int i = 0;
        for (final OriginUpdate update : updates) {
            if (!seen.add(update.analysisId())) {
                throw new IllegalArgumentException("Duplicate origin update for analysis " + update.analysisId());
            }
            analysisIds[i] = update.analysisId();
            owners[i] = update.owner().name();
            decisionChanged[i] = update.decisionChanged();
            i++;
        }
        handle.createUpdate(/* language=SQL */ """
                        WITH input AS (
                          SELECT *
                            FROM UNNEST(:analysisIds, :owners, :decisionChanged)
                                 AS t(analysis_id, owner, decision_changed)
                        ),
                        updated AS (
                          UPDATE "ASSESSMENT_ORIGIN" AS o
                             SET "OWNER" = i.owner
                               , "LAST_REASON" = NULL
                               , "DECISION_VERSION" = o."DECISION_VERSION" + CASE
                                   WHEN i.decision_changed OR o."OWNER" <> i.owner THEN 1
                                   ELSE 0
                                 END
                            FROM input AS i
                           WHERE o."ANALYSIS_ID" = i.analysis_id
                          RETURNING o."ANALYSIS_ID"
                        )
                        INSERT INTO "ASSESSMENT_ORIGIN" ("ANALYSIS_ID", "OWNER", "DECISION_VERSION")
                        SELECT a."ID"
                             , i.owner
                             , CASE WHEN i.decision_changed THEN 1 ELSE 0 END
                          FROM input AS i
                         INNER JOIN "ANALYSIS" AS a
                            ON a."ID" = i.analysis_id
                         WHERE NOT EXISTS (SELECT 1 FROM updated AS u WHERE u."ANALYSIS_ID" = i.analysis_id)
                        """)
                .bind("analysisIds", analysisIds)
                .bind("owners", owners)
                .bind("decisionChanged", decisionChanged)
                .execute();
    }

    /// Reads the origin row. Null means the analysis predates the feature; see
    /// {@link AssessmentOwnership#ofUnlabeled(boolean)}.
    public @Nullable Origin findOrigin(final long analysisId) {
        requirePositive(analysisId, "analysisId");
        return handle.createQuery(/* language=SQL */ """
                        SELECT "OWNER"
                             , "DECISION_VERSION"
                             , "LAST_REASON"
                          FROM "ASSESSMENT_ORIGIN"
                         WHERE "ANALYSIS_ID" = :analysisId
                        """)
                .bind("analysisId", analysisId)
                .map((rs, ctx) -> readOrigin(rs))
                .findOne()
                .orElse(null);
    }

    /// Reads the origin of the analysis of one finding. Null when the analysis or its origin row is missing.
    public @Nullable Origin findOriginOfFinding(final long componentId, final long vulnerabilityId) {
        return handle.createQuery(/* language=SQL */ """
                        SELECT o."OWNER"
                             , o."DECISION_VERSION"
                             , o."LAST_REASON"
                          FROM "ANALYSIS" AS a
                         INNER JOIN "ASSESSMENT_ORIGIN" AS o
                            ON o."ANALYSIS_ID" = a."ID"
                         WHERE a."COMPONENT_ID" = :componentId
                           AND a."VULNERABILITY_ID" = :vulnerabilityId
                        """)
                .bind("componentId", componentId)
                .bind("vulnerabilityId", vulnerabilityId)
                .map((rs, ctx) -> readOrigin(rs))
                .findOne()
                .orElse(null);
    }

    /// Removes copied source trails. Target comments in ANALYSISCOMMENT are left in place.
    public void deleteCopiedContributions(final long analysisId) {
        deleteCopiedContributions(List.of(analysisId));
    }

    public void deleteCopiedContributions(final Collection<Long> analysisIds) {
        requireTransaction(handle);
        if (analysisIds.isEmpty()) {
            return;
        }
        handle.createUpdate(/* language=SQL */ """
                        DELETE FROM "ASSESSMENT_SOURCE_CONTRIBUTION"
                         WHERE "TARGET_ANALYSIS_ID" = ANY(:analysisIds)
                        """)
                .bind(
                        "analysisIds",
                        analysisIds.stream().mapToLong(Long::longValue).toArray())
                .execute();
    }

    /// Labels one project's unlabeled analyses. An existing origin row is left unchanged.
    public int backfillProjectOrigins(final UUID projectUuid) {
        requireTransaction(handle);
        return handle.createUpdate(/* language=SQL */ """
                        INSERT INTO "ASSESSMENT_ORIGIN" ("ANALYSIS_ID", "OWNER")
                        SELECT a."ID"
                             , %s
                          FROM "ANALYSIS" AS a
                         INNER JOIN "PROJECT" AS p
                            ON p."ID" = a."PROJECT_ID"
                         WHERE p."UUID" = :projectUuid
                        ON CONFLICT ("ANALYSIS_ID") DO NOTHING
                        """.formatted(UNLABELED_OWNER_SQL))
                .bind("projectUuid", projectUuid)
                .execute();
    }

    /// Maps {@code OWNER}, {@code DECISION_VERSION} and {@code LAST_REASON}. Null when {@code OWNER} is null, as
    /// it is for an analysis without an origin row in an outer join.
    static @Nullable Origin readOrigin(final ResultSet rs) throws SQLException {
        final String owner = rs.getString("OWNER");
        if (owner == null) {
            return null;
        }
        final String lastReason = rs.getString("LAST_REASON");
        return new Origin(
                AssessmentOwnership.valueOf(owner),
                rs.getLong("DECISION_VERSION"),
                lastReason == null ? null : AssessmentReason.valueOf(lastReason));
    }

    /// Stored owner of one analysis, its decision version, and why the worker last left it as it is.
    public record Origin(
            AssessmentOwnership owner,
            long decisionVersion,
            @Nullable AssessmentReason lastReason) {}

    public record OriginUpdate(long analysisId, AssessmentOwnership owner, boolean decisionChanged) {

        public OriginUpdate {
            requirePositive(analysisId, "analysisId");
        }
    }
}
