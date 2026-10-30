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

import java.util.UUID;

import static java.util.Objects.requireNonNull;

/// Ownership records of target analyses, as authored writers and backfill set them. Uses the caller's transaction.
public final class AssessmentOriginDao {

    private final Handle handle;

    public AssessmentOriginDao(final Handle handle) {
        this.handle = requireNonNull(handle, "handle must not be null");
    }

    /// Inserts origin or updates it, and clears the worker's last reason. The version moves by one when
    /// ownership or the decision changes. A missing row is version 0, so a new row starts at 1 when the
    /// decision changed.
    public long upsertOrigin(final long analysisId, final AssessmentOwnership owner, final boolean decisionChanged) {
        requireAnalysisId(analysisId);
        requireNonNull(owner, "owner must not be null");
        requireTransaction();
        return handle.createQuery(/* language=SQL */ """
                        INSERT INTO "ASSESSMENT_ORIGIN" ("ANALYSIS_ID", "OWNER", "DECISION_VERSION")
                        VALUES (:analysisId, :owner, CASE WHEN :decisionChanged THEN 1 ELSE 0 END)
                        ON CONFLICT ("ANALYSIS_ID") DO UPDATE
                        SET "OWNER" = EXCLUDED."OWNER"
                          , "LAST_REASON" = NULL
                          , "DECISION_VERSION" = "ASSESSMENT_ORIGIN"."DECISION_VERSION" + CASE
                              WHEN :decisionChanged
                                OR "ASSESSMENT_ORIGIN"."OWNER" IS DISTINCT FROM EXCLUDED."OWNER" THEN 1
                              ELSE 0
                            END
                        RETURNING "DECISION_VERSION"
                        """)
                .bind("analysisId", analysisId)
                .bind("owner", owner.name())
                .bind("decisionChanged", decisionChanged)
                .mapTo(long.class)
                .one();
    }

    /// Reads the origin row. Null means the analysis predates the feature: protected as local, or as policy
    /// when a vulnerability policy wrote it.
    public @Nullable Origin findOrigin(final long analysisId) {
        requireAnalysisId(analysisId);
        return handle.createQuery(/* language=SQL */ """
                        SELECT "OWNER"
                             , "DECISION_VERSION"
                             , "LAST_REASON"
                          FROM "ASSESSMENT_ORIGIN"
                         WHERE "ANALYSIS_ID" = :analysisId
                        """)
                .bind("analysisId", analysisId)
                .map((rs, ctx) -> new Origin(
                        AssessmentOwnership.valueOf(rs.getString("OWNER")),
                        rs.getLong("DECISION_VERSION"),
                        rs.getString("LAST_REASON")))
                .findOne()
                .orElse(null);
    }

    /// Removes copied source trails. Target comments in ANALYSISCOMMENT are left in place.
    public void deleteCopiedContributions(final long analysisId) {
        requireAnalysisId(analysisId);
        requireTransaction();
        handle.createUpdate(/* language=SQL */ """
                        DELETE FROM "ASSESSMENT_SOURCE_CONTRIBUTION"
                         WHERE "TARGET_ANALYSIS_ID" = :analysisId
                        """)
                .bind("analysisId", analysisId)
                .execute();
    }

    /// Labels one project's unlabeled analyses. An existing origin row is left unchanged.
    public int backfillProjectOrigins(final UUID projectUuid) {
        requireNonNull(projectUuid, "projectUuid must not be null");
        requireTransaction();
        return handle.createUpdate(/* language=SQL */ """
                        INSERT INTO "ASSESSMENT_ORIGIN" ("ANALYSIS_ID", "OWNER")
                        SELECT a."ID"
                             , CASE
                                 WHEN a."VULNERABILITY_POLICY_ID" IS NOT NULL THEN 'POLICY'
                                 ELSE 'LOCAL'
                               END
                          FROM "ANALYSIS" AS a
                         INNER JOIN "PROJECT" AS p
                            ON p."ID" = a."PROJECT_ID"
                         WHERE p."UUID" = :projectUuid
                        ON CONFLICT ("ANALYSIS_ID") DO NOTHING
                        """)
                .bind("projectUuid", projectUuid)
                .execute();
    }

    private void requireTransaction() {
        if (!handle.isInTransaction()) {
            throw new IllegalStateException("Assessment origin writes require an active transaction");
        }
    }

    private static void requireAnalysisId(final long analysisId) {
        if (analysisId <= 0) {
            throw new IllegalArgumentException("analysisId must be positive");
        }
    }

    /// Ownership sidecar.
    public record Origin(
            AssessmentOwnership owner,
            long decisionVersion,
            @Nullable String lastReason) {

        public Origin {
            requireNonNull(owner, "owner must not be null");
        }
    }
}
