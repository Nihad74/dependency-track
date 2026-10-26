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

import org.dependencytrack.assessmentsync.AssessmentConsensus.Contributor;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Severity;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.SqlStatement;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/// Target origin, machine fields, and copied source trails. Uses the caller's transaction.
public final class AssessmentProjectionDao {

    private final Handle handle;

    public AssessmentProjectionDao(final Handle handle) {
        this.handle = requireNonNull(handle, "handle must not be null");
    }

    /// Inserts origin or updates it. The version moves only when ownership changes.
    public long upsertOrigin(
            final long analysisId, final AssessmentOwnership owner, final @Nullable String lastReason) {
        requireAnalysisId(analysisId);
        requireNonNull(owner, "owner must not be null");
        requireTransaction();
        return handle.createQuery(/* language=SQL */ """
                        INSERT INTO "ASSESSMENT_ORIGIN" ("ANALYSIS_ID", "OWNER", "LAST_REASON")
                        VALUES (:analysisId, :owner, :lastReason)
                        ON CONFLICT ("ANALYSIS_ID") DO UPDATE
                        SET "OWNER" = EXCLUDED."OWNER"
                          , "LAST_REASON" = EXCLUDED."LAST_REASON"
                          , "DECISION_VERSION" = "ASSESSMENT_ORIGIN"."DECISION_VERSION" + CASE
                              WHEN "ASSESSMENT_ORIGIN"."OWNER" IS DISTINCT FROM EXCLUDED."OWNER" THEN 1
                              ELSE 0
                            END
                        RETURNING "DECISION_VERSION"
                        """)
                .bind("analysisId", analysisId)
                .bind("owner", owner.name())
                .bind("lastReason", lastReason)
                .mapTo(long.class)
                .one();
    }

    /// Reads the origin row. Null means the analysis is protected local state.
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

    /// Increments the origin version by one. The origin row must already exist.
    public long bumpDecisionVersion(final long analysisId) {
        requireAnalysisId(analysisId);
        requireTransaction();
        return handle.createQuery(/* language=SQL */ """
                        UPDATE "ASSESSMENT_ORIGIN"
                           SET "DECISION_VERSION" = "DECISION_VERSION" + 1
                         WHERE "ANALYSIS_ID" = :analysisId
                        RETURNING "DECISION_VERSION"
                        """)
                .bind("analysisId", analysisId)
                .mapTo(long.class)
                .one();
    }

    /// Applies a worker projection. Local and policy rows, and stale versions, are left unchanged.
    public WorkerWriteResult applyWorkerWrite(final WorkerWrite write) {
        requireNonNull(write, "write must not be null");
        requireTransaction();
        final LockedAnalysis locked = lockAnalysis(write.analysisId());
        if (locked == null || locked.owner() == null) {
            return new WorkerWriteResult(WorkerWriteStatus.MISSING, 0);
        }
        if (locked.owner() == AssessmentOwnership.LOCAL || locked.owner() == AssessmentOwnership.POLICY) {
            return new WorkerWriteResult(WorkerWriteStatus.REJECTED_OWNERSHIP, locked.decisionVersion());
        }
        if (locked.decisionVersion() != write.expectedDecisionVersion()) {
            return new WorkerWriteResult(WorkerWriteStatus.REJECTED_VERSION, locked.decisionVersion());
        }

        final boolean versionBump = locked.owner() != write.owner()
                || !locked.decision().equals(write.decision())
                || !Objects.equals(locked.details(), write.details());
        final int updated = updateMachineFields(write);
        if (updated != 1) {
            throw new IllegalStateException("Worker write did not update analysis " + write.analysisId());
        }
        final long version = handle.createQuery(/* language=SQL */ """
                        UPDATE "ASSESSMENT_ORIGIN"
                           SET "OWNER" = :owner
                             , "LAST_REASON" = :lastReason
                             , "DECISION_VERSION" = "DECISION_VERSION" + :versionIncrement
                         WHERE "ANALYSIS_ID" = :analysisId
                           AND "OWNER" IN ('INHERITED', 'NEUTRAL')
                           AND "DECISION_VERSION" = :expectedDecisionVersion
                        RETURNING "DECISION_VERSION"
                        """)
                .bind("analysisId", write.analysisId())
                .bind("owner", write.owner().name())
                .bind("lastReason", write.lastReason())
                .bind("versionIncrement", versionBump ? 1 : 0)
                .bind("expectedDecisionVersion", write.expectedDecisionVersion())
                .mapTo(long.class)
                .findOne()
                .orElseThrow(() -> new IllegalStateException(
                        "Worker write lost the origin guard for analysis " + write.analysisId()));
        replaceContributions(write);
        return new WorkerWriteResult(WorkerWriteStatus.APPLIED, version);
    }

    public @Nullable StoredProjection load(final long analysisId) {
        requireAnalysisId(analysisId);
        final StoredProjection header = handle.createQuery(/* language=SQL */ """
                        SELECT a."ID"
                             , a."STATE"
                             , a."JUSTIFICATION"
                             , a."RESPONSE"
                             , a."SUPPRESSED"
                             , a."SEVERITY"::text AS "SEVERITY"
                             , a."CVSSV2VECTOR"
                             , a."CVSSV2SCORE"
                             , a."CVSSV3VECTOR"
                             , a."CVSSV3SCORE"
                             , a."CVSSV4VECTOR"
                             , a."CVSSV4SCORE"
                             , a."OWASPVECTOR"
                             , a."OWASPSCORE"
                             , a."DETAILS"
                             , a."VULNERABILITY_POLICY_ID"
                             , o."OWNER"
                             , o."DECISION_VERSION"
                             , o."LAST_REASON"
                          FROM "ANALYSIS" AS a
                          LEFT JOIN "ASSESSMENT_ORIGIN" AS o
                            ON o."ANALYSIS_ID" = a."ID"
                         WHERE a."ID" = :analysisId
                        """)
                .bind("analysisId", analysisId)
                .map((rs, ctx) -> new StoredProjection(
                        rs.getLong("ID"),
                        readOrigin(rs),
                        readDecision(rs),
                        rs.getString("DETAILS"),
                        nullableLong(rs, "VULNERABILITY_POLICY_ID"),
                        List.of()))
                .findOne()
                .orElse(null);
        if (header == null) {
            return null;
        }
        return new StoredProjection(
                header.analysisId(),
                header.origin(),
                header.decision(),
                header.details(),
                header.policyId(),
                loadContributions(analysisId));
    }

    /// Labels existing analyses without replacing a row written by a concurrent writer.
    public @Nullable UUID backfillOrigins(final @Nullable UUID projectUuidKeyset, final int limit) {
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be positive");
        }
        requireTransaction();
        final UUID cursor =
                projectUuidKeyset == null ? UUID.fromString("00000000-0000-0000-0000-000000000000") : projectUuidKeyset;
        final BackfillPage page = handle.createQuery(/* language=SQL */ """
                        WITH projects AS (
                          SELECT "ID"
                               , "UUID"
                            FROM "PROJECT"
                           WHERE (:hasCursor = FALSE OR "UUID" > :cursor)
                           ORDER BY "UUID"
                           LIMIT :limit
                        ),
                        inserted AS (
                          INSERT INTO "ASSESSMENT_ORIGIN" ("ANALYSIS_ID", "OWNER")
                          SELECT a."ID"
                               , CASE
                                   WHEN a."VULNERABILITY_POLICY_ID" IS NOT NULL THEN 'POLICY'
                                   ELSE 'LOCAL'
                                 END
                            FROM "ANALYSIS" AS a
                           INNER JOIN projects AS p
                              ON p."ID" = a."PROJECT_ID"
                          ON CONFLICT ("ANALYSIS_ID") DO NOTHING
                          RETURNING "ANALYSIS_ID"
                        )
                        SELECT (SELECT "UUID" FROM projects ORDER BY "UUID" DESC LIMIT 1) AS next_cursor
                             , (SELECT COUNT(*) FROM projects) AS project_count
                             , (SELECT COUNT(*) FROM inserted) AS inserted_count
                        """)
                .bind("hasCursor", projectUuidKeyset != null)
                .bind("cursor", cursor)
                .bind("limit", limit)
                .map((rs, ctx) -> new BackfillPage(rs.getObject("next_cursor", UUID.class), rs.getInt("project_count")))
                .one();
        if (page.projectCount() < limit) {
            return null;
        }
        return page.nextCursor();
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

    /// Resets worker-owned inherited projections on one project to neutral.
    ///
    /// Local, policy, and neutral rows are not updated. Comments in {@code ANALYSISCOMMENT} stay.
    /// Copied source trails for the withdrawn rows are removed.
    public int withdrawInherited(final UUID projectUuid) {
        requireNonNull(projectUuid, "projectUuid must not be null");
        requireTransaction();
        final AssessmentDecision neutral = AssessmentDecision.neutral();
        final String details = null;
        final Long policyId = null;
        return bindDecision(handle.createQuery(/* language=SQL */ """
                                WITH victims AS (
                                  SELECT a."ID"
                                    FROM "ANALYSIS" AS a
                                   INNER JOIN "PROJECT" AS p
                                      ON p."ID" = a."PROJECT_ID"
                                   INNER JOIN "ASSESSMENT_ORIGIN" AS o
                                      ON o."ANALYSIS_ID" = a."ID"
                                   WHERE p."UUID" = :projectUuid
                                     AND o."OWNER" = 'INHERITED'
                                ),
                                cleared AS (
                                  UPDATE "ANALYSIS" AS a
                                     SET "STATE" = :state
                                       , "JUSTIFICATION" = :justification
                                       , "RESPONSE" = :response
                                       , "SUPPRESSED" = :suppressed
                                       , "SEVERITY" = CAST(:severity AS severity)
                                       , "CVSSV2VECTOR" = :cvssV2Vector
                                       , "CVSSV2SCORE" = :cvssV2Score
                                       , "CVSSV3VECTOR" = :cvssV3Vector
                                       , "CVSSV3SCORE" = :cvssV3Score
                                       , "CVSSV4VECTOR" = :cvssV4Vector
                                       , "CVSSV4SCORE" = :cvssV4Score
                                       , "OWASPVECTOR" = :owaspVector
                                       , "OWASPSCORE" = :owaspScore
                                       , "DETAILS" = :details
                                       , "VULNERABILITY_POLICY_ID" = :policyId
                                   WHERE a."ID" IN (SELECT "ID" FROM victims)
                                  RETURNING a."ID"
                                ),
                                relabeled AS (
                                  UPDATE "ASSESSMENT_ORIGIN" AS o
                                     SET "OWNER" = 'NEUTRAL'
                                       , "LAST_REASON" = 'WITHDRAW'
                                       , "DECISION_VERSION" = "DECISION_VERSION" + 1
                                   WHERE o."ANALYSIS_ID" IN (SELECT "ID" FROM cleared)
                                     AND o."OWNER" = 'INHERITED'
                                  RETURNING o."ANALYSIS_ID"
                                ),
                                dropped AS (
                                  DELETE FROM "ASSESSMENT_SOURCE_CONTRIBUTION"
                                   WHERE "TARGET_ANALYSIS_ID" IN (SELECT "ANALYSIS_ID" FROM relabeled)
                                  RETURNING "TARGET_ANALYSIS_ID"
                                )
                                SELECT COUNT(*)::int
                                  FROM relabeled
                                 WHERE (SELECT COUNT(*) FROM dropped) >= 0
                                """), neutral)
                .bind("projectUuid", projectUuid)
                .bind("details", details)
                .bind("policyId", policyId)
                .mapTo(int.class)
                .one();
    }

    private int updateMachineFields(final WorkerWrite write) {
        final AssessmentDecision decision = write.decision();
        return bindDecision(handle.createUpdate(/* language=SQL */ """
                                UPDATE "ANALYSIS" AS a
                                   SET "STATE" = :state
                                     , "JUSTIFICATION" = :justification
                                     , "RESPONSE" = :response
                                     , "SUPPRESSED" = :suppressed
                                     , "SEVERITY" = CAST(:severity AS severity)
                                     , "CVSSV2VECTOR" = :cvssV2Vector
                                     , "CVSSV2SCORE" = :cvssV2Score
                                     , "CVSSV3VECTOR" = :cvssV3Vector
                                     , "CVSSV3SCORE" = :cvssV3Score
                                     , "CVSSV4VECTOR" = :cvssV4Vector
                                     , "CVSSV4SCORE" = :cvssV4Score
                                     , "OWASPVECTOR" = :owaspVector
                                     , "OWASPSCORE" = :owaspScore
                                     , "DETAILS" = :details
                                     , "VULNERABILITY_POLICY_ID" = :policyId
                                 WHERE a."ID" = :analysisId
                                   AND EXISTS (
                                     SELECT 1
                                       FROM "ASSESSMENT_ORIGIN" AS o
                                      WHERE o."ANALYSIS_ID" = a."ID"
                                        AND o."OWNER" IN ('INHERITED', 'NEUTRAL')
                                        AND o."DECISION_VERSION" = :expectedDecisionVersion
                                   )
                                """), decision)
                .bind("analysisId", write.analysisId())
                .bind("details", write.details())
                .bind("policyId", write.policyId())
                .bind("expectedDecisionVersion", write.expectedDecisionVersion())
                .execute();
    }

    private void replaceContributions(final WorkerWrite write) {
        final List<SourceContributionWrite> contributions = write.contributions();
        if (!contributions.isEmpty()) {
            final var sourceProjects = new UUID[contributions.size()];
            final var sourceComponents = new UUID[contributions.size()];
            final var sourceVulnerabilities = new UUID[contributions.size()];
            final var sourceAnalyses = new long[contributions.size()];
            final var sourceDetails = new @Nullable String[contributions.size()];
            for (int i = 0; i < contributions.size(); i++) {
                final SourceContributionWrite contribution = contributions.get(i);
                sourceProjects[i] = contribution.contributor().sourceProjectUuid();
                sourceComponents[i] = contribution.contributor().sourceComponentUuid();
                sourceVulnerabilities[i] = contribution.contributor().sourceVulnerabilityUuid();
                sourceAnalyses[i] = contribution.contributor().sourceAnalysisId();
                sourceDetails[i] = contribution.sourceDetails();
            }
            handle.createUpdate(/* language=SQL */ """
                            INSERT INTO "ASSESSMENT_SOURCE_CONTRIBUTION" (
                              "TARGET_ANALYSIS_ID"
                            , "SOURCE_PROJECT_UUID"
                            , "SOURCE_COMPONENT_UUID"
                            , "SOURCE_VULNERABILITY_UUID"
                            , "SOURCE_ANALYSIS_ID"
                            , "SOURCE_DETAILS"
                            , "LAST_SYNC_AT"
                            )
                            SELECT :analysisId
                                 , t.source_project
                                 , t.source_component
                                 , t.source_vulnerability
                                 , t.source_analysis
                                 , t.source_details
                                 , now()
                              FROM UNNEST(
                                     :sourceProjects
                                   , :sourceComponents
                                   , :sourceVulnerabilities
                                   , :sourceAnalyses
                                   , :sourceDetails
                                   ) AS t(
                                     source_project
                                   , source_component
                                   , source_vulnerability
                                   , source_analysis
                                   , source_details
                                   )
                            ON CONFLICT ("TARGET_ANALYSIS_ID", "SOURCE_PROJECT_UUID", "SOURCE_ANALYSIS_ID") DO UPDATE
                            SET "SOURCE_COMPONENT_UUID" = EXCLUDED."SOURCE_COMPONENT_UUID"
                              , "SOURCE_VULNERABILITY_UUID" = EXCLUDED."SOURCE_VULNERABILITY_UUID"
                              , "SOURCE_DETAILS" = EXCLUDED."SOURCE_DETAILS"
                              , "LAST_SYNC_AT" = now()
                            """)
                    .bind("analysisId", write.analysisId())
                    .bind("sourceProjects", sourceProjects)
                    .bind("sourceComponents", sourceComponents)
                    .bind("sourceVulnerabilities", sourceVulnerabilities)
                    .bind("sourceAnalyses", sourceAnalyses)
                    .bind("sourceDetails", sourceDetails)
                    .execute();
        }

        if (contributions.isEmpty()) {
            handle.createUpdate(/* language=SQL */ """
                            DELETE FROM "ASSESSMENT_SOURCE_CONTRIBUTION"
                             WHERE "TARGET_ANALYSIS_ID" = :analysisId
                            """)
                    .bind("analysisId", write.analysisId())
                    .execute();
            return;
        }

        final var keptProjects = new UUID[contributions.size()];
        final var keptAnalyses = new long[contributions.size()];
        for (int i = 0; i < contributions.size(); i++) {
            keptProjects[i] = contributions.get(i).contributor().sourceProjectUuid();
            keptAnalyses[i] = contributions.get(i).contributor().sourceAnalysisId();
        }
        handle.createUpdate(/* language=SQL */ """
                        DELETE FROM "ASSESSMENT_SOURCE_CONTRIBUTION" AS c
                         WHERE c."TARGET_ANALYSIS_ID" = :analysisId
                           AND NOT EXISTS (
                             SELECT 1
                               FROM UNNEST(:keptProjects, :keptAnalyses) AS t(source_project, source_analysis)
                              WHERE t.source_project = c."SOURCE_PROJECT_UUID"
                                AND t.source_analysis = c."SOURCE_ANALYSIS_ID"
                           )
                        """)
                .bind("analysisId", write.analysisId())
                .bind("keptProjects", keptProjects)
                .bind("keptAnalyses", keptAnalyses)
                .execute();

        final var commentInserts = new ArrayList<CommentInsert>();
        for (final SourceContributionWrite contribution : contributions) {
            for (final SourceCommentWrite comment : contribution.comments()) {
                commentInserts.add(new CommentInsert(
                        contribution.contributor().sourceProjectUuid(),
                        contribution.contributor().sourceAnalysisId(),
                        comment));
            }
        }
        if (commentInserts.isEmpty()) {
            handle.createUpdate(/* language=SQL */ """
                            DELETE FROM "ASSESSMENT_SOURCE_COMMENT"
                             WHERE "TARGET_ANALYSIS_ID" = :analysisId
                            """)
                    .bind("analysisId", write.analysisId())
                    .execute();
            return;
        }

        final var commentProjects = new UUID[commentInserts.size()];
        final var commentAnalyses = new long[commentInserts.size()];
        final var commentIds = new long[commentInserts.size()];
        final var commentTexts = new String[commentInserts.size()];
        final var commenters = new @Nullable String[commentInserts.size()];
        final var commentTimestamps = new Instant[commentInserts.size()];
        for (int i = 0; i < commentInserts.size(); i++) {
            final CommentInsert commentInsert = commentInserts.get(i);
            commentProjects[i] = commentInsert.sourceProjectUuid();
            commentAnalyses[i] = commentInsert.sourceAnalysisId();
            commentIds[i] = commentInsert.comment().sourceCommentId();
            commentTexts[i] = commentInsert.comment().comment();
            commenters[i] = commentInsert.comment().commenter();
            commentTimestamps[i] = commentInsert.comment().originalTimestamp();
        }
        handle.createUpdate(/* language=SQL */ """
                        INSERT INTO "ASSESSMENT_SOURCE_COMMENT" (
                          "TARGET_ANALYSIS_ID"
                        , "SOURCE_PROJECT_UUID"
                        , "SOURCE_ANALYSIS_ID"
                        , "SOURCE_COMMENT_ID"
                        , "COMMENT"
                        , "COMMENTER"
                        , "ORIGINAL_TIMESTAMP"
                        )
                        SELECT :analysisId
                             , t.source_project
                             , t.source_analysis
                             , t.source_comment_id
                             , t.comment
                             , t.commenter
                             , t.original_timestamp
                          FROM UNNEST(
                                 :sourceProjects
                               , :sourceAnalyses
                               , :sourceCommentIds
                               , :comments
                               , :commenters
                               , :originalTimestamps
                               ) AS t(
                                 source_project
                               , source_analysis
                               , source_comment_id
                               , comment
                               , commenter
                               , original_timestamp
                               )
                        ON CONFLICT (
                          "TARGET_ANALYSIS_ID"
                        , "SOURCE_PROJECT_UUID"
                        , "SOURCE_ANALYSIS_ID"
                        , "SOURCE_COMMENT_ID"
                        ) DO UPDATE
                        SET "COMMENT" = EXCLUDED."COMMENT"
                          , "COMMENTER" = EXCLUDED."COMMENTER"
                        """)
                .registerArrayType(Instant.class, "timestamptz")
                .bind("analysisId", write.analysisId())
                .bind("sourceProjects", commentProjects)
                .bind("sourceAnalyses", commentAnalyses)
                .bind("sourceCommentIds", commentIds)
                .bind("comments", commentTexts)
                .bind("commenters", commenters)
                .bind("originalTimestamps", commentTimestamps)
                .execute();
        handle.createUpdate(/* language=SQL */ """
                        DELETE FROM "ASSESSMENT_SOURCE_COMMENT" AS c
                         WHERE c."TARGET_ANALYSIS_ID" = :analysisId
                           AND NOT EXISTS (
                             SELECT 1
                               FROM UNNEST(:sourceProjects, :sourceAnalyses, :sourceCommentIds)
                                 AS t(source_project, source_analysis, source_comment_id)
                              WHERE t.source_project = c."SOURCE_PROJECT_UUID"
                                AND t.source_analysis = c."SOURCE_ANALYSIS_ID"
                                AND t.source_comment_id = c."SOURCE_COMMENT_ID"
                           )
                        """)
                .bind("analysisId", write.analysisId())
                .bind("sourceProjects", commentProjects)
                .bind("sourceAnalyses", commentAnalyses)
                .bind("sourceCommentIds", commentIds)
                .execute();
    }

    private List<StoredContribution> loadContributions(final long analysisId) {
        final List<StoredContribution> contributions = handle.createQuery(/* language=SQL */ """
                        SELECT "SOURCE_PROJECT_UUID"
                             , "SOURCE_COMPONENT_UUID"
                             , "SOURCE_VULNERABILITY_UUID"
                             , "SOURCE_ANALYSIS_ID"
                             , "SOURCE_DETAILS"
                             , "LAST_SYNC_AT"
                          FROM "ASSESSMENT_SOURCE_CONTRIBUTION"
                         WHERE "TARGET_ANALYSIS_ID" = :analysisId
                         ORDER BY "SOURCE_PROJECT_UUID", "SOURCE_ANALYSIS_ID"
                        """)
                .bind("analysisId", analysisId)
                .map((rs, ctx) -> new StoredContribution(
                        new Contributor(
                                rs.getObject("SOURCE_PROJECT_UUID", UUID.class),
                                rs.getObject("SOURCE_COMPONENT_UUID", UUID.class),
                                rs.getObject("SOURCE_VULNERABILITY_UUID", UUID.class),
                                rs.getLong("SOURCE_ANALYSIS_ID")),
                        rs.getString("SOURCE_DETAILS"),
                        readInstant(rs, "LAST_SYNC_AT"),
                        List.of()))
                .list();
        if (contributions.isEmpty()) {
            return List.of();
        }
        final var commentsByContribution = new LinkedHashMap<ContributionKey, List<StoredComment>>();
        handle.createQuery(/* language=SQL */ """
                        SELECT "SOURCE_PROJECT_UUID"
                             , "SOURCE_ANALYSIS_ID"
                             , "SOURCE_COMMENT_ID"
                             , "COMMENT"
                             , "COMMENTER"
                             , "ORIGINAL_TIMESTAMP"
                          FROM "ASSESSMENT_SOURCE_COMMENT"
                         WHERE "TARGET_ANALYSIS_ID" = :analysisId
                         ORDER BY "SOURCE_PROJECT_UUID", "SOURCE_ANALYSIS_ID", "SOURCE_COMMENT_ID"
                        """)
                .bind("analysisId", analysisId)
                .map((rs, ctx) -> {
                    final var key = new ContributionKey(
                            rs.getObject("SOURCE_PROJECT_UUID", UUID.class), rs.getLong("SOURCE_ANALYSIS_ID"));
                    commentsByContribution
                            .computeIfAbsent(key, ignored -> new ArrayList<>())
                            .add(new StoredComment(
                                    rs.getLong("SOURCE_COMMENT_ID"),
                                    rs.getString("COMMENT"),
                                    rs.getString("COMMENTER"),
                                    readInstant(rs, "ORIGINAL_TIMESTAMP")));
                    return key;
                })
                .list();
        return contributions.stream()
                .map(contribution -> new StoredContribution(
                        contribution.contributor(),
                        contribution.sourceDetails(),
                        contribution.lastSyncAt(),
                        List.copyOf(commentsByContribution.getOrDefault(
                                new ContributionKey(
                                        contribution.contributor().sourceProjectUuid(),
                                        contribution.contributor().sourceAnalysisId()),
                                List.of()))))
                .toList();
    }

    private @Nullable LockedAnalysis lockAnalysis(final long analysisId) {
        final MachineRow machine = handle.createQuery(/* language=SQL */ """
                        SELECT "ID"
                             , "STATE"
                             , "JUSTIFICATION"
                             , "RESPONSE"
                             , "SUPPRESSED"
                             , "SEVERITY"::text AS "SEVERITY"
                             , "CVSSV2VECTOR"
                             , "CVSSV2SCORE"
                             , "CVSSV3VECTOR"
                             , "CVSSV3SCORE"
                             , "CVSSV4VECTOR"
                             , "CVSSV4SCORE"
                             , "OWASPVECTOR"
                             , "OWASPSCORE"
                             , "DETAILS"
                             , "VULNERABILITY_POLICY_ID"
                          FROM "ANALYSIS"
                         WHERE "ID" = :analysisId
                           FOR UPDATE
                        """)
                .bind("analysisId", analysisId)
                .map((rs, ctx) -> new MachineRow(
                        readDecision(rs), rs.getString("DETAILS"), nullableLong(rs, "VULNERABILITY_POLICY_ID")))
                .findOne()
                .orElse(null);
        if (machine == null) {
            return null;
        }
        final Origin origin = handle.createQuery(/* language=SQL */ """
                        SELECT "OWNER"
                             , "DECISION_VERSION"
                             , "LAST_REASON"
                          FROM "ASSESSMENT_ORIGIN"
                         WHERE "ANALYSIS_ID" = :analysisId
                           FOR UPDATE
                        """)
                .bind("analysisId", analysisId)
                .map((rs, ctx) -> new Origin(
                        AssessmentOwnership.valueOf(rs.getString("OWNER")),
                        rs.getLong("DECISION_VERSION"),
                        rs.getString("LAST_REASON")))
                .findOne()
                .orElse(null);
        if (origin == null) {
            return new LockedAnalysis(null, 0, null, machine.decision(), machine.details(), machine.policyId());
        }
        return new LockedAnalysis(
                origin.owner(),
                origin.decisionVersion(),
                origin.lastReason(),
                machine.decision(),
                machine.details(),
                machine.policyId());
    }

    private static <S extends SqlStatement<S>> S bindDecision(final S statement, final AssessmentDecision decision) {
        return statement
                .bind("state", decision.state().name())
                .bind("justification", decision.justification().name())
                .bind("response", decision.response().name())
                .bind("suppressed", decision.suppressed())
                .bind(
                        "severity",
                        decision.severity() == null ? null : decision.severity().name())
                .bind("cvssV2Vector", decision.cvssV2Vector())
                .bind("cvssV2Score", decision.cvssV2Score())
                .bind("cvssV3Vector", decision.cvssV3Vector())
                .bind("cvssV3Score", decision.cvssV3Score())
                .bind("cvssV4Vector", decision.cvssV4Vector())
                .bind("cvssV4Score", decision.cvssV4Score())
                .bind("owaspVector", decision.owaspVector())
                .bind("owaspScore", decision.owaspScore());
    }

    private static AssessmentDecision readDecision(final ResultSet rs) throws SQLException {
        final String severity = rs.getString("SEVERITY");
        final String justification = rs.getString("JUSTIFICATION");
        final String response = rs.getString("RESPONSE");
        return AssessmentDecision.of(
                AnalysisState.valueOf(rs.getString("STATE")),
                justification == null ? null : AnalysisJustification.valueOf(justification),
                response == null ? null : AnalysisResponse.valueOf(response),
                rs.getBoolean("SUPPRESSED"),
                severity == null ? null : Severity.valueOf(severity),
                rs.getString("CVSSV2VECTOR"),
                rs.getBigDecimal("CVSSV2SCORE"),
                rs.getString("CVSSV3VECTOR"),
                rs.getBigDecimal("CVSSV3SCORE"),
                rs.getString("CVSSV4VECTOR"),
                rs.getBigDecimal("CVSSV4SCORE"),
                rs.getString("OWASPVECTOR"),
                rs.getBigDecimal("OWASPSCORE"));
    }

    private static @Nullable Origin readOrigin(final ResultSet rs) throws SQLException {
        final String owner = rs.getString("OWNER");
        if (owner == null) {
            return null;
        }
        return new Origin(
                AssessmentOwnership.valueOf(owner), rs.getLong("DECISION_VERSION"), rs.getString("LAST_REASON"));
    }

    private static @Nullable Long nullableLong(final ResultSet rs, final String column) throws SQLException {
        final long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    private static Instant readInstant(final ResultSet rs, final String column) throws SQLException {
        final OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
        return requireNonNull(value, column).toInstant();
    }

    private void requireTransaction() {
        if (!handle.isInTransaction()) {
            throw new IllegalStateException("Assessment projection writes require an active transaction");
        }
    }

    private static void requireAnalysisId(final long analysisId) {
        if (analysisId <= 0) {
            throw new IllegalArgumentException("analysisId must be positive");
        }
    }

    /// Why a worker write did not change the target row.
    public enum WorkerWriteStatus {
        APPLIED,
        REJECTED_OWNERSHIP,
        REJECTED_VERSION,
        MISSING
    }

    /// Result of a worker write. {@code decisionVersion} is the version after a successful write, or the current one.
    public record WorkerWriteResult(WorkerWriteStatus status, long decisionVersion) {

        public WorkerWriteResult {
            requireNonNull(status, "status must not be null");
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

    /// Current stored projection, including copied source trails.
    public record StoredProjection(
            long analysisId,
            @Nullable Origin origin,
            AssessmentDecision decision,
            @Nullable String details,
            @Nullable Long policyId,
            List<StoredContribution> contributions) {

        public StoredProjection {
            requireNonNull(decision, "decision must not be null");
            requireNonNull(contributions, "contributions must not be null");
            contributions = List.copyOf(contributions);
        }
    }

    /// One copied source, including its own details and original comments.
    public record StoredContribution(
            Contributor contributor, @Nullable String sourceDetails, Instant lastSyncAt, List<StoredComment> comments) {

        public StoredContribution {
            requireNonNull(contributor, "contributor must not be null");
            requireNonNull(lastSyncAt, "lastSyncAt must not be null");
            requireNonNull(comments, "comments must not be null");
            comments = List.copyOf(comments);
        }
    }

    /// Copied source comment. {@code originalTimestamp} is the source timestamp, not the copy time.
    public record StoredComment(
            long sourceCommentId, String comment, @Nullable String commenter, Instant originalTimestamp) {

        public StoredComment {
            requireNonNull(comment, "comment must not be null");
            requireNonNull(originalTimestamp, "originalTimestamp must not be null");
        }
    }

    /// Desired worker projection. Ownership {@code LOCAL} and {@code POLICY} are not worker-assigned.
    public record WorkerWrite(
            long analysisId,
            AssessmentOwnership owner,
            AssessmentDecision decision,
            @Nullable String details,
            @Nullable Long policyId,
            @Nullable String lastReason,
            long expectedDecisionVersion,
            List<SourceContributionWrite> contributions) {

        public WorkerWrite {
            if (analysisId <= 0) {
                throw new IllegalArgumentException("analysisId must be positive");
            }
            requireNonNull(owner, "owner must not be null");
            requireNonNull(decision, "decision must not be null");
            if (expectedDecisionVersion < 0) {
                throw new IllegalArgumentException("expectedDecisionVersion must not be negative");
            }
            if (owner == AssessmentOwnership.LOCAL || owner == AssessmentOwnership.POLICY) {
                throw new IllegalArgumentException("Worker writes cannot assign " + owner);
            }
            requireNonNull(contributions, "contributions must not be null");
            final var identities = new LinkedHashMap<ContributionKey, ContributionKey>();
            for (final SourceContributionWrite contribution : contributions) {
                requireNonNull(contribution, "contribution must not be null");
                final var key = new ContributionKey(
                        contribution.contributor().sourceProjectUuid(),
                        contribution.contributor().sourceAnalysisId());
                if (identities.putIfAbsent(key, key) != null) {
                    throw new IllegalArgumentException("Duplicate source contribution " + key.sourceProjectUuid());
                }
            }
            contributions = List.copyOf(contributions);
        }
    }

    /// Desired source trail. Details belong to this contributor only.
    public record SourceContributionWrite(
            Contributor contributor, @Nullable String sourceDetails, List<SourceCommentWrite> comments) {

        public SourceContributionWrite {
            requireNonNull(contributor, "contributor must not be null");
            requireNonNull(comments, "comments must not be null");
            final var ids = new LinkedHashMap<Long, Long>();
            for (final SourceCommentWrite comment : comments) {
                requireNonNull(comment, "comment must not be null");
                if (ids.putIfAbsent(comment.sourceCommentId(), comment.sourceCommentId()) != null) {
                    throw new IllegalArgumentException("Duplicate source comment " + comment.sourceCommentId());
                }
            }
            comments = List.copyOf(comments);
        }
    }

    /// Desired copied comment. The original timestamp is kept when the same source comment is written again.
    public record SourceCommentWrite(
            long sourceCommentId, String comment, @Nullable String commenter, Instant originalTimestamp) {

        public SourceCommentWrite {
            requireNonNull(comment, "comment must not be null");
            requireNonNull(originalTimestamp, "originalTimestamp must not be null");
        }
    }

    private record LockedAnalysis(
            @Nullable AssessmentOwnership owner,
            long decisionVersion,
            @Nullable String lastReason,
            AssessmentDecision decision,
            @Nullable String details,
            @Nullable Long policyId) {}

    private record MachineRow(
            AssessmentDecision decision,
            @Nullable String details,
            @Nullable Long policyId) {}

    private record BackfillPage(@Nullable UUID nextCursor, int projectCount) {}

    private record ContributionKey(UUID sourceProjectUuid, long sourceAnalysisId) {}

    private record CommentInsert(UUID sourceProjectUuid, long sourceAnalysisId, SourceCommentWrite comment) {}
}
