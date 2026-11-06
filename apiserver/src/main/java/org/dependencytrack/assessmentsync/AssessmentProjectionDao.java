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
import org.dependencytrack.assessmentsync.AssessmentOriginDao.Origin;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Severity;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.SqlStatement;
import org.jspecify.annotations.Nullable;

import java.math.BigDecimal;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.assessmentsync.AssessmentOriginDao.readOrigin;
import static org.dependencytrack.assessmentsync.DaoSupport.nullableLong;
import static org.dependencytrack.assessmentsync.DaoSupport.readInstant;
import static org.dependencytrack.assessmentsync.DaoSupport.requirePositive;
import static org.dependencytrack.assessmentsync.DaoSupport.requireTransaction;

/**
 * Worker projections: machine fields and copied source trails on target analyses. Ownership records
 * written by authored writers live in {@link AssessmentOriginDao}. Uses the caller's transaction.
 */
public final class AssessmentProjectionDao {

    private final Handle handle;

    public AssessmentProjectionDao(final Handle handle) {
        this.handle = requireNonNull(handle, "handle must not be null");
    }

    /**
     * Applies worker projections in a fixed number of statements. Returns one result per write, in order.
     * Local and policy rows, and stale versions, are left unchanged.
     */
    public List<WorkerWriteResult> applyWorkerWrites(final List<WorkerWrite> writes) {
        requireTransaction(handle);
        if (writes.isEmpty()) {
            return List.of();
        }
        final var analysisIds = new LinkedHashSet<Long>();
        for (final WorkerWrite write : writes) {
            if (!analysisIds.add(write.analysisId())) {
                throw new IllegalArgumentException("Duplicate worker write for analysis " + write.analysisId());
            }
        }
        final Map<Long, LockedAnalysis> locked = lockAnalyses(analysisIds);

        final var results = new ArrayList<WorkerWriteResult>(writes.size());
        final var accepted = new ArrayList<AcceptedWrite>(writes.size());
        for (final WorkerWrite write : writes) {
            final LockedAnalysis current = locked.get(write.analysisId());
            if (current == null || current.owner() == null) {
                results.add(new WorkerWriteResult(WorkerWriteStatus.MISSING, 0));
            } else if (AssessmentOwnership.authored(current.owner())) {
                results.add(new WorkerWriteResult(WorkerWriteStatus.REJECTED_OWNERSHIP, current.decisionVersion()));
            } else if (current.decisionVersion() != write.expectedDecisionVersion()) {
                results.add(new WorkerWriteResult(WorkerWriteStatus.REJECTED_VERSION, current.decisionVersion()));
            } else {
                final boolean versionBump = current.owner() != write.owner()
                        || !current.decision().equals(write.decision())
                        || current.details() != null;
                accepted.add(new AcceptedWrite(results.size(), write, versionBump));
                results.add(null);
            }
        }
        if (accepted.isEmpty()) {
            return List.copyOf(results);
        }

        updateMachineFields(accepted);
        final Map<Long, Long> versions = updateOrigins(accepted);
        for (final AcceptedWrite write : accepted) {
            final Long version = versions.get(write.write().analysisId());
            if (version == null) {
                throw new IllegalStateException("Worker write lost the origin guard for analysis "
                        + write.write().analysisId());
            }
            results.set(write.index(), new WorkerWriteResult(WorkerWriteStatus.APPLIED, version));
        }
        replaceContributions(accepted);
        return List.copyOf(results);
    }

    /**
     * Applies one worker projection. Local and policy rows, and stale versions, are left unchanged.
     */
    public WorkerWriteResult applyWorkerWrite(final WorkerWrite write) {
        return applyWorkerWrites(List.of(write)).getFirst();
    }

    public @Nullable StoredProjection load(final long analysisId) {
        requirePositive(analysisId, "analysisId");
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

    /**
     * Resets worker-owned inherited projections on one project to neutral.
     *
     * <p>Local, policy, and neutral rows are not updated. Comments in {@code ANALYSISCOMMENT} stay.
     * Every copied source trail on the project is removed, including provenance kept on local rows.
     */
    public int withdrawInherited(final UUID projectUuid) {
        requireNonNull(projectUuid, "projectUuid must not be null");
        requireTransaction(handle);
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
                                       , "LAST_REASON" = 'WITHDRAWN'
                                       , "DECISION_VERSION" = "DECISION_VERSION" + 1
                                   WHERE o."ANALYSIS_ID" IN (SELECT "ID" FROM cleared)
                                     AND o."OWNER" = 'INHERITED'
                                  RETURNING o."ANALYSIS_ID"
                                ),
                                dropped AS (
                                  DELETE FROM "ASSESSMENT_SOURCE_CONTRIBUTION" AS c
                                   USING "ANALYSIS" AS a
                                       , "PROJECT" AS p
                                   WHERE a."ID" = c."TARGET_ANALYSIS_ID"
                                     AND p."ID" = a."PROJECT_ID"
                                     AND p."UUID" = :projectUuid
                                  RETURNING c."TARGET_ANALYSIS_ID"
                                )
                                SELECT COUNT(*)::int
                                  FROM relabeled
                                """), neutral)
                .bind("projectUuid", projectUuid)
                .bind("details", details)
                .bind("policyId", policyId)
                .mapTo(int.class)
                .one();
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

    /**
     * Locks the analysis rows. The origins are not locked: every origin writer holds the project lock, as the
     * worker does, and the origin update still checks the version it read.
     */
    private Map<Long, LockedAnalysis> lockAnalyses(final Collection<Long> analysisIds) {
        final var locked = new LinkedHashMap<Long, LockedAnalysis>();
        handle.createQuery(/* language=SQL */ """
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
                             , o."OWNER"
                             , o."DECISION_VERSION"
                             , o."LAST_REASON"
                          FROM "ANALYSIS" AS a
                          LEFT JOIN "ASSESSMENT_ORIGIN" AS o
                            ON o."ANALYSIS_ID" = a."ID"
                         WHERE a."ID" = ANY(:analysisIds)
                         ORDER BY a."ID"
                           FOR UPDATE OF a
                        """)
                .bind(
                        "analysisIds",
                        analysisIds.stream().mapToLong(Long::longValue).toArray())
                .map((rs, ctx) -> Map.entry(
                        rs.getLong("ID"),
                        new LockedAnalysis(readOrigin(rs), readDecision(rs), rs.getString("DETAILS"))))
                .forEach(entry -> locked.put(entry.getKey(), entry.getValue()));
        return locked;
    }

    private void updateMachineFields(final List<AcceptedWrite> accepted) {
        final int n = accepted.size();
        final var ids = new long[n];
        final var states = new String[n];
        final var justifications = new String[n];
        final var responses = new String[n];
        final var suppressed = new boolean[n];
        final var severities = new @Nullable String[n];
        final var cvssV2Vectors = new @Nullable String[n];
        final var cvssV2Scores = new @Nullable BigDecimal[n];
        final var cvssV3Vectors = new @Nullable String[n];
        final var cvssV3Scores = new @Nullable BigDecimal[n];
        final var cvssV4Vectors = new @Nullable String[n];
        final var cvssV4Scores = new @Nullable BigDecimal[n];
        final var owaspVectors = new @Nullable String[n];
        final var owaspScores = new @Nullable BigDecimal[n];
        for (int i = 0; i < n; i++) {
            final WorkerWrite write = accepted.get(i).write();
            final AssessmentDecision decision = write.decision();
            ids[i] = write.analysisId();
            states[i] = decision.state().name();
            justifications[i] = decision.justification().name();
            responses[i] = decision.response().name();
            suppressed[i] = decision.suppressed();
            severities[i] =
                    decision.severity() == null ? null : decision.severity().name();
            cvssV2Vectors[i] = decision.cvssV2Vector();
            cvssV2Scores[i] = decision.cvssV2Score();
            cvssV3Vectors[i] = decision.cvssV3Vector();
            cvssV3Scores[i] = decision.cvssV3Score();
            cvssV4Vectors[i] = decision.cvssV4Vector();
            cvssV4Scores[i] = decision.cvssV4Score();
            owaspVectors[i] = decision.owaspVector();
            owaspScores[i] = decision.owaspScore();
        }
        handle.createUpdate(/* language=SQL */ """
                        UPDATE "ANALYSIS" AS a
                           SET "STATE" = t.state
                             , "JUSTIFICATION" = t.justification
                             , "RESPONSE" = t.response
                             , "SUPPRESSED" = t.suppressed
                             , "SEVERITY" = t.severity
                             , "CVSSV2VECTOR" = t.cvss_v2_vector
                             , "CVSSV2SCORE" = t.cvss_v2_score
                             , "CVSSV3VECTOR" = t.cvss_v3_vector
                             , "CVSSV3SCORE" = t.cvss_v3_score
                             , "CVSSV4VECTOR" = t.cvss_v4_vector
                             , "CVSSV4SCORE" = t.cvss_v4_score
                             , "OWASPVECTOR" = t.owasp_vector
                             , "OWASPSCORE" = t.owasp_score
                             , "DETAILS" = NULL
                             , "VULNERABILITY_POLICY_ID" = NULL
                          FROM UNNEST(
                                 :ids
                               , :states
                               , :justifications
                               , :responses
                               , :suppressed
                               , CAST(:severities AS severity[])
                               , :cvssV2Vectors
                               , :cvssV2Scores
                               , :cvssV3Vectors
                               , :cvssV3Scores
                               , :cvssV4Vectors
                               , :cvssV4Scores
                               , :owaspVectors
                               , :owaspScores
                               ) AS t(
                                 id
                               , state
                               , justification
                               , response
                               , suppressed
                               , severity
                               , cvss_v2_vector
                               , cvss_v2_score
                               , cvss_v3_vector
                               , cvss_v3_score
                               , cvss_v4_vector
                               , cvss_v4_score
                               , owasp_vector
                               , owasp_score
                               )
                         WHERE a."ID" = t.id
                        """)
                .registerArrayType(BigDecimal.class, "numeric")
                .bind("ids", ids)
                .bind("states", states)
                .bind("justifications", justifications)
                .bind("responses", responses)
                .bind("suppressed", suppressed)
                .bind("severities", severities)
                .bind("cvssV2Vectors", cvssV2Vectors)
                .bind("cvssV2Scores", cvssV2Scores)
                .bind("cvssV3Vectors", cvssV3Vectors)
                .bind("cvssV3Scores", cvssV3Scores)
                .bind("cvssV4Vectors", cvssV4Vectors)
                .bind("cvssV4Scores", cvssV4Scores)
                .bind("owaspVectors", owaspVectors)
                .bind("owaspScores", owaspScores)
                .execute();
    }

    /**
     * Returns the new version per analysis. A row missing from the result lost the origin guard.
     */
    private Map<Long, Long> updateOrigins(final List<AcceptedWrite> accepted) {
        final int n = accepted.size();
        final var ids = new long[n];
        final var owners = new String[n];
        final var reasons = new @Nullable String[n];
        final var increments = new int[n];
        final var expectedVersions = new long[n];
        for (int i = 0; i < n; i++) {
            final AcceptedWrite accept = accepted.get(i);
            final WorkerWrite write = accept.write();
            ids[i] = write.analysisId();
            owners[i] = write.owner().name();
            reasons[i] = write.lastReason() == null ? null : write.lastReason().name();
            increments[i] = accept.versionBump() ? 1 : 0;
            expectedVersions[i] = write.expectedDecisionVersion();
        }
        final var versions = new LinkedHashMap<Long, Long>();
        handle.createQuery(/* language=SQL */ """
                        UPDATE "ASSESSMENT_ORIGIN" AS o
                           SET "OWNER" = t.owner
                             , "LAST_REASON" = t.reason
                             , "DECISION_VERSION" = o."DECISION_VERSION" + t.increment
                          FROM UNNEST(:ids, :owners, :reasons, :increments, :expectedVersions)
                            AS t(id, owner, reason, increment, expected_version)
                         WHERE o."ANALYSIS_ID" = t.id
                           AND o."OWNER" IN ('INHERITED', 'NEUTRAL')
                           AND o."DECISION_VERSION" = t.expected_version
                        RETURNING o."ANALYSIS_ID", o."DECISION_VERSION"
                        """)
                .bind("ids", ids)
                .bind("owners", owners)
                .bind("reasons", reasons)
                .bind("increments", increments)
                .bind("expectedVersions", expectedVersions)
                .map((rs, ctx) -> Map.entry(rs.getLong("ANALYSIS_ID"), rs.getLong("DECISION_VERSION")))
                .forEach(entry -> versions.put(entry.getKey(), entry.getValue()));
        return versions;
    }

    /**
     * Upserts the desired trails of every accepted write, then removes contributions and comments that are no
     * longer desired. A write with no contributions clears its trail.
     */
    private void replaceContributions(final List<AcceptedWrite> accepted) {
        final long[] targetIds =
                accepted.stream().mapToLong(write -> write.write().analysisId()).toArray();
        final var contributionTargets = new ArrayList<Long>();
        final var sourceProjects = new ArrayList<UUID>();
        final var sourceComponents = new ArrayList<UUID>();
        final var sourceVulnerabilities = new ArrayList<UUID>();
        final var sourceAnalyses = new ArrayList<Long>();
        final var sourceDetails = new ArrayList<@Nullable String>();
        final var commentTargets = new ArrayList<Long>();
        final var commentProjects = new ArrayList<UUID>();
        final var commentAnalyses = new ArrayList<Long>();
        final var commentIds = new ArrayList<Long>();
        final var commentTexts = new ArrayList<String>();
        final var commenters = new ArrayList<@Nullable String>();
        final var commentTimestamps = new ArrayList<Instant>();
        for (final AcceptedWrite accept : accepted) {
            final long targetId = accept.write().analysisId();
            for (final SourceContributionWrite contribution : accept.write().contributions()) {
                final Contributor contributor = contribution.contributor();
                contributionTargets.add(targetId);
                sourceProjects.add(contributor.sourceProjectUuid());
                sourceComponents.add(contributor.sourceComponentUuid());
                sourceVulnerabilities.add(contributor.sourceVulnerabilityUuid());
                sourceAnalyses.add(contributor.sourceAnalysisId());
                sourceDetails.add(contribution.sourceDetails());
                for (final SourceCommentWrite comment : contribution.comments()) {
                    commentTargets.add(targetId);
                    commentProjects.add(contributor.sourceProjectUuid());
                    commentAnalyses.add(contributor.sourceAnalysisId());
                    commentIds.add(comment.sourceCommentId());
                    commentTexts.add(comment.comment());
                    commenters.add(comment.commenter());
                    commentTimestamps.add(comment.originalTimestamp());
                }
            }
        }

        if (!contributionTargets.isEmpty()) {
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
                            SELECT t.target_id
                                 , t.source_project
                                 , t.source_component
                                 , t.source_vulnerability
                                 , t.source_analysis
                                 , t.source_details
                                 , now()
                              FROM UNNEST(
                                     :targetIds
                                   , :sourceProjects
                                   , :sourceComponents
                                   , :sourceVulnerabilities
                                   , :sourceAnalyses
                                   , :sourceDetails
                                   ) AS t(
                                     target_id
                                   , source_project
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
                    .bind("targetIds", toLongArray(contributionTargets))
                    .bind("sourceProjects", sourceProjects.toArray(UUID[]::new))
                    .bind("sourceComponents", sourceComponents.toArray(UUID[]::new))
                    .bind("sourceVulnerabilities", sourceVulnerabilities.toArray(UUID[]::new))
                    .bind("sourceAnalyses", toLongArray(sourceAnalyses))
                    .bind("sourceDetails", sourceDetails.toArray(String[]::new))
                    .execute();
        }
        // Removed contributions take their comments with them through the foreign key.
        handle.createUpdate(/* language=SQL */ """
                        DELETE FROM "ASSESSMENT_SOURCE_CONTRIBUTION" AS c
                         WHERE c."TARGET_ANALYSIS_ID" = ANY(:writtenIds)
                           AND NOT EXISTS (
                             SELECT 1
                               FROM UNNEST(:targetIds, :sourceProjects, :sourceAnalyses)
                                 AS t(target_id, source_project, source_analysis)
                              WHERE t.target_id = c."TARGET_ANALYSIS_ID"
                                AND t.source_project = c."SOURCE_PROJECT_UUID"
                                AND t.source_analysis = c."SOURCE_ANALYSIS_ID"
                           )
                        """)
                .bind("writtenIds", targetIds)
                .bind("targetIds", toLongArray(contributionTargets))
                .bind("sourceProjects", sourceProjects.toArray(UUID[]::new))
                .bind("sourceAnalyses", toLongArray(sourceAnalyses))
                .execute();

        if (!commentTargets.isEmpty()) {
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
                            SELECT t.target_id
                                 , t.source_project
                                 , t.source_analysis
                                 , t.source_comment_id
                                 , t.comment
                                 , t.commenter
                                 , t.original_timestamp
                              FROM UNNEST(
                                     :targetIds
                                   , :sourceProjects
                                   , :sourceAnalyses
                                   , :sourceCommentIds
                                   , :comments
                                   , :commenters
                                   , :originalTimestamps
                                   ) AS t(
                                     target_id
                                   , source_project
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
                    .bind("targetIds", toLongArray(commentTargets))
                    .bind("sourceProjects", commentProjects.toArray(UUID[]::new))
                    .bind("sourceAnalyses", toLongArray(commentAnalyses))
                    .bind("sourceCommentIds", toLongArray(commentIds))
                    .bind("comments", commentTexts.toArray(String[]::new))
                    .bind("commenters", commenters.toArray(String[]::new))
                    .bind("originalTimestamps", commentTimestamps.toArray(Instant[]::new))
                    .execute();
        }
        handle.createUpdate(/* language=SQL */ """
                        DELETE FROM "ASSESSMENT_SOURCE_COMMENT" AS c
                         WHERE c."TARGET_ANALYSIS_ID" = ANY(:writtenIds)
                           AND NOT EXISTS (
                             SELECT 1
                               FROM UNNEST(:targetIds, :sourceProjects, :sourceAnalyses, :sourceCommentIds)
                                 AS t(target_id, source_project, source_analysis, source_comment_id)
                              WHERE t.target_id = c."TARGET_ANALYSIS_ID"
                                AND t.source_project = c."SOURCE_PROJECT_UUID"
                                AND t.source_analysis = c."SOURCE_ANALYSIS_ID"
                                AND t.source_comment_id = c."SOURCE_COMMENT_ID"
                           )
                        """)
                .bind("writtenIds", targetIds)
                .bind("targetIds", toLongArray(commentTargets))
                .bind("sourceProjects", commentProjects.toArray(UUID[]::new))
                .bind("sourceAnalyses", toLongArray(commentAnalyses))
                .bind("sourceCommentIds", toLongArray(commentIds))
                .execute();
    }

    private static long[] toLongArray(final List<Long> values) {
        return values.stream().mapToLong(Long::longValue).toArray();
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

    /**
     * Why a worker write did not change the target row.
     */
    public enum WorkerWriteStatus {
        APPLIED,
        REJECTED_OWNERSHIP,
        REJECTED_VERSION,
        MISSING
    }

    /**
     * Result of a worker write. {@code decisionVersion} is the version after a successful write, or the current one.
     */
    public record WorkerWriteResult(WorkerWriteStatus status, long decisionVersion) {

        public WorkerWriteResult {
            requireNonNull(status, "status must not be null");
        }
    }

    /**
     * Current stored projection, including copied source trails.
     */
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

    /**
     * One copied source, including its own details and original comments.
     */
    public record StoredContribution(
            Contributor contributor, @Nullable String sourceDetails, Instant lastSyncAt, List<StoredComment> comments) {

        public StoredContribution {
            requireNonNull(contributor, "contributor must not be null");
            requireNonNull(lastSyncAt, "lastSyncAt must not be null");
            requireNonNull(comments, "comments must not be null");
            comments = List.copyOf(comments);
        }
    }

    /**
     * Copied source comment. {@code originalTimestamp} is the source timestamp, not the copy time.
     */
    public record StoredComment(
            long sourceCommentId, String comment, @Nullable String commenter, Instant originalTimestamp) {

        public StoredComment {
            requireNonNull(comment, "comment must not be null");
            requireNonNull(originalTimestamp, "originalTimestamp must not be null");
        }
    }

    /**
     * Desired worker projection. Ownership {@code LOCAL} and {@code POLICY} are not worker-assigned.
     */
    public record WorkerWrite(
            long analysisId,
            AssessmentOwnership owner,
            AssessmentDecision decision,
            @Nullable AssessmentReason lastReason,
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
            if (AssessmentOwnership.authored(owner)) {
                throw new IllegalArgumentException("Worker writes cannot assign " + owner);
            }
            requireNonNull(contributions, "contributions must not be null");
            final var identities = new LinkedHashSet<ContributionKey>();
            for (final SourceContributionWrite contribution : contributions) {
                requireNonNull(contribution, "contribution must not be null");
                final var key = new ContributionKey(
                        contribution.contributor().sourceProjectUuid(),
                        contribution.contributor().sourceAnalysisId());
                if (!identities.add(key)) {
                    throw new IllegalArgumentException("Duplicate source contribution " + key.sourceProjectUuid());
                }
            }
            contributions = List.copyOf(contributions);
        }
    }

    /**
     * Desired source trail. Details belong to this contributor only.
     */
    public record SourceContributionWrite(
            Contributor contributor, @Nullable String sourceDetails, List<SourceCommentWrite> comments) {

        public SourceContributionWrite {
            requireNonNull(contributor, "contributor must not be null");
            requireNonNull(comments, "comments must not be null");
            final var ids = new LinkedHashSet<Long>();
            for (final SourceCommentWrite comment : comments) {
                requireNonNull(comment, "comment must not be null");
                if (!ids.add(comment.sourceCommentId())) {
                    throw new IllegalArgumentException("Duplicate source comment " + comment.sourceCommentId());
                }
            }
            comments = List.copyOf(comments);
        }
    }

    /**
     * Desired copied comment. The original timestamp is kept when the same source comment is written again.
     */
    public record SourceCommentWrite(
            long sourceCommentId, String comment, @Nullable String commenter, Instant originalTimestamp) {

        public SourceCommentWrite {
            requireNonNull(comment, "comment must not be null");
            requireNonNull(originalTimestamp, "originalTimestamp must not be null");
        }
    }

    private record LockedAnalysis(
            @Nullable Origin origin,
            AssessmentDecision decision,
            @Nullable String details) {

        private @Nullable AssessmentOwnership owner() {
            return origin == null ? null : origin.owner();
        }

        private long decisionVersion() {
            return origin == null ? 0 : origin.decisionVersion();
        }
    }

    private record ContributionKey(UUID sourceProjectUuid, long sourceAnalysisId) {}

    private record AcceptedWrite(int index, WorkerWrite write, boolean versionBump) {}
}
