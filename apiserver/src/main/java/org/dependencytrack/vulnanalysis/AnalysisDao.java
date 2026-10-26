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
package org.dependencytrack.vulnanalysis;

import org.dependencytrack.assessmentsync.AssessmentChange;
import org.dependencytrack.assessmentsync.AssessmentChangeRecorder;
import org.dependencytrack.assessmentsync.AssessmentMutationGuard;
import org.dependencytrack.assessmentsync.AssessmentOwnership;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.FindingKey;
import org.dependencytrack.model.Severity;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.SqlStatements;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

public final class AnalysisDao {

    private final Handle handle;

    public AnalysisDao(Handle handle) {
        this.handle = handle;
    }

    record Analysis(
            long id,
            @Nullable Long vulnPolicyId,
            @Nullable AnalysisState state,
            @Nullable AnalysisJustification justification,
            @Nullable AnalysisResponse response,
            @Nullable String details,
            boolean suppressed,
            @Nullable Severity severity,
            @Nullable String cvssV2Vector,
            @Nullable Double cvssV2Score,
            @Nullable String cvssV3Vector,
            @Nullable Double cvssV3Score,
            @Nullable String cvssV4Vector,
            @Nullable Double cvssV4Score,
            @Nullable String owaspVector,
            @Nullable Double owaspScore) {}

    private static final RowMapper<Map.Entry<FindingKey, Analysis>> FINDING_ANALYSIS_ROW_MAPPER =
            (rs, ctx) -> Map.entry(
                    new FindingKey(rs.getLong("COMPONENT_ID"), rs.getLong("VULNERABILITY_ID")),
                    new Analysis(
                            rs.getLong("ID"),
                            rs.getObject("VULNERABILITY_POLICY_ID", Long.class),
                            rs.getString("STATE") != null ? AnalysisState.valueOf(rs.getString("STATE")) : null,
                            rs.getString("JUSTIFICATION") != null
                                    ? AnalysisJustification.valueOf(rs.getString("JUSTIFICATION"))
                                    : null,
                            rs.getString("RESPONSE") != null
                                    ? AnalysisResponse.valueOf(rs.getString("RESPONSE"))
                                    : null,
                            rs.getString("DETAILS"),
                            rs.getBoolean("SUPPRESSED"),
                            rs.getString("SEVERITY") != null ? Severity.valueOf(rs.getString("SEVERITY")) : null,
                            rs.getString("CVSSV2VECTOR"),
                            rs.getObject("CVSSV2SCORE", Double.class),
                            rs.getString("CVSSV3VECTOR"),
                            rs.getObject("CVSSV3SCORE", Double.class),
                            rs.getString("CVSSV4VECTOR"),
                            rs.getObject("CVSSV4SCORE", Double.class),
                            rs.getString("OWASPVECTOR"),
                            rs.getObject("OWASPSCORE", Double.class)));

    Map<FindingKey, Analysis> getForProjectFindings(long projectId, Collection<FindingKey> findingKeys) {
        if (findingKeys.isEmpty()) {
            return Map.of();
        }

        final var componentIds = new long[findingKeys.size()];
        final var vulnerabilityIds = new long[findingKeys.size()];

        int i = 0;
        for (final FindingKey findingKey : findingKeys) {
            componentIds[i] = findingKey.componentId();
            vulnerabilityIds[i] = findingKey.vulnDbId();
            i++;
        }

        return handle
                .createQuery("""
                        SELECT "ID"
                             , "COMPONENT_ID"
                             , "VULNERABILITY_ID"
                             , "VULNERABILITY_POLICY_ID"
                             , "STATE"
                             , "JUSTIFICATION"
                             , "RESPONSE"
                             , "DETAILS"
                             , "SUPPRESSED"
                             , "SEVERITY"
                             , "CVSSV2VECTOR"
                             , CAST("CVSSV2SCORE" AS DOUBLE PRECISION) AS "CVSSV2SCORE"
                             , "CVSSV3VECTOR"
                             , CAST("CVSSV3SCORE" AS DOUBLE PRECISION) AS "CVSSV3SCORE"
                             , "CVSSV4VECTOR"
                             , CAST("CVSSV4SCORE" AS DOUBLE PRECISION) AS "CVSSV4SCORE"
                             , "OWASPVECTOR"
                             , CAST("OWASPSCORE" AS DOUBLE PRECISION) AS "OWASPSCORE"
                          FROM "ANALYSIS"
                         WHERE "PROJECT_ID" = :projectId
                           AND ("COMPONENT_ID", "VULNERABILITY_ID")
                            IN (SELECT * FROM UNNEST(:componentIds, :vulnerabilityIds))
                        """)
                .bind("projectId", projectId)
                .bind("componentIds", componentIds)
                .bind("vulnerabilityIds", vulnerabilityIds)
                .map(FINDING_ANALYSIS_ROW_MAPPER)
                .stream()
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    Map<FindingKey, Analysis> getForProjectWithPolicyApplied(
            long projectId, Collection<FindingKey> excludeFindingKeys) {
        final var excludeComponentIds = new long[excludeFindingKeys.size()];
        final var excludeVulnIds = new long[excludeFindingKeys.size()];

        int i = 0;
        for (final FindingKey findingKey : excludeFindingKeys) {
            excludeComponentIds[i] = findingKey.componentId();
            excludeVulnIds[i] = findingKey.vulnDbId();
            i++;
        }

        return handle
                .createQuery("""
                        SELECT "ID"
                             , "COMPONENT_ID"
                             , "VULNERABILITY_ID"
                             , "VULNERABILITY_POLICY_ID"
                             , "STATE"
                             , "JUSTIFICATION"
                             , "RESPONSE"
                             , "DETAILS"
                             , "SUPPRESSED"
                             , "SEVERITY"
                             , "CVSSV2VECTOR"
                             , CAST("CVSSV2SCORE" AS DOUBLE PRECISION) AS "CVSSV2SCORE"
                             , "CVSSV3VECTOR"
                             , CAST("CVSSV3SCORE" AS DOUBLE PRECISION) AS "CVSSV3SCORE"
                             , "CVSSV4VECTOR"
                             , CAST("CVSSV4SCORE" AS DOUBLE PRECISION) AS "CVSSV4SCORE"
                             , "OWASPVECTOR"
                             , CAST("OWASPSCORE" AS DOUBLE PRECISION) AS "OWASPSCORE"
                          FROM "ANALYSIS"
                         WHERE "PROJECT_ID" = :projectId
                           AND "VULNERABILITY_POLICY_ID" IS NOT NULL
                        <#if hasExclusions>
                           AND ("COMPONENT_ID", "VULNERABILITY_ID") NOT IN (
                                 SELECT *
                                   FROM UNNEST(:excludeComponentIds, :excludeVulnIds)
                               )
                        </#if>
                        """)
                .bind("projectId", projectId)
                .bind("excludeComponentIds", excludeComponentIds)
                .bind("excludeVulnIds", excludeVulnIds)
                .define("hasExclusions", !excludeFindingKeys.isEmpty())
                .configure(SqlStatements.class, cfg -> cfg.setUnusedBindingAllowed(true))
                .map(FINDING_ANALYSIS_ROW_MAPPER)
                .stream()
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    record MakeAnalysisCommand(
            long projectId,
            long componentId,
            long vulnDbId,
            @Nullable String vulnPolicyName,
            AnalysisState state,
            AnalysisJustification justification,
            AnalysisResponse response,
            @Nullable String details,
            boolean suppressed,
            @Nullable Severity severity,
            @Nullable String cvssV2Vector,
            @Nullable Double cvssV2Score,
            @Nullable String cvssV3Vector,
            @Nullable Double cvssV3Score,
            @Nullable String cvssV4Vector,
            @Nullable Double cvssV4Score,
            @Nullable String owaspVector,
            @Nullable Double owaspScore,
            boolean ownershipOnly) {

        MakeAnalysisCommand(
                long projectId,
                long componentId,
                long vulnDbId,
                @Nullable String vulnPolicyName,
                AnalysisState state,
                AnalysisJustification justification,
                AnalysisResponse response,
                @Nullable String details,
                boolean suppressed,
                @Nullable Severity severity,
                @Nullable String cvssV2Vector,
                @Nullable Double cvssV2Score,
                @Nullable String cvssV3Vector,
                @Nullable Double cvssV3Score,
                @Nullable String cvssV4Vector,
                @Nullable Double cvssV4Score,
                @Nullable String owaspVector,
                @Nullable Double owaspScore) {
            this(
                    projectId,
                    componentId,
                    vulnDbId,
                    vulnPolicyName,
                    state,
                    justification,
                    response,
                    details,
                    suppressed,
                    severity,
                    cvssV2Vector,
                    cvssV2Score,
                    cvssV3Vector,
                    cvssV3Score,
                    cvssV4Vector,
                    cvssV4Score,
                    owaspVector,
                    owaspScore,
                    false);
        }

        MakeAnalysisCommand asOwnershipOnly() {
            return new MakeAnalysisCommand(
                    projectId,
                    componentId,
                    vulnDbId,
                    vulnPolicyName,
                    state,
                    justification,
                    response,
                    details,
                    suppressed,
                    severity,
                    cvssV2Vector,
                    cvssV2Score,
                    cvssV3Vector,
                    cvssV3Score,
                    cvssV4Vector,
                    cvssV4Score,
                    owaspVector,
                    owaspScore,
                    true);
        }
    }

    Map<FindingKey, Long> makeAnalyses(Collection<MakeAnalysisCommand> commands) {
        if (commands.isEmpty()) {
            return Map.of();
        }

        final var mutations = new ArrayList<MakeAnalysisCommand>();
        final var ownershipOnly = new ArrayList<MakeAnalysisCommand>();
        for (final MakeAnalysisCommand command : commands) {
            if (command.ownershipOnly()) {
                ownershipOnly.add(command);
            } else {
                mutations.add(command);
            }
        }
        lockProjects(commands);
        final Map<FindingKey, Long> modified = mutations.isEmpty() ? Map.of() : upsertMutations(mutations);
        recordPolicyChanges(modified, mutations, ownershipOnly);
        return modified;
    }

    private Map<FindingKey, Long> upsertMutations(Collection<MakeAnalysisCommand> commands) {

        final var projectIds = new long[commands.size()];
        final var componentIds = new long[commands.size()];
        final var vulnDbIds = new long[commands.size()];
        final var vulnPolicyNames = new String[commands.size()];
        final var states = new String[commands.size()];
        final var justifications = new String[commands.size()];
        final var responses = new String[commands.size()];
        final var details = new String[commands.size()];
        final var suppressedArray = new boolean[commands.size()];
        final var severities = new String[commands.size()];
        final var cvssV2Vectors = new String[commands.size()];
        final var cvssV2Scores = new Double[commands.size()];
        final var cvssV3Vectors = new String[commands.size()];
        final var cvssV3Scores = new Double[commands.size()];
        final var cvssV4Vectors = new String[commands.size()];
        final var cvssV4Scores = new Double[commands.size()];
        final var owaspVectors = new String[commands.size()];
        final var owaspScores = new Double[commands.size()];

        int i = 0;
        for (final MakeAnalysisCommand command : commands) {
            projectIds[i] = command.projectId();
            componentIds[i] = command.componentId();
            vulnDbIds[i] = command.vulnDbId();
            vulnPolicyNames[i] = command.vulnPolicyName();
            states[i] = command.state().name();
            justifications[i] = command.justification().name();
            responses[i] = command.response().name();
            details[i] = command.details();
            suppressedArray[i] = command.suppressed();
            severities[i] = command.severity() != null ? command.severity().name() : null;
            cvssV2Vectors[i] = command.cvssV2Vector();
            cvssV2Scores[i] = command.cvssV2Score();
            cvssV3Vectors[i] = command.cvssV3Vector();
            cvssV3Scores[i] = command.cvssV3Score();
            cvssV4Vectors[i] = command.cvssV4Vector();
            cvssV4Scores[i] = command.cvssV4Score();
            owaspVectors[i] = command.owaspVector();
            owaspScores[i] = command.owaspScore();
            i++;
        }

        return handle
                .createUpdate("""
                        WITH cte_vuln_policy AS (
                          SELECT "ID"
                               , "NAME"
                            FROM "VULNERABILITY_POLICY"
                           WHERE "NAME" = ANY(:vulnPolicyNames)
                        )
                        INSERT INTO "ANALYSIS" AS a (
                          "PROJECT_ID"
                        , "COMPONENT_ID"
                        , "VULNERABILITY_ID"
                        , "VULNERABILITY_POLICY_ID"
                        , "STATE"
                        , "JUSTIFICATION"
                        , "RESPONSE"
                        , "DETAILS"
                        , "SUPPRESSED"
                        , "SEVERITY"
                        , "CVSSV2VECTOR"
                        , "CVSSV2SCORE"
                        , "CVSSV3VECTOR"
                        , "CVSSV3SCORE"
                        , "CVSSV4VECTOR"
                        , "CVSSV4SCORE"
                        , "OWASPVECTOR"
                        , "OWASPSCORE"
                        )
                        SELECT project_id
                             , component_id
                             , vulnerability_id
                             , vp."ID"
                             , state
                             , justification
                             , response
                             , details
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
                          FROM UNNEST (
                            :projectIds
                          , :componentIds
                          , :vulnDbIds
                          , :vulnPolicyNames
                          , :states
                          , :justifications
                          , :responses
                          , :details
                          , :suppressedArray
                          , CAST(:severities AS severity[])
                          , :cvssV2Vectors
                          , :cvssV2Scores
                          , :cvssV3Vectors
                          , :cvssV3Scores
                          , :cvssV4Vectors
                          , :cvssV4Scores
                          , :owaspVectors
                          , :owaspScores
                          ) AS t (
                            project_id
                          , component_id
                          , vulnerability_id
                          , vuln_policy_name
                          , state
                          , justification
                          , response
                          , details
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
                          LEFT JOIN cte_vuln_policy AS vp
                            ON vp."NAME" = t.vuln_policy_name
                         ORDER BY project_id
                                , component_id
                                , vulnerability_id
                        ON CONFLICT ("PROJECT_ID", "COMPONENT_ID", "VULNERABILITY_ID") DO UPDATE
                        SET "VULNERABILITY_POLICY_ID" = EXCLUDED."VULNERABILITY_POLICY_ID"
                          , "STATE" = EXCLUDED."STATE"
                          , "JUSTIFICATION" = EXCLUDED."JUSTIFICATION"
                          , "RESPONSE" = EXCLUDED."RESPONSE"
                          , "DETAILS" = EXCLUDED."DETAILS"
                          , "SUPPRESSED" = EXCLUDED."SUPPRESSED"
                          , "SEVERITY" = EXCLUDED."SEVERITY"
                          , "CVSSV2VECTOR" = EXCLUDED."CVSSV2VECTOR"
                          , "CVSSV2SCORE" = EXCLUDED."CVSSV2SCORE"
                          , "CVSSV3VECTOR" = EXCLUDED."CVSSV3VECTOR"
                          , "CVSSV3SCORE" = EXCLUDED."CVSSV3SCORE"
                          , "CVSSV4VECTOR" = EXCLUDED."CVSSV4VECTOR"
                          , "CVSSV4SCORE" = EXCLUDED."CVSSV4SCORE"
                          , "OWASPVECTOR" = EXCLUDED."OWASPVECTOR"
                          , "OWASPSCORE" = EXCLUDED."OWASPSCORE"
                        WHERE (
                            a."VULNERABILITY_POLICY_ID"
                          , a."STATE"
                          , a."JUSTIFICATION"
                          , a."RESPONSE"
                          , a."DETAILS"
                          , a."SUPPRESSED"
                          , a."SEVERITY"
                          , a."CVSSV2VECTOR"
                          , a."CVSSV2SCORE"
                          , a."CVSSV3VECTOR"
                          , a."CVSSV3SCORE"
                          , a."CVSSV4VECTOR"
                          , a."CVSSV4SCORE"
                          , a."OWASPVECTOR"
                          , a."OWASPSCORE"
                          ) IS DISTINCT FROM (
                            EXCLUDED."VULNERABILITY_POLICY_ID"
                          , EXCLUDED."STATE"
                          , EXCLUDED."JUSTIFICATION"
                          , EXCLUDED."RESPONSE"
                          , EXCLUDED."DETAILS"
                          , EXCLUDED."SUPPRESSED"
                          , EXCLUDED."SEVERITY"
                          , EXCLUDED."CVSSV2VECTOR"
                          , EXCLUDED."CVSSV2SCORE"
                          , EXCLUDED."CVSSV3VECTOR"
                          , EXCLUDED."CVSSV3SCORE"
                          , EXCLUDED."CVSSV4VECTOR"
                          , EXCLUDED."CVSSV4SCORE"
                          , EXCLUDED."OWASPVECTOR"
                          , EXCLUDED."OWASPSCORE"
                          )
                        RETURNING "ID"
                                , "COMPONENT_ID"
                                , "VULNERABILITY_ID"
                        """)
                .bind("projectIds", projectIds)
                .bind("componentIds", componentIds)
                .bind("vulnDbIds", vulnDbIds)
                .bind("vulnPolicyNames", vulnPolicyNames)
                .bind("states", states)
                .bind("justifications", justifications)
                .bind("responses", responses)
                .bind("details", details)
                .bind("suppressedArray", suppressedArray)
                .bind("severities", severities)
                .bind("cvssV2Vectors", cvssV2Vectors)
                .bind("cvssV2Scores", cvssV2Scores)
                .bind("cvssV3Vectors", cvssV3Vectors)
                .bind("cvssV3Scores", cvssV3Scores)
                .bind("cvssV4Vectors", cvssV4Vectors)
                .bind("cvssV4Scores", cvssV4Scores)
                .bind("owaspVectors", owaspVectors)
                .bind("owaspScores", owaspScores)
                .executeAndReturnGeneratedKeys()
                .map((rs, ctx) -> Map.entry(
                        new FindingKey(rs.getLong("COMPONENT_ID"), rs.getLong("VULNERABILITY_ID")), rs.getLong("ID")))
                .stream()
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private void lockProjects(final Collection<MakeAnalysisCommand> commands) {
        final long[] projectIds = commands.stream()
                .mapToLong(MakeAnalysisCommand::projectId)
                .distinct()
                .toArray();
        final List<UUID> projectUuids = handle.createQuery("""
                        SELECT "UUID"
                          FROM "PROJECT"
                         WHERE "ID" = ANY(:projectIds)
                        """)
                .bind("projectIds", projectIds)
                .map((rs, ctx) -> rs.getObject("UUID", UUID.class))
                .list();
        if (projectUuids.size() != projectIds.length) {
            throw new IllegalStateException("Policy analysis is missing a project");
        }
        AssessmentMutationGuard.lockProjects(handle, projectUuids);
    }

    private void recordPolicyChanges(
            final Map<FindingKey, Long> modified,
            final List<MakeAnalysisCommand> mutations,
            final List<MakeAnalysisCommand> ownershipOnly) {
        final var commandByKey = new HashMap<FindingKey, MakeAnalysisCommand>();
        for (final MakeAnalysisCommand command : mutations) {
            commandByKey.put(new FindingKey(command.componentId(), command.vulnDbId()), command);
        }

        final var dao = new AssessmentProjectionDao(handle);
        final var changes = new ArrayList<AssessmentChange>();
        if (!modified.isEmpty()) {
            final long[] ids =
                    modified.values().stream().mapToLong(Long::longValue).toArray();
            for (final PolicyFinding finding : loadFindingsByAnalysisId(ids)) {
                final MakeAnalysisCommand command =
                        commandByKey.get(new FindingKey(finding.componentId(), finding.vulnerabilityId()));
                if (command == null) {
                    throw new IllegalStateException("Updated analysis has no policy command");
                }
                final AssessmentOwnership owner =
                        command.vulnPolicyName() == null ? AssessmentOwnership.NEUTRAL : AssessmentOwnership.POLICY;
                writeOwner(dao, finding, owner);
                changes.add(policyChange(
                        finding,
                        owner == AssessmentOwnership.POLICY
                                ? AssessmentChangeRecorder.POLICY
                                : AssessmentChangeRecorder.POLICY_UNASSIGNED));
            }
        }
        for (final PolicyFinding finding : loadEqualValueTakeovers(ownershipOnly)) {
            writeOwner(dao, finding, AssessmentOwnership.POLICY);
            changes.add(policyChange(finding, AssessmentChangeRecorder.POLICY));
        }
        new AssessmentChangeRecorder(handle).recordAll(changes);
    }

    private static void writeOwner(
            final AssessmentProjectionDao dao, final PolicyFinding finding, final AssessmentOwnership owner) {
        final boolean ownerChanged = finding.owner() == null || finding.owner() != owner;
        dao.upsertOrigin(finding.analysisId(), owner, null);
        if (!ownerChanged) {
            dao.bumpDecisionVersion(finding.analysisId());
        }
    }

    private List<PolicyFinding> loadFindingsByAnalysisId(final long[] ids) {
        final List<PolicyFinding> findings = handle.createQuery("""
                        SELECT a."ID" AS analysis_id
                             , a."COMPONENT_ID" AS component_id
                             , a."VULNERABILITY_ID" AS vulnerability_id
                             , p."UUID" AS project_uuid
                             , p."NAME" AS project_name
                             , p."VERSION" AS project_version
                             , c."UUID" AS component_uuid
                             , v."UUID" AS vulnerability_uuid
                             , o."OWNER" AS owner
                          FROM "ANALYSIS" AS a
                         INNER JOIN "PROJECT" AS p
                            ON p."ID" = a."PROJECT_ID"
                         INNER JOIN "COMPONENT" AS c
                            ON c."ID" = a."COMPONENT_ID"
                         INNER JOIN "VULNERABILITY" AS v
                            ON v."ID" = a."VULNERABILITY_ID"
                          LEFT JOIN "ASSESSMENT_ORIGIN" AS o
                            ON o."ANALYSIS_ID" = a."ID"
                         WHERE a."ID" = ANY(:ids)
                        """)
                .bind("ids", ids)
                .map(this::mapPolicyFinding)
                .list();
        if (findings.size() != ids.length) {
            throw new IllegalStateException("Updated analysis is missing its finding identity");
        }
        return findings;
    }

    private List<PolicyFinding> loadEqualValueTakeovers(final List<MakeAnalysisCommand> commands) {
        if (commands.isEmpty()) {
            return List.of();
        }
        final var projectIds = new long[commands.size()];
        final var componentIds = new long[commands.size()];
        final var vulnerabilityIds = new long[commands.size()];
        final var policyNames = new String[commands.size()];
        for (int i = 0; i < commands.size(); i++) {
            final MakeAnalysisCommand command = commands.get(i);
            projectIds[i] = command.projectId();
            componentIds[i] = command.componentId();
            vulnerabilityIds[i] = command.vulnDbId();
            policyNames[i] = command.vulnPolicyName();
        }
        return handle.createQuery("""
                        SELECT a."ID" AS analysis_id
                             , a."COMPONENT_ID" AS component_id
                             , a."VULNERABILITY_ID" AS vulnerability_id
                             , p."UUID" AS project_uuid
                             , p."NAME" AS project_name
                             , p."VERSION" AS project_version
                             , c."UUID" AS component_uuid
                             , v."UUID" AS vulnerability_uuid
                             , o."OWNER" AS owner
                          FROM UNNEST(:projectIds, :componentIds, :vulnerabilityIds, :policyNames)
                            AS t(project_id, component_id, vulnerability_id, policy_name)
                         INNER JOIN "ANALYSIS" AS a
                            ON a."PROJECT_ID" = t.project_id
                           AND a."COMPONENT_ID" = t.component_id
                           AND a."VULNERABILITY_ID" = t.vulnerability_id
                         INNER JOIN "PROJECT" AS p
                            ON p."ID" = a."PROJECT_ID"
                         INNER JOIN "COMPONENT" AS c
                            ON c."ID" = a."COMPONENT_ID"
                         INNER JOIN "VULNERABILITY" AS v
                            ON v."ID" = a."VULNERABILITY_ID"
                         INNER JOIN "VULNERABILITY_POLICY" AS vp
                            ON vp."ID" = a."VULNERABILITY_POLICY_ID"
                           AND vp."NAME" = t.policy_name
                          LEFT JOIN "ASSESSMENT_ORIGIN" AS o
                            ON o."ANALYSIS_ID" = a."ID"
                         WHERE o."OWNER" IS DISTINCT FROM 'POLICY'
                        """)
                .bind("projectIds", projectIds)
                .bind("componentIds", componentIds)
                .bind("vulnerabilityIds", vulnerabilityIds)
                .bind("policyNames", policyNames)
                .map(this::mapPolicyFinding)
                .list();
    }

    private PolicyFinding mapPolicyFinding(final ResultSet rs, final StatementContext ctx) throws SQLException {
        final String owner = rs.getString("owner");
        return new PolicyFinding(
                rs.getLong("analysis_id"),
                rs.getLong("component_id"),
                rs.getLong("vulnerability_id"),
                rs.getObject("project_uuid", UUID.class),
                rs.getString("project_name"),
                rs.getString("project_version"),
                rs.getObject("component_uuid", UUID.class),
                rs.getObject("vulnerability_uuid", UUID.class),
                owner == null ? null : AssessmentOwnership.valueOf(owner));
    }

    private static AssessmentChange policyChange(final PolicyFinding finding, final String reason) {
        return new AssessmentChange(
                AssessmentChange.Scope.FINDING,
                finding.projectUuid(),
                finding.componentUuid(),
                finding.vulnerabilityUuid(),
                reason,
                AssessmentChangeRecorder.lookupKeys(finding.projectName(), finding.projectVersion()));
    }

    private record PolicyFinding(
            long analysisId,
            long componentId,
            long vulnerabilityId,
            UUID projectUuid,
            @Nullable String projectName,
            @Nullable String projectVersion,
            UUID componentUuid,
            UUID vulnerabilityUuid,
            @Nullable AssessmentOwnership owner) {}

    public record CreateCommentCommand(long analysisId, String commenter, String comment) {}

    public int createComments(Collection<CreateCommentCommand> commands) {
        if (commands.isEmpty()) {
            return 0;
        }

        final var analysisIds = new long[commands.size()];
        final var commenters = new String[commands.size()];
        final var comments = new String[commands.size()];

        int i = 0;
        for (final CreateCommentCommand command : commands) {
            analysisIds[i] = command.analysisId();
            commenters[i] = command.commenter();
            comments[i] = command.comment();
            i++;
        }

        return handle.createUpdate("""
                        INSERT INTO "ANALYSISCOMMENT" ("ANALYSIS_ID", "COMMENTER", "COMMENT", "TIMESTAMP")
                        SELECT analysis_id
                             , commenter
                             , comment
                             , NOW()
                          FROM UNNEST(:analysisIds, :commenters, :comments)
                            AS t(analysis_id, commenter, comment)
                         ORDER BY analysis_id
                        """)
                .bind("analysisIds", analysisIds)
                .bind("commenters", commenters)
                .bind("comments", comments)
                .execute();
    }
}
