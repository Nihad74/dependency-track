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

import alpine.resources.AlpineRequest;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Severity;
import org.dependencytrack.persistence.jdbi.ApiRequestConfig;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.transaction.TransactionIsolationLevel;
import org.jspecify.annotations.Nullable;

import java.math.BigDecimal;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.assessmentsync.DaoSupport.readInstant;
import static org.dependencytrack.assessmentsync.DaoSupport.requirePositive;

/**
 * Projects target analysis rows and the source groups the caller can read right now.
 *
 * <p>Access is the caller's current portfolio ACL, not a permission stored at sync time.
 * The caller is the principal of the request the handle is bound to. A handle without one yields no
 * source groups, because an unbound handle treats portfolio ACL as open.
 * Deleted or inaccessible sources are omitted entirely. The result has no hidden-source count.
 * Source text is read only for contributions that passed the access check, so hidden text never leaves the
 * database.
 * Reads outside a transaction use a short repeatable-read snapshot; existing caller transactions
 * are joined without changing their isolation level.
 */
public final class AssessmentTrailAssembler {

    private AssessmentTrailAssembler() {}

    public static List<Trail> assemble(final Handle handle, final Collection<Long> targetAnalysisIds) {
        if (targetAnalysisIds.isEmpty()) {
            return List.of();
        }

        final var orderedIds = new LinkedHashSet<Long>(targetAnalysisIds);
        for (final long analysisId : orderedIds) {
            requirePositive(analysisId, "analysisId");
        }

        if (handle.isInTransaction()) {
            return assembleSnapshot(handle, orderedIds);
        }
        return handle.inTransaction(TransactionIsolationLevel.REPEATABLE_READ, tx -> assembleSnapshot(tx, orderedIds));
    }

    private static List<Trail> assembleSnapshot(final Handle handle, final LinkedHashSet<Long> orderedIds) {
        final var targets = loadTargets(handle, orderedIds);
        final var identities = loadContributionIdentities(handle, orderedIds);
        final var visible = visibleContributions(handle, identities);
        final var detailsByKey = loadVisibleDetails(handle, visible);
        final var commentsByKey = loadVisibleComments(handle, visible);
        final var groupsByAnalysis = new LinkedHashMap<Long, List<SourceAssessment>>();
        for (final VisibleContribution identity : visible) {
            final var key = identity.key();
            final List<SourceComment> comments = commentsByKey.getOrDefault(key, List.of());
            groupsByAnalysis
                    .computeIfAbsent(identity.targetAnalysisId(), ignored -> new ArrayList<>())
                    .add(new SourceAssessment(
                            identity.project(), identity.component(), detailsByKey.get(key), comments));
        }

        final var trails = new ArrayList<Trail>(orderedIds.size());
        for (final Long analysisId : orderedIds) {
            final TargetRow target = targets.get(analysisId);
            if (target == null) {
                continue;
            }
            final List<SourceAssessment> groups = groupsByAnalysis.getOrDefault(analysisId, List.of());
            trails.add(new Trail(
                    analysisId,
                    target.analysis(),
                    target.owner(),
                    target.decisionVersion(),
                    target.localDetails(),
                    groups));
        }
        return List.copyOf(trails);
    }

    private static LinkedHashMap<Long, TargetRow> loadTargets(final Handle handle, final Collection<Long> analysisIds) {
        final var targets = new LinkedHashMap<Long, TargetRow>();
        handle.createQuery(/* language=SQL */ """
                        SELECT a."ID"
                             , a."DETAILS"
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
                             , o."OWNER"
                             , o."DECISION_VERSION"
                          FROM "ANALYSIS" AS a
                          LEFT JOIN "ASSESSMENT_ORIGIN" AS o
                            ON o."ANALYSIS_ID" = a."ID"
                         WHERE a."ID" = ANY(:analysisIds)
                        """)
                .bind("analysisIds", toLongArray(analysisIds))
                .map((rs, ctx) -> {
                    final String ownerName = rs.getString("OWNER");
                    final AssessmentOwnership owner = ownerName == null ? null : AssessmentOwnership.valueOf(ownerName);
                    return new TargetRow(
                            rs.getLong("ID"),
                            new AnalysisSnapshot(
                                    AnalysisState.valueOf(rs.getString("STATE")),
                                    nullableEnum(AnalysisJustification.class, rs.getString("JUSTIFICATION")),
                                    nullableEnum(AnalysisResponse.class, rs.getString("RESPONSE")),
                                    rs.getBoolean("SUPPRESSED"),
                                    nullableEnum(Severity.class, rs.getString("SEVERITY")),
                                    rs.getString("CVSSV2VECTOR"),
                                    rs.getBigDecimal("CVSSV2SCORE"),
                                    rs.getString("CVSSV3VECTOR"),
                                    rs.getBigDecimal("CVSSV3SCORE"),
                                    rs.getString("CVSSV4VECTOR"),
                                    rs.getBigDecimal("CVSSV4SCORE"),
                                    rs.getString("OWASPVECTOR"),
                                    rs.getBigDecimal("OWASPSCORE")),
                            owner,
                            owner == null ? 0 : rs.getLong("DECISION_VERSION"),
                            owner == AssessmentOwnership.INHERITED ? null : rs.getString("DETAILS"));
                })
                .forEach(target -> targets.put(target.analysisId(), target));
        return targets;
    }

    private static <E extends Enum<E>> @Nullable E nullableEnum(final Class<E> type, final @Nullable String value) {
        return value == null ? null : Enum.valueOf(type, value);
    }

    private static List<ContributionIdentity> loadContributionIdentities(
            final Handle handle, final Collection<Long> analysisIds) {
        return handle.createQuery(/* language=SQL */ """
                        SELECT "TARGET_ANALYSIS_ID"
                             , "SOURCE_PROJECT_UUID"
                             , "SOURCE_COMPONENT_UUID"
                             , "SOURCE_ANALYSIS_ID"
                          FROM "ASSESSMENT_SOURCE_CONTRIBUTION"
                         WHERE "TARGET_ANALYSIS_ID" = ANY(:analysisIds)
                         ORDER BY "TARGET_ANALYSIS_ID", "SOURCE_PROJECT_UUID", "SOURCE_ANALYSIS_ID"
                        """)
                .bind("analysisIds", toLongArray(analysisIds))
                .map((rs, ctx) -> new ContributionIdentity(
                        rs.getLong("TARGET_ANALYSIS_ID"),
                        rs.getObject("SOURCE_PROJECT_UUID", UUID.class),
                        rs.getObject("SOURCE_COMPONENT_UUID", UUID.class),
                        rs.getLong("SOURCE_ANALYSIS_ID")))
                .list();
    }

    /**
     * Drops sources the principal cannot read, and sources whose project, component, or analysis is gone.
     */
    private static List<VisibleContribution> visibleContributions(
            final Handle handle, final List<ContributionIdentity> identities) {
        if (identities.isEmpty() || !canReadSources(handle)) {
            return List.of();
        }
        final var projectUuids = new LinkedHashSet<UUID>();
        for (final ContributionIdentity identity : identities) {
            projectUuids.add(identity.sourceProjectUuid());
        }
        final Set<UUID> accessible =
                handle.attach(ProjectDao.class).getAccessibleProjectUuids(List.copyOf(projectUuids));
        if (accessible.isEmpty()) {
            return List.of();
        }

        final var candidateProjects = new ArrayList<UUID>();
        final var candidateComponents = new ArrayList<UUID>();
        final var candidateAnalyses = new ArrayList<Long>();
        for (final ContributionIdentity identity : identities) {
            if (!accessible.contains(identity.sourceProjectUuid())) {
                continue;
            }
            candidateProjects.add(identity.sourceProjectUuid());
            candidateComponents.add(identity.sourceComponentUuid());
            candidateAnalyses.add(identity.sourceAnalysisId());
        }
        if (candidateProjects.isEmpty()) {
            return List.of();
        }

        final var live = new LinkedHashMap<LiveSourceKey, LiveSource>();
        handle.createQuery(/* language=SQL */ """
                        SELECT p."UUID" AS project_uuid
                             , p."NAME" AS project_name
                             , p."VERSION" AS project_version
                             , c."UUID" AS component_uuid
                             , c."NAME" AS component_name
                             , c."VERSION" AS component_version
                             , a."ID" AS analysis_id
                          FROM "ANALYSIS" AS a
                         INNER JOIN "COMPONENT" AS c
                            ON c."ID" = a."COMPONENT_ID"
                         INNER JOIN "PROJECT" AS p
                            ON p."ID" = a."PROJECT_ID"
                         WHERE p."UUID" = ANY(:projectUuids)
                           AND c."UUID" = ANY(:componentUuids)
                           AND a."ID" = ANY(:analysisIds)
                        """)
                .bind("projectUuids", candidateProjects.toArray(UUID[]::new))
                .bind("componentUuids", candidateComponents.toArray(UUID[]::new))
                .bind("analysisIds", toLongArray(candidateAnalyses))
                .map((rs, ctx) -> new LiveSource(
                        new ProjectIdentity(
                                rs.getObject("project_uuid", UUID.class),
                                requireNonNull(rs.getString("project_name"), "project name must not be null"),
                                rs.getString("project_version")),
                        new ComponentIdentity(
                                rs.getObject("component_uuid", UUID.class),
                                requireNonNull(rs.getString("component_name"), "component name must not be null"),
                                rs.getString("component_version")),
                        rs.getLong("analysis_id")))
                .forEach(source -> live.put(
                        new LiveSourceKey(
                                source.project().uuid(), source.component().uuid(), source.analysisId()),
                        source));

        final var visible = new ArrayList<VisibleContribution>();
        for (final ContributionIdentity identity : identities) {
            final LiveSource source = live.get(new LiveSourceKey(
                    identity.sourceProjectUuid(), identity.sourceComponentUuid(), identity.sourceAnalysisId()));
            if (source == null) {
                continue;
            }
            visible.add(new VisibleContribution(
                    identity.targetAnalysisId(), source.project(), source.component(), identity.sourceAnalysisId()));
        }
        visible.sort(
                Comparator.comparing((VisibleContribution row) -> row.project().uuid())
                        .thenComparingLong(VisibleContribution::sourceAnalysisId));
        return List.copyOf(visible);
    }

    private static boolean canReadSources(final Handle handle) {
        final AlpineRequest request = handle.getConfig(ApiRequestConfig.class).apiRequest();
        return request != null && request.getPrincipal() != null;
    }

    private static LinkedHashMap<ContributionKey, String> loadVisibleDetails(
            final Handle handle, final List<VisibleContribution> visible) {
        final var details = new LinkedHashMap<ContributionKey, String>();
        if (visible.isEmpty()) {
            return details;
        }
        final var keys = keys(visible);
        handle.createQuery(/* language=SQL */ """
                        SELECT c."TARGET_ANALYSIS_ID"
                             , c."SOURCE_PROJECT_UUID"
                             , c."SOURCE_ANALYSIS_ID"
                             , c."SOURCE_DETAILS"
                          FROM "ASSESSMENT_SOURCE_CONTRIBUTION" AS c
                         INNER JOIN UNNEST(:targetIds, :projectUuids, :sourceAnalysisIds)
                            AS v(target_id, project_uuid, source_analysis_id)
                            ON c."TARGET_ANALYSIS_ID" = v.target_id
                           AND c."SOURCE_PROJECT_UUID" = v.project_uuid
                           AND c."SOURCE_ANALYSIS_ID" = v.source_analysis_id
                         WHERE c."SOURCE_DETAILS" IS NOT NULL
                        """)
                .bind("targetIds", keys.targetIds())
                .bind("projectUuids", keys.projectUuids())
                .bind("sourceAnalysisIds", keys.sourceAnalysisIds())
                .map((rs, ctx) -> Map.entry(key(rs), rs.getString("SOURCE_DETAILS")))
                .forEach(entry -> details.put(entry.getKey(), entry.getValue()));
        return details;
    }

    private static LinkedHashMap<ContributionKey, List<SourceComment>> loadVisibleComments(
            final Handle handle, final List<VisibleContribution> visible) {
        final var comments = new LinkedHashMap<ContributionKey, List<SourceComment>>();
        if (visible.isEmpty()) {
            return comments;
        }
        final var keys = keys(visible);
        handle.createQuery(/* language=SQL */ """
                        SELECT m."TARGET_ANALYSIS_ID"
                             , m."SOURCE_PROJECT_UUID"
                             , m."SOURCE_ANALYSIS_ID"
                             , m."SOURCE_COMMENT_ID"
                             , m."COMMENT"
                             , m."COMMENTER"
                             , m."ORIGINAL_TIMESTAMP"
                          FROM "ASSESSMENT_SOURCE_COMMENT" AS m
                         INNER JOIN UNNEST(:targetIds, :projectUuids, :sourceAnalysisIds)
                            AS v(target_id, project_uuid, source_analysis_id)
                            ON m."TARGET_ANALYSIS_ID" = v.target_id
                           AND m."SOURCE_PROJECT_UUID" = v.project_uuid
                           AND m."SOURCE_ANALYSIS_ID" = v.source_analysis_id
                         ORDER BY m."ORIGINAL_TIMESTAMP", m."SOURCE_COMMENT_ID"
                        """)
                .bind("targetIds", keys.targetIds())
                .bind("projectUuids", keys.projectUuids())
                .bind("sourceAnalysisIds", keys.sourceAnalysisIds())
                .map((rs, ctx) -> Map.entry(
                        key(rs),
                        new SourceComment(
                                readInstant(rs, "ORIGINAL_TIMESTAMP"),
                                requireNonNull(rs.getString("COMMENT"), "comment must not be null"),
                                rs.getString("COMMENTER"))))
                .forEach(entry -> comments.computeIfAbsent(entry.getKey(), ignored -> new ArrayList<>())
                        .add(entry.getValue()));
        final var copied = new LinkedHashMap<ContributionKey, List<SourceComment>>();
        for (final var entry : comments.entrySet()) {
            copied.put(entry.getKey(), List.copyOf(entry.getValue()));
        }
        return copied;
    }

    private static ContributionKey key(final ResultSet rs) throws SQLException {
        return new ContributionKey(
                rs.getLong("TARGET_ANALYSIS_ID"),
                rs.getObject("SOURCE_PROJECT_UUID", UUID.class),
                rs.getLong("SOURCE_ANALYSIS_ID"));
    }

    private static KeyArrays keys(final List<VisibleContribution> visible) {
        final var targetIds = new long[visible.size()];
        final var projectUuids = new UUID[visible.size()];
        final var sourceAnalysisIds = new long[visible.size()];
        for (int i = 0; i < visible.size(); i++) {
            final VisibleContribution row = visible.get(i);
            targetIds[i] = row.targetAnalysisId();
            projectUuids[i] = row.project().uuid();
            sourceAnalysisIds[i] = row.sourceAnalysisId();
        }
        return new KeyArrays(targetIds, projectUuids, sourceAnalysisIds);
    }

    private static long[] toLongArray(final Collection<Long> values) {
        return values.stream().mapToLong(Long::longValue).toArray();
    }

    /**
     * Target machine fields read in the same SQL statement as ownership and decision version.
     * Nullable legacy justification/response values are preserved for the existing API.
     */
    public record AnalysisSnapshot(
            AnalysisState state,
            @Nullable AnalysisJustification justification,
            @Nullable AnalysisResponse response,
            boolean suppressed,
            @Nullable Severity severity,
            @Nullable String cvssV2Vector,
            @Nullable BigDecimal cvssV2Score,
            @Nullable String cvssV3Vector,
            @Nullable BigDecimal cvssV3Score,
            @Nullable String cvssV4Vector,
            @Nullable BigDecimal cvssV4Score,
            @Nullable String owaspVector,
            @Nullable BigDecimal owaspScore) {
        public AnalysisSnapshot {
            requireNonNull(state, "state must not be null");
        }
    }

    /**
     * One target analysis. {@code localDetails} is null while the decision is inherited.
     */
    public record Trail(
            long analysisId,
            AnalysisSnapshot analysis,
            @Nullable AssessmentOwnership decisionOrigin,
            long decisionVersion,
            @Nullable String localDetails,
            List<SourceAssessment> sourceAssessments) {

        public Trail {
            requireNonNull(analysis, "analysis must not be null");
            requireNonNull(sourceAssessments, "sourceAssessments must not be null");
            sourceAssessments = List.copyOf(sourceAssessments);
        }
    }

    /**
     * One source the caller can currently read. Identity is the live project and component.
     */
    public record SourceAssessment(
            ProjectIdentity project,
            ComponentIdentity component,
            @Nullable String sourceDetails,
            List<SourceComment> comments) {

        public SourceAssessment {
            requireNonNull(project, "project must not be null");
            requireNonNull(component, "component must not be null");
            requireNonNull(comments, "comments must not be null");
            comments = List.copyOf(comments);
        }
    }

    public record ProjectIdentity(
            UUID uuid, String name, @Nullable String version) {

        public ProjectIdentity {
            requireNonNull(uuid, "uuid must not be null");
            requireNonNull(name, "name must not be null");
        }
    }

    public record ComponentIdentity(
            UUID uuid, String name, @Nullable String version) {

        public ComponentIdentity {
            requireNonNull(uuid, "uuid must not be null");
            requireNonNull(name, "name must not be null");
        }
    }

    /**
     * Original source comment, as the source commenter wrote it.
     */
    public record SourceComment(
            Instant timestamp, String comment, @Nullable String commenter) {

        public SourceComment {
            requireNonNull(timestamp, "timestamp must not be null");
            requireNonNull(comment, "comment must not be null");
        }
    }

    private record TargetRow(
            long analysisId,
            AnalysisSnapshot analysis,
            @Nullable AssessmentOwnership owner,
            long decisionVersion,
            @Nullable String localDetails) {}

    private record ContributionIdentity(
            long targetAnalysisId, UUID sourceProjectUuid, UUID sourceComponentUuid, long sourceAnalysisId) {}

    private record VisibleContribution(
            long targetAnalysisId, ProjectIdentity project, ComponentIdentity component, long sourceAnalysisId) {

        private ContributionKey key() {
            return new ContributionKey(targetAnalysisId, project.uuid(), sourceAnalysisId);
        }
    }

    private record LiveSource(ProjectIdentity project, ComponentIdentity component, long analysisId) {}

    private record LiveSourceKey(UUID projectUuid, UUID componentUuid, long analysisId) {}

    private record ContributionKey(long targetAnalysisId, UUID sourceProjectUuid, long sourceAnalysisId) {}

    private record KeyArrays(long[] targetIds, UUID[] projectUuids, long[] sourceAnalysisIds) {}
}
