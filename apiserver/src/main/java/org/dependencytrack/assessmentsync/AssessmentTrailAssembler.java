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

import alpine.model.auth.ApiKeyPrincipal;
import alpine.model.auth.Principal;
import alpine.model.auth.UserPrincipal;
import alpine.resources.AlpineRequest;
import org.dependencytrack.persistence.jdbi.ApiRequestConfig;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/// Projects target analysis rows and the source groups the caller can read right now.
///
/// Access is the caller's current portfolio ACL, not a permission stored at sync time.
/// A missing principal, or a handle that is not bound to that principal, yields no source groups.
/// Deleted or inaccessible sources are omitted entirely. The result has no hidden-source count.
public final class AssessmentTrailAssembler {

    public List<Trail> assemble(
            final Handle handle, final @Nullable Principal principal, final Collection<Long> targetAnalysisIds) {
        requireNonNull(handle, "handle must not be null");
        requireNonNull(targetAnalysisIds, "targetAnalysisIds must not be null");
        if (targetAnalysisIds.isEmpty()) {
            return List.of();
        }

        final var orderedIds = new ArrayList<Long>(targetAnalysisIds.size());
        for (final Long analysisId : targetAnalysisIds) {
            if (analysisId == null || analysisId <= 0) {
                throw new IllegalArgumentException("analysisId must be positive");
            }
            if (!orderedIds.contains(analysisId)) {
                orderedIds.add(analysisId);
            }
        }

        final var machines = loadMachines(handle, orderedIds);
        final var identities = loadContributionIdentities(handle, orderedIds);
        final var visible = visibleContributions(handle, principal, identities);
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
            final MachineRow machine = machines.get(analysisId);
            if (machine == null) {
                continue;
            }
            final List<SourceAssessment> groups = groupsByAnalysis.getOrDefault(analysisId, List.of());
            trails.add(new Trail(
                    analysisId,
                    machine.owner(),
                    machine.decisionVersion(),
                    machine.inheritanceStatus(),
                    machine.localDetails(),
                    List.copyOf(groups)));
        }
        return List.copyOf(trails);
    }

    private static LinkedHashMap<Long, MachineRow> loadMachines(final Handle handle, final List<Long> analysisIds) {
        final var machines = new LinkedHashMap<Long, MachineRow>();
        handle.createQuery(/* language=SQL */ """
                        SELECT a."ID"
                             , a."DETAILS"
                             , o."OWNER"
                             , o."DECISION_VERSION"
                             , o."LAST_REASON"
                          FROM "ANALYSIS" AS a
                          LEFT JOIN "ASSESSMENT_ORIGIN" AS o
                            ON o."ANALYSIS_ID" = a."ID"
                         WHERE a."ID" = ANY(:analysisIds)
                        """)
                .bind("analysisIds", toLongArray(analysisIds))
                .map((rs, ctx) -> {
                    final long analysisId = rs.getLong("ID");
                    final String ownerName = rs.getString("OWNER");
                    final AssessmentOwnership owner = ownerName == null ? null : AssessmentOwnership.valueOf(ownerName);
                    final String storedDetails = rs.getString("DETAILS");
                    machines.put(
                            analysisId,
                            new MachineRow(
                                    owner,
                                    owner == null ? 0 : rs.getLong("DECISION_VERSION"),
                                    safeReason(rs.getString("LAST_REASON")),
                                    owner == AssessmentOwnership.INHERITED ? null : storedDetails));
                    return analysisId;
                })
                .list();
        return machines;
    }

    private static List<ContributionIdentity> loadContributionIdentities(
            final Handle handle, final List<Long> analysisIds) {
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

    /// Drops sources the principal cannot read, and sources whose project, component, or analysis is gone.
    private static List<VisibleContribution> visibleContributions(
            final Handle handle, final @Nullable Principal principal, final List<ContributionIdentity> identities) {
        if (identities.isEmpty() || !canReadSources(handle, principal)) {
            return List.of();
        }
        final var projectUuids = new ArrayList<UUID>();
        for (final ContributionIdentity identity : identities) {
            if (!projectUuids.contains(identity.sourceProjectUuid())) {
                projectUuids.add(identity.sourceProjectUuid());
            }
        }
        final Set<UUID> accessible = handle.attach(ProjectDao.class).getAccessibleProjectUuids(projectUuids);
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
                .map((rs, ctx) -> {
                    final var source = new LiveSource(
                            new ProjectIdentity(
                                    rs.getObject("project_uuid", UUID.class),
                                    requireNonNull(rs.getString("project_name"), "project name must not be null"),
                                    rs.getString("project_version")),
                            new ComponentIdentity(
                                    rs.getObject("component_uuid", UUID.class),
                                    requireNonNull(rs.getString("component_name"), "component name must not be null"),
                                    rs.getString("component_version")),
                            rs.getLong("analysis_id"));
                    live.put(
                            new LiveSourceKey(
                                    source.project().uuid(), source.component().uuid(), source.analysisId()),
                            source);
                    return source.analysisId();
                })
                .list();

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

    /// A null principal is not authorization. The handle must be the same caller's request,
    /// because an unbound handle treats portfolio ACL as open.
    private static boolean canReadSources(final Handle handle, final @Nullable Principal principal) {
        if (principal == null) {
            return false;
        }
        final AlpineRequest request = handle.getConfig(ApiRequestConfig.class).apiRequest();
        if (request == null || request.getPrincipal() == null) {
            return false;
        }
        return samePrincipal(request.getPrincipal(), principal);
    }

    private static boolean samePrincipal(final Principal bound, final Principal requested) {
        if (bound instanceof final UserPrincipal user && requested instanceof final UserPrincipal other) {
            return user.id() == other.id();
        }
        if (bound instanceof final ApiKeyPrincipal apiKey && requested instanceof final ApiKeyPrincipal other) {
            return apiKey.id() == other.id();
        }
        return false;
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
                        """)
                .bind("targetIds", keys.targetIds())
                .bind("projectUuids", keys.projectUuids())
                .bind("sourceAnalysisIds", keys.sourceAnalysisIds())
                .map((rs, ctx) -> {
                    final String text = rs.getString("SOURCE_DETAILS");
                    if (text != null) {
                        details.put(key(rs), text);
                    }
                    return text;
                })
                .list();
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
                .map((rs, ctx) -> {
                    comments.computeIfAbsent(key(rs), ignored -> new ArrayList<>())
                            .add(new SourceComment(
                                    readInstant(rs, "ORIGINAL_TIMESTAMP"),
                                    requireNonNull(rs.getString("COMMENT"), "comment must not be null"),
                                    rs.getString("COMMENTER")));
                    return rs.getLong("SOURCE_COMMENT_ID");
                })
                .list();
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

    private static long[] toLongArray(final List<Long> values) {
        final var array = new long[values.size()];
        for (int i = 0; i < values.size(); i++) {
            array[i] = values.get(i);
        }
        return array;
    }

    /// Only the fixed reason enum is safe to show. Free text could name a hidden source.
    private static @Nullable String safeReason(final @Nullable String reason) {
        if (reason == null) {
            return null;
        }
        for (final AssessmentReason known : AssessmentReason.values()) {
            if (known.name().equals(reason)) {
                return reason;
            }
        }
        return null;
    }

    private static Instant readInstant(final ResultSet rs, final String column) throws SQLException {
        final OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
        return requireNonNull(value, column).toInstant();
    }

    /// One target analysis. {@code localDetails} is null while the decision is inherited.
    public record Trail(
            long analysisId,
            @Nullable AssessmentOwnership decisionOrigin,
            long decisionVersion,
            @Nullable String inheritanceStatus,
            @Nullable String localDetails,
            List<SourceAssessment> sourceAssessments) {

        public Trail {
            requireNonNull(sourceAssessments, "sourceAssessments must not be null");
            sourceAssessments = List.copyOf(sourceAssessments);
        }
    }

    /// One source the caller can currently read. Identity is the live project and component.
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

    /// Original source comment. {@code author} is the source commenter.
    public record SourceComment(
            Instant timestamp, String comment, @Nullable String author) {

        public SourceComment {
            requireNonNull(timestamp, "timestamp must not be null");
            requireNonNull(comment, "comment must not be null");
        }
    }

    private record MachineRow(
            @Nullable AssessmentOwnership owner,
            long decisionVersion,
            @Nullable String inheritanceStatus,
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
