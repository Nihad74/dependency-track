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
import org.dependencytrack.assessmentsync.AssessmentConsensus.Result;
import org.dependencytrack.assessmentsync.AssessmentConsensus.SourceAssessment;
import org.dependencytrack.assessmentsync.AssessmentMatcher.ComponentIdentity;
import org.dependencytrack.assessmentsync.AssessmentMatcher.HashAlgorithm;
import org.dependencytrack.assessmentsync.AssessmentMatcher.SourceCandidate;
import org.dependencytrack.assessmentsync.AssessmentMatcher.VulnerabilityIdentity;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao.SourceCommentWrite;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao.SourceContributionWrite;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao.WorkerWrite;
import org.dependencytrack.assessmentsync.AssessmentProjectionDiff.Change;
import org.dependencytrack.assessmentsync.AssessmentProjectionDiff.CurrentProjection;
import org.dependencytrack.assessmentsync.AssessmentSourceResolver.Identity;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.FindingKey;
import org.dependencytrack.model.Severity;
import org.dependencytrack.notification.GetProjectAuditChangeNotificationSubjectQuery;
import org.dependencytrack.notification.JdbiNotificationEmitter;
import org.dependencytrack.notification.NotificationGroup;
import org.dependencytrack.notification.NotificationSubjectDao;
import org.dependencytrack.notification.proto.v1.Notification;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.api.NotificationFactory.createVulnerabilityAnalysisDecisionChangeNotification;

/// Applies one page of target findings on the caller's transaction.
///
/// Does not open a transaction, commit, or call Dex. Source projects are read, not locked.
public final class AssessmentSynchronizer {

    /// Outcome of one page. {@code conflicts} counts disagreeing source sets.
    /// A conflict that withdraws an inherited row is also included in {@code withdrawn}.
    public record BatchResult(int applied, int withdrawn, int skipped, int conflicts, boolean machineFieldsChanged) {}

    /// Matches, projects, and notifies for {@code findingKeys}. The caller chooses the page.
    public BatchResult reconcileBatch(final Handle handle, final UUID targetUuid, final List<FindingKey> findingKeys) {
        requireNonNull(handle, "handle must not be null");
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireNonNull(findingKeys, "findingKeys must not be null");
        if (!handle.isInTransaction()) {
            throw new IllegalStateException("Assessment reconciliation requires an active transaction");
        }
        final List<FindingKey> keys = dedupe(findingKeys);
        if (keys.isEmpty()) {
            return new BatchResult(0, 0, 0, 0, false);
        }

        final Long projectId = projectId(handle, targetUuid);
        if (projectId == null) {
            return new BatchResult(0, 0, keys.size(), 0, false);
        }

        lockAnalyses(handle, projectId, keys);
        final Map<FindingKey, TargetRow> targets = loadTargets(handle, projectId, keys);
        final Map<Long, List<UUID>> sourcesByComponent = sourceProjects(handle, targetUuid, projectId, keys);
        final Map<UUID, Map<UUID, SourceComponent>> componentsBySource =
                loadSourceComponents(handle, sourcesByComponent, keys);
        final Map<Long, List<CopiedTrail>> trailsByAnalysis = loadTrails(handle, targets);

        var applied = 0;
        var withdrawn = 0;
        var skipped = 0;
        var conflicts = 0;
        var machineFieldsChanged = false;
        final var audits = new ArrayList<AuditNotice>();
        final var projectionDao = new AssessmentProjectionDao(handle);

        for (final FindingKey key : keys) {
            final TargetRow target = targets.get(key);
            if (target == null || (target.analysisId() != null && target.owner() == null)) {
                skipped++;
                continue;
            }
            final Decision decision = decide(target, sourcesByComponent, componentsBySource);
            final Result consensus = decision.consensus();
            if (consensus instanceof AssessmentConsensus.Conflict) {
                conflicts++;
            }
            final PreparedTarget prepared = prepareTarget(handle, projectId, target, consensus);
            if (prepared == null) {
                skipped++;
                continue;
            }
            final List<CopiedTrail> trails =
                    target.analysisId() != null && target.analysisId().longValue() == prepared.analysisId()
                            ? trailsByAnalysis.getOrDefault(prepared.analysisId(), List.of())
                            : List.of();
            final CurrentProjection current = new CurrentProjection(
                    prepared.owner(),
                    prepared.decision(),
                    prepared.details(),
                    prepared.policyId(),
                    contributors(trails),
                    prepared.localComment());
            final Change change = AssessmentProjectionDiff.diff(current, consensus);
            if (change.origin() == null
                    || change.origin() == AssessmentOwnership.LOCAL
                    || change.origin() == AssessmentOwnership.POLICY) {
                skipped++;
                continue;
            }
            final List<SourceContributionWrite> contributions = decision.contributions();
            if (!change.machineChanged() && !change.contributorsChanged() && !trailsDiffer(trails, contributions)) {
                skipped++;
                continue;
            }
            final var write = new WorkerWrite(
                    prepared.analysisId(),
                    change.origin(),
                    change.decision(),
                    null,
                    null,
                    change.reason() == null ? null : change.reason().name(),
                    prepared.decisionVersion(),
                    contributions);
            final var written = projectionDao.applyWorkerWrite(write);
            if (written.status() != AssessmentProjectionDao.WorkerWriteStatus.APPLIED) {
                skipped++;
                continue;
            }
            if (change.origin() == AssessmentOwnership.NEUTRAL) {
                withdrawn++;
            } else {
                applied++;
            }
            if (change.machineChanged()) {
                machineFieldsChanged = true;
            }
            final boolean stateChanged =
                    current.decision().state() != change.decision().state();
            final boolean suppressionChanged =
                    current.decision().suppressed() != change.decision().suppressed();
            if (stateChanged || suppressionChanged) {
                audits.add(new AuditNotice(
                        key.componentId(),
                        key.vulnDbId(),
                        change.decision().state(),
                        change.decision().suppressed(),
                        stateChanged,
                        suppressionChanged));
            }
        }
        emitAuditChanges(handle, audits);
        return new BatchResult(applied, withdrawn, skipped, conflicts, machineFieldsChanged);
    }

    /// Counts findings whose match, consensus, and diff would change the stored projection.
    ///
    /// Does not insert analyses, change ownership, or write machine fields.
    /// A legacy analysis with no origin is not drift.
    public int countDrift(final Handle handle, final UUID targetUuid, final List<FindingKey> findingKeys) {
        requireNonNull(handle, "handle must not be null");
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireNonNull(findingKeys, "findingKeys must not be null");
        if (!handle.isInTransaction()) {
            throw new IllegalStateException("Assessment drift inspection requires an active transaction");
        }
        final List<FindingKey> keys = dedupe(findingKeys);
        if (keys.isEmpty()) {
            return 0;
        }
        final Long projectId = projectId(handle, targetUuid);
        if (projectId == null) {
            return 0;
        }

        lockAnalyses(handle, projectId, keys);
        final Map<FindingKey, TargetRow> targets = loadTargets(handle, projectId, keys);
        final Map<Long, List<UUID>> sourcesByComponent = sourceProjects(handle, targetUuid, projectId, keys);
        final Map<UUID, Map<UUID, SourceComponent>> componentsBySource =
                loadSourceComponents(handle, sourcesByComponent, keys);
        final Map<Long, List<CopiedTrail>> trailsByAnalysis = loadTrails(handle, targets);

        var drift = 0;
        for (final FindingKey key : keys) {
            final TargetRow target = targets.get(key);
            if (target == null || (target.analysisId() != null && target.owner() == null)) {
                continue;
            }
            final Decision decision = decide(target, sourcesByComponent, componentsBySource);
            if (target.analysisId() == null) {
                if (decision.consensus() instanceof AssessmentConsensus.Agreed) {
                    drift++;
                }
                continue;
            }
            final long analysisId = requireNonNull(target.analysisId());
            final List<CopiedTrail> trails = trailsByAnalysis.getOrDefault(analysisId, List.of());
            final Change change = AssessmentProjectionDiff.diff(
                    new CurrentProjection(
                            target.owner(),
                            target.decision(),
                            target.details(),
                            target.policyId(),
                            contributors(trails),
                            target.localComment()),
                    decision.consensus());
            if (change.origin() == null
                    || change.origin() == AssessmentOwnership.LOCAL
                    || change.origin() == AssessmentOwnership.POLICY) {
                continue;
            }
            if (change.machineChanged()
                    || change.contributorsChanged()
                    || trailsDiffer(trails, decision.contributions())) {
                drift++;
            }
        }
        return drift;
    }

    /// One source match per source project. Ambiguous identity blocks the finding.
    /// An inactive target attribution withdraws instead of inheriting.
    ///
    /// The marker component and each package descendant are separate target rows.
    /// A descendant decision is never used as the marker component's own decision.
    private static Decision decide(
            final TargetRow target,
            final Map<Long, List<UUID>> sourcesByComponent,
            final Map<UUID, Map<UUID, SourceComponent>> componentsBySource) {
        if (!target.vulnerability().attributionActive()) {
            return new Decision(new AssessmentConsensus.Unavailable(AssessmentReason.FINDING_INACTIVE), List.of());
        }
        final var voters = new ArrayList<SourceAssessment>();
        final var writesByContributor = new LinkedHashMap<Contributor, SourceContributionWrite>();
        for (final UUID sourceProjectUuid : sourcesByComponent.getOrDefault(target.componentId(), List.of())) {
            final Map<UUID, SourceComponent> components = componentsBySource.getOrDefault(sourceProjectUuid, Map.of());
            final var candidates = new ArrayList<SourceCandidate>(components.size());
            for (final SourceComponent component : components.values()) {
                candidates.add(new SourceCandidate(component.identity(), null));
            }
            switch (AssessmentMatcher.match(target.identity(), candidates)) {
                case AssessmentMatcher.MatchResult.Unavailable unavailable -> {
                    if (unavailable.reason() == AssessmentReason.AMBIGUOUS_COMPONENT
                            || unavailable.reason() == AssessmentReason.IDENTITY_CONFLICT) {
                        return new Decision(new AssessmentConsensus.Unavailable(unavailable.reason()), List.of());
                    }
                }
                case AssessmentMatcher.MatchResult.Matched matched ->
                    addVoter(voters, writesByContributor, sourceProjectUuid, target, components, matched.candidate());
            }
        }
        final Result consensus = AssessmentConsensus.resolve(voters);
        if (!(consensus instanceof AssessmentConsensus.Agreed agreed)) {
            return new Decision(consensus, List.of());
        }
        final var writes =
                new ArrayList<SourceContributionWrite>(agreed.contributors().size());
        for (final Contributor contributor : agreed.contributors()) {
            final SourceContributionWrite write = writesByContributor.get(contributor);
            if (write == null) {
                throw new IllegalStateException("Agreed contributor had no source row");
            }
            writes.add(write);
        }
        return new Decision(consensus, writes);
    }

    private static void addVoter(
            final List<SourceAssessment> voters,
            final Map<Contributor, SourceContributionWrite> writesByContributor,
            final UUID sourceProjectUuid,
            final TargetRow target,
            final Map<UUID, SourceComponent> components,
            final SourceCandidate matched) {
        final SourceComponent component = components.get(matched.component().uuid());
        if (component == null) {
            return;
        }
        final SourceAnalysis analysis =
                component.analysisByVulnerability().get(target.vulnerability().vulnerabilityUuid());
        if (analysis == null) {
            return;
        }
        final var sourceVulnerability = new VulnerabilityIdentity(
                analysis.vulnerabilityUuid(), analysis.vulnerabilityId(), analysis.attributionActive());
        switch (AssessmentMatcher.matchVulnerability(target.vulnerability(), sourceVulnerability)) {
            case AssessmentMatcher.VulnerabilityMatch.Same ignored -> {
                if (AssessmentConsensus.eligible(analysis.owner())) {
                    final var contributor = new Contributor(
                            sourceProjectUuid,
                            component.identity().uuid(),
                            analysis.vulnerabilityUuid(),
                            analysis.analysisId());
                    voters.add(new SourceAssessment(
                            contributor, analysis.owner(), analysis.decision(), analysis.details()));
                    writesByContributor.putIfAbsent(
                            contributor,
                            new SourceContributionWrite(
                                    contributor, analysis.details(), List.copyOf(analysis.comments())));
                }
            }
            case AssessmentMatcher.VulnerabilityMatch.Different ignored -> {
                // A different vulnerability row does not vote.
            }
            case AssessmentMatcher.VulnerabilityMatch.Unavailable ignored -> {
                // An inactive source attribution does not vote.
            }
        }
    }

    private static @Nullable PreparedTarget prepareTarget(
            final Handle handle, final long projectId, final TargetRow target, final Result consensus) {
        if (target.analysisId() != null) {
            return new PreparedTarget(
                    target.analysisId(),
                    target.owner(),
                    target.decisionVersion(),
                    target.decision(),
                    target.details(),
                    target.policyId(),
                    target.localComment());
        }
        if (!(consensus instanceof AssessmentConsensus.Agreed)) {
            return null;
        }
        final Long inserted = insertNeutralAnalysis(handle, projectId, target);
        if (inserted != null) {
            return new PreparedTarget(
                    inserted, AssessmentOwnership.NEUTRAL, 0, AssessmentDecision.neutral(), null, null, false);
        }
        return rereadAnalysis(handle, projectId, target);
    }

    private static @Nullable Long insertNeutralAnalysis(
            final Handle handle, final long projectId, final TargetRow target) {
        final Long analysisId = handle.createQuery(/* language=SQL */ """
                        INSERT INTO "ANALYSIS" (
                          "PROJECT_ID"
                        , "COMPONENT_ID"
                        , "VULNERABILITY_ID"
                        , "STATE"
                        , "JUSTIFICATION"
                        , "RESPONSE"
                        , "SUPPRESSED"
                        )
                        VALUES (
                          :projectId
                        , :componentId
                        , :vulnerabilityId
                        , 'NOT_SET'
                        , 'NOT_SET'
                        , 'NOT_SET'
                        , FALSE
                        )
                        ON CONFLICT ("PROJECT_ID", "COMPONENT_ID", "VULNERABILITY_ID") DO NOTHING
                        RETURNING "ID"
                        """)
                .bind("projectId", projectId)
                .bind("componentId", target.componentId())
                .bind("vulnerabilityId", target.vulnerabilityId())
                .mapTo(long.class)
                .findOne()
                .orElse(null);
        if (analysisId == null) {
            return null;
        }
        handle.createUpdate(/* language=SQL */ """
                        INSERT INTO "ASSESSMENT_ORIGIN" ("ANALYSIS_ID", "OWNER")
                        VALUES (:analysisId, 'NEUTRAL')
                        """)
                .bind("analysisId", analysisId)
                .execute();
        return analysisId;
    }

    /// The unique analysis key already existed. A missing origin stays protected.
    private static @Nullable PreparedTarget rereadAnalysis(
            final Handle handle, final long projectId, final TargetRow target) {
        return handle.createQuery(/* language=SQL */ """
                        SELECT a."ID" AS analysis_id
                             , a."STATE" AS state
                             , a."JUSTIFICATION" AS justification
                             , a."RESPONSE" AS response
                             , a."SUPPRESSED" AS suppressed
                             , a."SEVERITY"::text AS severity
                             , a."CVSSV2VECTOR" AS cvss_v2_vector
                             , a."CVSSV2SCORE" AS cvss_v2_score
                             , a."CVSSV3VECTOR" AS cvss_v3_vector
                             , a."CVSSV3SCORE" AS cvss_v3_score
                             , a."CVSSV4VECTOR" AS cvss_v4_vector
                             , a."CVSSV4SCORE" AS cvss_v4_score
                             , a."OWASPVECTOR" AS owasp_vector
                             , a."OWASPSCORE" AS owasp_score
                             , a."DETAILS" AS details
                             , a."VULNERABILITY_POLICY_ID" AS policy_id
                             , o."OWNER" AS owner
                             , o."DECISION_VERSION" AS decision_version
                             , EXISTS (
                                 SELECT 1
                                   FROM "ANALYSISCOMMENT" AS ac
                                  WHERE ac."ANALYSIS_ID" = a."ID"
                               ) AS local_comment
                          FROM "ANALYSIS" AS a
                          LEFT JOIN "ASSESSMENT_ORIGIN" AS o
                            ON o."ANALYSIS_ID" = a."ID"
                         WHERE a."PROJECT_ID" = :projectId
                           AND a."COMPONENT_ID" = :componentId
                           AND a."VULNERABILITY_ID" = :vulnerabilityId
                           FOR UPDATE OF a
                        """)
                .bind("projectId", projectId)
                .bind("componentId", target.componentId())
                .bind("vulnerabilityId", target.vulnerabilityId())
                .map((rs, ctx) -> {
                    final String owner = rs.getString("owner");
                    if (owner == null) {
                        return null;
                    }
                    final AssessmentOwnership ownership = AssessmentOwnership.valueOf(owner);
                    if (ownership == AssessmentOwnership.LOCAL || ownership == AssessmentOwnership.POLICY) {
                        return null;
                    }
                    return new PreparedTarget(
                            rs.getLong("analysis_id"),
                            ownership,
                            rs.getLong("decision_version"),
                            readDecision(rs),
                            rs.getString("details"),
                            nullableLong(rs, "policy_id"),
                            rs.getBoolean("local_comment"));
                })
                .findOne()
                .orElse(null);
    }

    private static void emitAuditChanges(final Handle handle, final List<AuditNotice> audits) {
        if (audits.isEmpty()) {
            return;
        }
        final var subjectDao = handle.attach(NotificationSubjectDao.class);
        if (!subjectDao.getSubscribedNotificationGroups().contains(NotificationGroup.PROJECT_AUDIT_CHANGE.name())) {
            return;
        }
        final var queries = new ArrayList<GetProjectAuditChangeNotificationSubjectQuery>(audits.size());
        for (final AuditNotice audit : audits) {
            queries.add(new GetProjectAuditChangeNotificationSubjectQuery(
                    audit.componentId(), audit.vulnerabilityId(), audit.state(), audit.suppressed()));
        }
        final var subjects = subjectDao.getForProjectAuditChanges(queries);
        final var notifications = new ArrayList<Notification>(subjects.size());
        for (int i = 0; i < subjects.size() && i < audits.size(); i++) {
            final AuditNotice audit = audits.get(i);
            final var subject = subjects.get(i);
            notifications.add(createVulnerabilityAnalysisDecisionChangeNotification(
                    subject.getProject(),
                    subject.getComponent(),
                    subject.getVulnerability(),
                    subject.getAnalysis(),
                    audit.stateChanged(),
                    audit.suppressionChanged()));
        }
        if (!notifications.isEmpty()) {
            new JdbiNotificationEmitter(handle).emitAll(notifications);
        }
    }

    private static void lockAnalyses(final Handle handle, final long projectId, final List<FindingKey> keys) {
        final long[] componentIds = componentIds(keys);
        final long[] vulnerabilityIds = vulnerabilityIds(keys);
        handle.createQuery(/* language=SQL */ """
                        SELECT a."ID"
                          FROM "ANALYSIS" AS a
                         INNER JOIN UNNEST(:componentIds, :vulnerabilityIds)
                            AS k(component_id, vulnerability_id)
                            ON k.component_id = a."COMPONENT_ID"
                           AND k.vulnerability_id = a."VULNERABILITY_ID"
                         WHERE a."PROJECT_ID" = :projectId
                         ORDER BY a."COMPONENT_ID", a."VULNERABILITY_ID"
                           FOR UPDATE
                        """)
                .bind("projectId", projectId)
                .bind("componentIds", componentIds)
                .bind("vulnerabilityIds", vulnerabilityIds)
                .mapTo(long.class)
                .list();
    }

    private static @Nullable Long projectId(final Handle handle, final UUID targetUuid) {
        return handle.createQuery(/* language=SQL */ """
                        SELECT "ID"
                          FROM "PROJECT"
                         WHERE "UUID" = :targetUuid
                        """)
                .bind("targetUuid", targetUuid)
                .mapTo(long.class)
                .findOne()
                .orElse(null);
    }

    private static Map<FindingKey, TargetRow> loadTargets(
            final Handle handle, final long projectId, final List<FindingKey> keys) {
        final Map<FindingKey, TargetRow> targets = new LinkedHashMap<>();
        handle.createQuery(/* language=SQL */ """
                        SELECT c."ID" AS component_id
                             , c."UUID" AS component_uuid
                             , c."CLASSIFIER" AS classifier
                             , c."NAME" AS component_name
                             , c."VERSION" AS component_version
                             , c."PURL" AS purl
                             , c."CPE" AS cpe
                             , c."MD5" AS md5
                             , c."SHA1" AS sha1
                             , c."SHA_256" AS sha256
                             , c."SHA_384" AS sha384
                             , c."SHA_512" AS sha512
                             , c."SHA3_256" AS sha3_256
                             , c."SHA3_384" AS sha3_384
                             , c."SHA3_512" AS sha3_512
                             , c."BLAKE2B_256" AS blake2b_256
                             , c."BLAKE2B_384" AS blake2b_384
                             , c."BLAKE2B_512" AS blake2b_512
                             , c."BLAKE3" AS blake3
                             , c."STREEBOG_256" AS streebog_256
                             , c."STREEBOG_512" AS streebog_512
                             , v."ID" AS vulnerability_id
                             , v."UUID" AS vulnerability_uuid
                             , v."VULNID" AS vuln_id
                             , EXISTS (
                                 SELECT 1
                                   FROM "FINDINGATTRIBUTION" AS fa
                                  WHERE fa."COMPONENT_ID" = c."ID"
                                    AND fa."VULNERABILITY_ID" = v."ID"
                                    AND fa."DELETED_AT" IS NULL
                               ) AS attribution_active
                             , a."ID" AS analysis_id
                             , a."STATE" AS state
                             , a."JUSTIFICATION" AS justification
                             , a."RESPONSE" AS response
                             , a."SUPPRESSED" AS suppressed
                             , a."SEVERITY"::text AS severity
                             , a."CVSSV2VECTOR" AS cvss_v2_vector
                             , a."CVSSV2SCORE" AS cvss_v2_score
                             , a."CVSSV3VECTOR" AS cvss_v3_vector
                             , a."CVSSV3SCORE" AS cvss_v3_score
                             , a."CVSSV4VECTOR" AS cvss_v4_vector
                             , a."CVSSV4SCORE" AS cvss_v4_score
                             , a."OWASPVECTOR" AS owasp_vector
                             , a."OWASPSCORE" AS owasp_score
                             , a."DETAILS" AS details
                             , a."VULNERABILITY_POLICY_ID" AS policy_id
                             , o."OWNER" AS owner
                             , o."DECISION_VERSION" AS decision_version
                             , EXISTS (
                                 SELECT 1
                                   FROM "ANALYSISCOMMENT" AS ac
                                  WHERE ac."ANALYSIS_ID" = a."ID"
                               ) AS local_comment
                          FROM UNNEST(:componentIds, :vulnerabilityIds) AS k(component_id, vulnerability_id)
                         INNER JOIN "COMPONENT" AS c
                            ON c."ID" = k.component_id
                           AND c."PROJECT_ID" = :projectId
                         INNER JOIN "VULNERABILITY" AS v
                            ON v."ID" = k.vulnerability_id
                          LEFT JOIN "ANALYSIS" AS a
                            ON a."PROJECT_ID" = :projectId
                           AND a."COMPONENT_ID" = c."ID"
                           AND a."VULNERABILITY_ID" = v."ID"
                          LEFT JOIN "ASSESSMENT_ORIGIN" AS o
                            ON o."ANALYSIS_ID" = a."ID"
                        """)
                .bind("projectId", projectId)
                .bind("componentIds", componentIds(keys))
                .bind("vulnerabilityIds", vulnerabilityIds(keys))
                .map((rs, ctx) -> {
                    final long componentId = rs.getLong("component_id");
                    final long vulnerabilityId = rs.getLong("vulnerability_id");
                    final UUID componentUuid = rs.getObject("component_uuid", UUID.class);
                    final UUID vulnerabilityUuid = rs.getObject("vulnerability_uuid", UUID.class);
                    if (componentUuid == null || vulnerabilityUuid == null) {
                        return null;
                    }
                    final Long analysisId = nullableLong(rs, "analysis_id");
                    final String owner = rs.getString("owner");
                    final TargetRow row = new TargetRow(
                            componentId,
                            vulnerabilityId,
                            new ComponentIdentity(
                                    componentUuid,
                                    classifier(rs.getString("classifier")),
                                    rs.getString("component_name"),
                                    rs.getString("component_version"),
                                    rs.getString("purl"),
                                    rs.getString("cpe"),
                                    hashes(rs)),
                            new VulnerabilityIdentity(
                                    vulnerabilityUuid, rs.getString("vuln_id"), rs.getBoolean("attribution_active")),
                            analysisId,
                            owner == null ? null : AssessmentOwnership.valueOf(owner),
                            owner == null ? 0 : rs.getLong("decision_version"),
                            analysisId == null ? AssessmentDecision.neutral() : readDecision(rs),
                            rs.getString("details"),
                            nullableLong(rs, "policy_id"),
                            rs.getBoolean("local_comment"));
                    targets.put(new FindingKey(componentId, vulnerabilityId), row);
                    return row;
                })
                .list();
        return targets;
    }

    private static Map<Long, List<UUID>> sourceProjects(
            final Handle handle, final UUID targetUuid, final long projectId, final List<FindingKey> keys) {
        final var componentIds = new long[keys.size()];
        for (int i = 0; i < keys.size(); i++) {
            componentIds[i] = keys.get(i).componentId();
        }
        final List<MarkerLink> links = handle.createQuery(/* language=SQL */ """
                        SELECT link.component_id
                             , e."MARKER_NAME" AS marker_name
                             , e."MARKER_VERSION" AS marker_version
                          FROM "ASSESSMENT_EMBEDDING" AS e
                         INNER JOIN (
                               SELECT "MARKER_COMPONENT_ID" AS marker_component_id
                                    , "MARKER_COMPONENT_ID" AS component_id
                                 FROM "ASSESSMENT_EMBEDDING"
                                WHERE "TARGET_PROJECT_ID" = :projectId
                                  AND "MARKER_COMPONENT_ID" IN (
                                    SELECT component_id FROM UNNEST(:componentIds) AS page(component_id)
                                  )
                               UNION
                               SELECT "MARKER_COMPONENT_ID"
                                    , "COMPONENT_ID"
                                 FROM "ASSESSMENT_EMBEDDING_MEMBER"
                                WHERE "TARGET_PROJECT_ID" = :projectId
                                  AND "COMPONENT_ID" IN (
                                    SELECT component_id FROM UNNEST(:componentIds) AS page(component_id)
                                  )
                           ) AS link
                            ON link.marker_component_id = e."MARKER_COMPONENT_ID"
                         WHERE e."TARGET_PROJECT_ID" = :projectId
                        """)
                .bind("projectId", projectId)
                .bind("componentIds", componentIds)
                .map((rs, ctx) -> new MarkerLink(
                        rs.getLong("component_id"), rs.getString("marker_name"), rs.getString("marker_version")))
                .list();
        if (links.isEmpty()) {
            return Map.of();
        }
        final var identities = new LinkedHashSet<Identity>();
        for (final MarkerLink link : links) {
            if (link.name() != null && link.version() != null) {
                identities.add(new Identity(link.name(), link.version()));
            }
        }
        // Resolved again at reconcile time so a stale index cannot keep a source that is gone or now gated.
        final Map<Identity, UUID> sourceByIdentity = AssessmentSourceResolver.resolve(handle, targetUuid, identities);
        final var sourcesByComponent = new LinkedHashMap<Long, List<UUID>>();
        for (final MarkerLink link : links) {
            if (link.name() == null || link.version() == null) {
                continue;
            }
            final UUID source = sourceByIdentity.get(new Identity(link.name(), link.version()));
            if (source == null) {
                continue;
            }
            final List<UUID> sources =
                    sourcesByComponent.computeIfAbsent(link.componentId(), ignored -> new ArrayList<>());
            if (!sources.contains(source)) {
                sources.add(source);
            }
        }
        return sourcesByComponent;
    }

    private static Map<UUID, Map<UUID, SourceComponent>> loadSourceComponents(
            final Handle handle, final Map<Long, List<UUID>> sourcesByComponent, final List<FindingKey> keys) {
        final var sourceUuids = new LinkedHashMap<UUID, UUID>();
        for (final List<UUID> sources : sourcesByComponent.values()) {
            for (final UUID sourceUuid : sources) {
                sourceUuids.putIfAbsent(sourceUuid, sourceUuid);
            }
        }
        if (sourceUuids.isEmpty()) {
            return Map.of();
        }
        final var vulnerabilityIds = vulnerabilityIds(keys);
        final var grouped = new LinkedHashMap<UUID, Map<UUID, SourceComponentBuilder>>();
        handle.createQuery(/* language=SQL */ """
                        SELECT p."UUID" AS source_project_uuid
                             , c."UUID" AS component_uuid
                             , c."CLASSIFIER" AS classifier
                             , c."NAME" AS component_name
                             , c."VERSION" AS component_version
                             , c."PURL" AS purl
                             , c."CPE" AS cpe
                             , c."MD5" AS md5
                             , c."SHA1" AS sha1
                             , c."SHA_256" AS sha256
                             , c."SHA_384" AS sha384
                             , c."SHA_512" AS sha512
                             , c."SHA3_256" AS sha3_256
                             , c."SHA3_384" AS sha3_384
                             , c."SHA3_512" AS sha3_512
                             , c."BLAKE2B_256" AS blake2b_256
                             , c."BLAKE2B_384" AS blake2b_384
                             , c."BLAKE2B_512" AS blake2b_512
                             , c."BLAKE3" AS blake3
                             , c."STREEBOG_256" AS streebog_256
                             , c."STREEBOG_512" AS streebog_512
                             , a."ID" AS analysis_id
                             , a."DETAILS" AS details
                             , a."STATE" AS state
                             , a."JUSTIFICATION" AS justification
                             , a."RESPONSE" AS response
                             , a."SUPPRESSED" AS suppressed
                             , a."SEVERITY"::text AS severity
                             , a."CVSSV2VECTOR" AS cvss_v2_vector
                             , a."CVSSV2SCORE" AS cvss_v2_score
                             , a."CVSSV3VECTOR" AS cvss_v3_vector
                             , a."CVSSV3SCORE" AS cvss_v3_score
                             , a."CVSSV4VECTOR" AS cvss_v4_vector
                             , a."CVSSV4SCORE" AS cvss_v4_score
                             , a."OWASPVECTOR" AS owasp_vector
                             , a."OWASPSCORE" AS owasp_score
                             , o."OWNER" AS owner
                             , v."UUID" AS vulnerability_uuid
                             , v."VULNID" AS vuln_id
                             , CASE
                                 WHEN a."ID" IS NULL THEN FALSE
                                 ELSE EXISTS (
                                   SELECT 1
                                     FROM "FINDINGATTRIBUTION" AS fa
                                    WHERE fa."COMPONENT_ID" = c."ID"
                                      AND fa."VULNERABILITY_ID" = a."VULNERABILITY_ID"
                                      AND fa."DELETED_AT" IS NULL
                                 )
                               END AS attribution_active
                          FROM UNNEST(:sourceUuids) AS src(source_uuid)
                         INNER JOIN "PROJECT" AS p
                            ON p."UUID" = src.source_uuid
                         INNER JOIN "COMPONENT" AS c
                            ON c."PROJECT_ID" = p."ID"
                          LEFT JOIN "ANALYSIS" AS a
                            ON a."PROJECT_ID" = p."ID"
                           AND a."COMPONENT_ID" = c."ID"
                           AND a."VULNERABILITY_ID" IN (
                             SELECT vulnerability_id
                               FROM UNNEST(:vulnerabilityIds) AS wanted(vulnerability_id)
                           )
                          LEFT JOIN "VULNERABILITY" AS v
                            ON v."ID" = a."VULNERABILITY_ID"
                          LEFT JOIN "ASSESSMENT_ORIGIN" AS o
                            ON o."ANALYSIS_ID" = a."ID"
                        """)
                .bind("sourceUuids", sourceUuids.keySet().toArray(UUID[]::new))
                .bind("vulnerabilityIds", vulnerabilityIds)
                .map((rs, ctx) -> {
                    final UUID sourceProjectUuid = rs.getObject("source_project_uuid", UUID.class);
                    final UUID componentUuid = rs.getObject("component_uuid", UUID.class);
                    if (sourceProjectUuid == null || componentUuid == null) {
                        return null;
                    }
                    final var identity = new ComponentIdentity(
                            componentUuid,
                            classifier(rs.getString("classifier")),
                            rs.getString("component_name"),
                            rs.getString("component_version"),
                            rs.getString("purl"),
                            rs.getString("cpe"),
                            hashes(rs));
                    final var builder = grouped.computeIfAbsent(sourceProjectUuid, ignored -> new LinkedHashMap<>())
                            .computeIfAbsent(componentUuid, ignored -> new SourceComponentBuilder(identity));
                    final Long analysisId = nullableLong(rs, "analysis_id");
                    final UUID vulnerabilityUuid = rs.getObject("vulnerability_uuid", UUID.class);
                    if (analysisId != null && vulnerabilityUuid != null) {
                        final String owner = rs.getString("owner");
                        builder.analyses()
                                .put(
                                        vulnerabilityUuid,
                                        new SourceAnalysis(
                                                analysisId,
                                                vulnerabilityUuid,
                                                rs.getString("vuln_id"),
                                                rs.getBoolean("attribution_active"),
                                                owner == null ? null : AssessmentOwnership.valueOf(owner),
                                                readDecision(rs),
                                                rs.getString("details"),
                                                new ArrayList<>()));
                    }
                    return sourceProjectUuid;
                })
                .list();
        attachComments(handle, sourceUuids.keySet().toArray(UUID[]::new), vulnerabilityIds, grouped);
        final var components = new LinkedHashMap<UUID, Map<UUID, SourceComponent>>();
        for (final var project : grouped.entrySet()) {
            final var projectComponents = new LinkedHashMap<UUID, SourceComponent>();
            for (final var component : project.getValue().entrySet()) {
                projectComponents.put(
                        component.getKey(),
                        new SourceComponent(
                                component.getValue().identity(),
                                Map.copyOf(component.getValue().analyses())));
            }
            components.put(project.getKey(), projectComponents);
        }
        return components;
    }

    private static void attachComments(
            final Handle handle,
            final UUID[] sourceUuids,
            final long[] vulnerabilityIds,
            final Map<UUID, Map<UUID, SourceComponentBuilder>> grouped) {
        final var byAnalysis = new LinkedHashMap<Long, SourceAnalysis>();
        for (final Map<UUID, SourceComponentBuilder> components : grouped.values()) {
            for (final SourceComponentBuilder builder : components.values()) {
                for (final SourceAnalysis analysis : builder.analyses().values()) {
                    byAnalysis.put(analysis.analysisId(), analysis);
                }
            }
        }
        if (byAnalysis.isEmpty()) {
            return;
        }
        handle.createQuery(/* language=SQL */ """
                        SELECT a."ID" AS analysis_id
                             , ac."ID" AS comment_id
                             , ac."COMMENT" AS comment
                             , ac."COMMENTER" AS commenter
                             , ac."TIMESTAMP" AS original_timestamp
                          FROM "ANALYSISCOMMENT" AS ac
                         INNER JOIN "ANALYSIS" AS a
                            ON a."ID" = ac."ANALYSIS_ID"
                         INNER JOIN "PROJECT" AS p
                            ON p."ID" = a."PROJECT_ID"
                         INNER JOIN UNNEST(:sourceUuids) AS src(source_uuid)
                            ON src.source_uuid = p."UUID"
                         WHERE a."VULNERABILITY_ID" IN (
                           SELECT vulnerability_id
                             FROM UNNEST(:vulnerabilityIds) AS wanted(vulnerability_id)
                         )
                         ORDER BY a."ID", ac."ID"
                        """)
                .bind("sourceUuids", sourceUuids)
                .bind("vulnerabilityIds", vulnerabilityIds)
                .map((rs, ctx) -> {
                    final SourceAnalysis analysis = byAnalysis.get(rs.getLong("analysis_id"));
                    final String comment = rs.getString("comment");
                    final Instant timestamp = readInstant(rs, "original_timestamp");
                    if (analysis == null || comment == null || timestamp == null) {
                        return null;
                    }
                    analysis.comments()
                            .add(new SourceCommentWrite(
                                    rs.getLong("comment_id"), comment, rs.getString("commenter"), timestamp));
                    return analysis.analysisId();
                })
                .list();
    }

    private static Map<Long, List<CopiedTrail>> loadTrails(
            final Handle handle, final Map<FindingKey, TargetRow> targets) {
        final var analysisIds = new ArrayList<Long>();
        for (final TargetRow target : targets.values()) {
            if (target.analysisId() != null) {
                analysisIds.add(target.analysisId());
            }
        }
        if (analysisIds.isEmpty()) {
            return Map.of();
        }
        final var ids = new long[analysisIds.size()];
        for (int i = 0; i < analysisIds.size(); i++) {
            ids[i] = analysisIds.get(i);
        }
        final var trails = new LinkedHashMap<Long, LinkedHashMap<TrailKey, CopiedTrailBuilder>>();
        handle.createQuery(/* language=SQL */ """
                        SELECT c."TARGET_ANALYSIS_ID" AS analysis_id
                             , c."SOURCE_PROJECT_UUID" AS source_project_uuid
                             , c."SOURCE_COMPONENT_UUID" AS source_component_uuid
                             , c."SOURCE_VULNERABILITY_UUID" AS source_vulnerability_uuid
                             , c."SOURCE_ANALYSIS_ID" AS source_analysis_id
                             , c."SOURCE_DETAILS" AS source_details
                             , m."SOURCE_COMMENT_ID" AS comment_id
                             , m."COMMENT" AS comment
                             , m."COMMENTER" AS commenter
                             , m."ORIGINAL_TIMESTAMP" AS original_timestamp
                          FROM "ASSESSMENT_SOURCE_CONTRIBUTION" AS c
                          LEFT JOIN "ASSESSMENT_SOURCE_COMMENT" AS m
                            ON m."TARGET_ANALYSIS_ID" = c."TARGET_ANALYSIS_ID"
                           AND m."SOURCE_PROJECT_UUID" = c."SOURCE_PROJECT_UUID"
                           AND m."SOURCE_ANALYSIS_ID" = c."SOURCE_ANALYSIS_ID"
                         WHERE c."TARGET_ANALYSIS_ID" IN (
                           SELECT analysis_id FROM UNNEST(:analysisIds) AS page(analysis_id)
                         )
                         ORDER BY c."TARGET_ANALYSIS_ID"
                                , c."SOURCE_PROJECT_UUID"
                                , c."SOURCE_ANALYSIS_ID"
                                , m."SOURCE_COMMENT_ID"
                        """)
                .bind("analysisIds", ids)
                .map((rs, ctx) -> {
                    final UUID sourceProjectUuid = rs.getObject("source_project_uuid", UUID.class);
                    final UUID sourceComponentUuid = rs.getObject("source_component_uuid", UUID.class);
                    final UUID sourceVulnerabilityUuid = rs.getObject("source_vulnerability_uuid", UUID.class);
                    if (sourceProjectUuid == null || sourceComponentUuid == null || sourceVulnerabilityUuid == null) {
                        return null;
                    }
                    final long analysisId = rs.getLong("analysis_id");
                    final long sourceAnalysisId = rs.getLong("source_analysis_id");
                    final var contributor = new Contributor(
                            sourceProjectUuid, sourceComponentUuid, sourceVulnerabilityUuid, sourceAnalysisId);
                    final String sourceDetails = rs.getString("source_details");
                    final var key = new TrailKey(sourceProjectUuid, sourceAnalysisId);
                    final var builder = trails.computeIfAbsent(analysisId, ignored -> new LinkedHashMap<>())
                            .computeIfAbsent(key, ignored -> new CopiedTrailBuilder(contributor, sourceDetails));
                    final Long commentId = nullableLong(rs, "comment_id");
                    final String comment = rs.getString("comment");
                    final Instant timestamp = readInstant(rs, "original_timestamp");
                    if (commentId != null && comment != null && timestamp != null) {
                        builder.comments()
                                .add(new SourceCommentWrite(commentId, comment, rs.getString("commenter"), timestamp));
                    }
                    return analysisId;
                })
                .list();
        final var copied = new LinkedHashMap<Long, List<CopiedTrail>>();
        for (final var analysis : trails.entrySet()) {
            final var analysisTrails = new ArrayList<CopiedTrail>();
            for (final CopiedTrailBuilder builder : analysis.getValue().values()) {
                analysisTrails.add(
                        new CopiedTrail(builder.contributor(), builder.details(), List.copyOf(builder.comments())));
            }
            copied.put(analysis.getKey(), analysisTrails);
        }
        return copied;
    }

    private static List<Contributor> contributors(final List<CopiedTrail> trails) {
        final var contributors = new ArrayList<Contributor>(trails.size());
        for (final CopiedTrail trail : trails) {
            contributors.add(trail.contributor());
        }
        return contributors;
    }

    private static boolean trailsDiffer(final List<CopiedTrail> current, final List<SourceContributionWrite> desired) {
        if (current.size() != desired.size()) {
            return true;
        }
        final var currentByKey = new LinkedHashMap<TrailKey, CopiedTrail>();
        for (final CopiedTrail trail : current) {
            currentByKey.put(
                    new TrailKey(
                            trail.contributor().sourceProjectUuid(),
                            trail.contributor().sourceAnalysisId()),
                    trail);
        }
        for (final SourceContributionWrite write : desired) {
            final CopiedTrail trail = currentByKey.get(new TrailKey(
                    write.contributor().sourceProjectUuid(), write.contributor().sourceAnalysisId()));
            if (trail == null || !Objects.equals(trail.details(), write.sourceDetails())) {
                return true;
            }
            if (trail.comments().size() != write.comments().size()) {
                return true;
            }
            for (int i = 0; i < trail.comments().size(); i++) {
                final SourceCommentWrite left = trail.comments().get(i);
                final SourceCommentWrite right = write.comments().get(i);
                if (left.sourceCommentId() != right.sourceCommentId()
                        || !left.comment().equals(right.comment())
                        || !Objects.equals(left.commenter(), right.commenter())
                        || !left.originalTimestamp().equals(right.originalTimestamp())) {
                    return true;
                }
            }
        }
        return false;
    }

    private static List<FindingKey> dedupe(final List<FindingKey> findingKeys) {
        final var ordered = new ArrayList<FindingKey>(findingKeys);
        ordered.sort(Comparator.comparingLong(FindingKey::componentId).thenComparingLong(FindingKey::vulnDbId));
        final var unique = new ArrayList<FindingKey>(ordered.size());
        FindingKey previous = null;
        for (final FindingKey key : ordered) {
            requireNonNull(key, "finding key must not be null");
            if (previous == null || !previous.equals(key)) {
                unique.add(key);
                previous = key;
            }
        }
        return unique;
    }

    private static long[] componentIds(final List<FindingKey> keys) {
        final var ids = new long[keys.size()];
        for (int i = 0; i < keys.size(); i++) {
            ids[i] = keys.get(i).componentId();
        }
        return ids;
    }

    private static long[] vulnerabilityIds(final List<FindingKey> keys) {
        final var ids = new long[keys.size()];
        for (int i = 0; i < keys.size(); i++) {
            ids[i] = keys.get(i).vulnDbId();
        }
        return ids;
    }

    private static Map<HashAlgorithm, String> hashes(final ResultSet rs) throws SQLException {
        final var hashes = new EnumMap<HashAlgorithm, String>(HashAlgorithm.class);
        putHash(hashes, HashAlgorithm.MD5, rs.getString("md5"));
        putHash(hashes, HashAlgorithm.SHA1, rs.getString("sha1"));
        putHash(hashes, HashAlgorithm.SHA256, rs.getString("sha256"));
        putHash(hashes, HashAlgorithm.SHA384, rs.getString("sha384"));
        putHash(hashes, HashAlgorithm.SHA512, rs.getString("sha512"));
        putHash(hashes, HashAlgorithm.SHA3_256, rs.getString("sha3_256"));
        putHash(hashes, HashAlgorithm.SHA3_384, rs.getString("sha3_384"));
        putHash(hashes, HashAlgorithm.SHA3_512, rs.getString("sha3_512"));
        putHash(hashes, HashAlgorithm.BLAKE2B_256, rs.getString("blake2b_256"));
        putHash(hashes, HashAlgorithm.BLAKE2B_384, rs.getString("blake2b_384"));
        putHash(hashes, HashAlgorithm.BLAKE2B_512, rs.getString("blake2b_512"));
        putHash(hashes, HashAlgorithm.BLAKE3, rs.getString("blake3"));
        putHash(hashes, HashAlgorithm.STREEBOG_256, rs.getString("streebog_256"));
        putHash(hashes, HashAlgorithm.STREEBOG_512, rs.getString("streebog_512"));
        return hashes;
    }

    private static void putHash(
            final Map<HashAlgorithm, String> hashes, final HashAlgorithm algorithm, final @Nullable String value) {
        if (value != null && !value.isBlank()) {
            hashes.put(algorithm, value);
        }
    }

    private static @Nullable Classifier classifier(final @Nullable String classifier) {
        if (classifier == null || classifier.isBlank()) {
            return null;
        }
        return Classifier.valueOf(classifier);
    }

    private static AssessmentDecision readDecision(final ResultSet rs) throws SQLException {
        final String severity = rs.getString("severity");
        final String justification = rs.getString("justification");
        final String response = rs.getString("response");
        final String state = rs.getString("state");
        return AssessmentDecision.of(
                state == null ? AnalysisState.NOT_SET : AnalysisState.valueOf(state),
                justification == null ? null : AnalysisJustification.valueOf(justification),
                response == null ? null : AnalysisResponse.valueOf(response),
                rs.getBoolean("suppressed"),
                severity == null ? null : Severity.valueOf(severity),
                rs.getString("cvss_v2_vector"),
                rs.getBigDecimal("cvss_v2_score"),
                rs.getString("cvss_v3_vector"),
                rs.getBigDecimal("cvss_v3_score"),
                rs.getString("cvss_v4_vector"),
                rs.getBigDecimal("cvss_v4_score"),
                rs.getString("owasp_vector"),
                rs.getBigDecimal("owasp_score"));
    }

    private static @Nullable Long nullableLong(final ResultSet rs, final String column) throws SQLException {
        final long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    private static @Nullable Instant readInstant(final ResultSet rs, final String column) throws SQLException {
        final OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
        return value == null ? null : value.toInstant();
    }

    private record TargetRow(
            long componentId,
            long vulnerabilityId,
            ComponentIdentity identity,
            VulnerabilityIdentity vulnerability,
            @Nullable Long analysisId,
            @Nullable AssessmentOwnership owner,
            long decisionVersion,
            AssessmentDecision decision,
            @Nullable String details,
            @Nullable Long policyId,
            boolean localComment) {}

    private record PreparedTarget(
            long analysisId,
            @Nullable AssessmentOwnership owner,
            long decisionVersion,
            AssessmentDecision decision,
            @Nullable String details,
            @Nullable Long policyId,
            boolean localComment) {}

    private record SourceComponent(ComponentIdentity identity, Map<UUID, SourceAnalysis> analysisByVulnerability) {}

    private record SourceAnalysis(
            long analysisId,
            UUID vulnerabilityUuid,
            @Nullable String vulnerabilityId,
            boolean attributionActive,
            @Nullable AssessmentOwnership owner,
            AssessmentDecision decision,
            @Nullable String details,
            List<SourceCommentWrite> comments) {}

    private record SourceComponentBuilder(ComponentIdentity identity, Map<UUID, SourceAnalysis> analyses) {

        private SourceComponentBuilder(final ComponentIdentity identity) {
            this(identity, new LinkedHashMap<>());
        }
    }

    private record MarkerLink(
            long componentId,
            @Nullable String name,
            @Nullable String version) {}

    private record CopiedTrail(
            Contributor contributor, @Nullable String details, List<SourceCommentWrite> comments) {}

    private record CopiedTrailBuilder(
            Contributor contributor, @Nullable String details, List<SourceCommentWrite> comments) {

        private CopiedTrailBuilder(final Contributor contributor, final @Nullable String details) {
            this(contributor, details, new ArrayList<>());
        }
    }

    private record TrailKey(UUID sourceProjectUuid, long sourceAnalysisId) {}

    private record AuditNotice(
            long componentId,
            long vulnerabilityId,
            AnalysisState state,
            boolean suppressed,
            boolean stateChanged,
            boolean suppressionChanged) {}

    /// Consensus plus the contribution rows to copy when the sources agree.
    private record Decision(Result consensus, List<SourceContributionWrite> contributions) {}
}
