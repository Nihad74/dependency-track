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
package org.dependencytrack.analysis;

import org.dependencytrack.assessmentsync.AssessmentChange;
import org.dependencytrack.assessmentsync.AssessmentChangeRecorder;
import org.dependencytrack.assessmentsync.AssessmentMutationGuard;
import org.dependencytrack.assessmentsync.AssessmentOriginDao;
import org.dependencytrack.assessmentsync.AssessmentOwnership;
import org.dependencytrack.assessmentsync.AssessmentReason;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Severity;
import org.dependencytrack.notification.GetProjectAuditChangeNotificationSubjectQuery;
import org.dependencytrack.notification.JdbiNotificationEmitter;
import org.dependencytrack.notification.NotificationSubjectDao;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;

import java.math.BigDecimal;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.notification.api.NotificationFactory.createVulnerabilityAnalysisDecisionChangeNotification;

/** Executes authored analysis plans in the caller's transaction, using scalar identities and batched writes. */
public final class AnalysisWriter {
    private AnalysisWriter() {}

    public record Finding(
            long projectId,
            UUID projectUuid,
            @Nullable String projectName,
            @Nullable String projectVersion,
            long componentId,
            UUID componentUuid,
            long vulnerabilityId,
            UUID vulnerabilityUuid) {}

    public record Entry(
            AnalysisMutationPlanner.Request request,
            Finding finding,
            @Nullable String commenter) {}

    private record Key(long componentId, long vulnerabilityId) {}

    private record StoredAnalysis(
            long id, Key key, AnalysisValues values, AssessmentOriginDao.@Nullable Origin origin) {}

    private record Planned(Entry entry, AnalysisMutationPlanner.Plan plan) {
        Key key() {
            return new Key(entry.finding().componentId(), entry.finding().vulnerabilityId());
        }
    }

    public static long write(
            final Handle handle,
            final AnalysisMutationPlanner.Request command,
            final Finding finding,
            final @Nullable String commenter) {
        return writeAll(handle, List.of(new Entry(command, finding, commenter))).getFirst();
    }

    /**
     * Applies one change per finding in a bounded caller-supplied batch. Duplicate findings must be sent
     * in successive batches, so their versions and audit trails retain request order. The caller owns the
     * transaction; all plans are validated before any mutation is executed.
     */
    public static List<Long> writeAll(final Handle handle, final List<Entry> entries) {
        if (entries.isEmpty()) {
            return List.of();
        }
        final var keys = new HashSet<Key>();
        for (final var entry : entries) {
            if (!keys.add(new Key(entry.finding().componentId(), entry.finding().vulnerabilityId()))) {
                throw new IllegalArgumentException("A batch may change each finding only once");
            }
        }
        AssessmentMutationGuard.lockProjects(
                handle, entries.stream().map(e -> e.finding().projectUuid()).toList());
        final Map<Key, StoredAnalysis> stored = loadAndLockAnalyses(handle, entries);
        final var plans = new ArrayList<Planned>(entries.size());
        final var ids = new HashMap<Key, Long>();
        for (final var entry : entries) {
            final var key =
                    new Key(entry.finding().componentId(), entry.finding().vulnerabilityId());
            final var previous = stored.get(key);
            if (previous != null) {
                ids.put(key, previous.id());
            }
            plans.add(new Planned(
                    entry,
                    AnalysisMutationPlanner.plan(
                            entry.request(),
                            previous == null ? null : previous.values(),
                            previous == null ? null : previous.origin())));
        }
        final var mutations = plans.stream()
                .filter(p -> !stored.containsKey(p.key()) || p.plan().valuesChanged())
                .toList();
        if (!mutations.isEmpty()) {
            ids.putAll(upsertAnalyses(handle, mutations));
        }
        insertComments(handle, plans, ids);
        final var dao = new AssessmentOriginDao(handle);
        dao.deleteCopiedContributions(plans.stream()
                .filter(p -> p.plan().dropCopiedTrail())
                .map(p -> requireNonNull(ids.get(p.key())))
                .toList());
        dao.upsertOrigins(plans.stream()
                .filter(p -> p.plan().owner() != null)
                .map(p -> new AssessmentOriginDao.OriginUpdate(
                        requireNonNull(ids.get(p.key())),
                        requireNonNull(p.plan().owner()),
                        p.plan().advanceDecisionVersion()))
                .toList());
        new AssessmentChangeRecorder(handle)
                .recordAll(plans.stream()
                        .filter(p -> p.plan().recordChange())
                        .map(p -> AssessmentChange.finding(
                                p.entry().finding().projectUuid(),
                                p.entry().finding().componentUuid(),
                                p.entry().finding().vulnerabilityUuid(),
                                AssessmentChange.Reason.AUTHORED,
                                p.entry().finding().projectName(),
                                p.entry().finding().projectVersion()))
                        .toList());
        emitDecisionChanges(handle, plans);
        return plans.stream().map(p -> requireNonNull(ids.get(p.key()))).toList();
    }

    private static Map<Key, StoredAnalysis> loadAndLockAnalyses(final Handle handle, final List<Entry> entries) {
        final var rows = handle.createQuery("""
                SELECT a."ID", a."COMPONENT_ID", a."VULNERABILITY_ID",
                       a."STATE", a."JUSTIFICATION", a."RESPONSE", a."DETAILS", a."SUPPRESSED",
                       a."SEVERITY"::text AS severity_text,
                       a."CVSSV2VECTOR", a."CVSSV2SCORE", a."CVSSV3VECTOR", a."CVSSV3SCORE",
                       a."CVSSV4VECTOR", a."CVSSV4SCORE", a."OWASPVECTOR", a."OWASPSCORE", a."VULNERABILITY_POLICY_ID",
                       o."OWNER", o."DECISION_VERSION", o."LAST_REASON"
                  FROM "ANALYSIS" AS a
                 INNER JOIN UNNEST(:components, :vulnerabilities) AS t(component_id, vulnerability_id)
                    ON a."COMPONENT_ID" = t.component_id AND a."VULNERABILITY_ID" = t.vulnerability_id
                  LEFT JOIN "ASSESSMENT_ORIGIN" AS o ON o."ANALYSIS_ID" = a."ID"
                 ORDER BY a."ID"
                 FOR UPDATE OF a
                """)
                .bind(
                        "components",
                        entries.stream()
                                .mapToLong(e -> e.finding().componentId())
                                .toArray())
                .bind(
                        "vulnerabilities",
                        entries.stream()
                                .mapToLong(e -> e.finding().vulnerabilityId())
                                .toArray())
                .map((rs, ctx) -> readAnalysis(rs))
                .list();
        final var result = new HashMap<Key, StoredAnalysis>();
        rows.forEach(row -> result.put(row.key(), row));
        return result;
    }

    private static StoredAnalysis readAnalysis(final ResultSet rs) throws SQLException {
        final var values = new AnalysisValues();
        values.setAnalysisState(AnalysisState.valueOf(rs.getString("STATE")));
        values.setAnalysisJustification(enumOrNull(AnalysisJustification.class, rs.getString("JUSTIFICATION")));
        values.setAnalysisResponse(enumOrNull(AnalysisResponse.class, rs.getString("RESPONSE")));
        values.setAnalysisDetails(rs.getString("DETAILS"));
        values.setSuppressed(rs.getBoolean("SUPPRESSED"));
        values.setSeverity(enumOrNull(Severity.class, rs.getString("severity_text")));
        values.setCvssV2Vector(rs.getString("CVSSV2VECTOR"));
        values.setCvssV2Score(rs.getBigDecimal("CVSSV2SCORE"));
        values.setCvssV3Vector(rs.getString("CVSSV3VECTOR"));
        values.setCvssV3Score(rs.getBigDecimal("CVSSV3SCORE"));
        values.setCvssV4Vector(rs.getString("CVSSV4VECTOR"));
        values.setCvssV4Score(rs.getBigDecimal("CVSSV4SCORE"));
        values.setOwaspVector(rs.getString("OWASPVECTOR"));
        values.setOwaspScore(rs.getBigDecimal("OWASPSCORE"));
        values.setVulnerabilityPolicyId(rs.getObject("VULNERABILITY_POLICY_ID", Long.class));
        final String owner = rs.getString("OWNER");
        final String reason = rs.getString("LAST_REASON");
        final var origin = owner == null
                ? null
                : new AssessmentOriginDao.Origin(
                        AssessmentOwnership.valueOf(owner),
                        rs.getLong("DECISION_VERSION"),
                        reason == null ? null : AssessmentReason.valueOf(reason));
        return new StoredAnalysis(
                rs.getLong("ID"), new Key(rs.getLong("COMPONENT_ID"), rs.getLong("VULNERABILITY_ID")), values, origin);
    }

    private static <E extends Enum<E>> @Nullable E enumOrNull(final Class<E> type, final @Nullable String value) {
        return value == null ? null : Enum.valueOf(type, value);
    }

    private static @Nullable String nameOrNull(final @Nullable Enum<?> value) {
        return value == null ? null : value.name();
    }

    private static @Nullable String decimal(final @Nullable BigDecimal value) {
        return value == null ? null : value.toPlainString();
    }

    private static Map<Key, Long> upsertAnalyses(final Handle handle, final List<Planned> plans) {
        return handle.createQuery("""
                INSERT INTO "ANALYSIS" ("PROJECT_ID"
                    , "COMPONENT_ID"
                    , "VULNERABILITY_ID"
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
                    , "VULNERABILITY_POLICY_ID")
                SELECT t.project_ids
                    , t.component_ids
                    , t.vuln_ids
                    , t.states
                    , t.justifications
                    , t.responses
                    , t.details
                    , t.suppressed
                    , CAST(t.severities AS severity)
                    , t.cvssv2vector
                    , CAST(t.cvssv2score AS numeric)
                    , t.cvssv3vector
                    , CAST(t.cvssv3score AS numeric)
                    , t.cvssv4vector
                    , CAST(t.cvssv4score AS numeric)
                    , t.owaspvector
                    , CAST(t.owaspscore AS numeric)
                    , t.policy_ids
                  FROM UNNEST(:project_ids
                    , :component_ids
                    , :vuln_ids
                    , :states
                    , :justifications
                    , :responses
                    , :details
                    , :suppressed
                    , :severities
                    , :cvssv2vector
                    , :cvssv2score
                    , :cvssv3vector
                    , :cvssv3score
                    , :cvssv4vector
                    , :cvssv4score
                    , :owaspvector
                    , :owaspscore
                    , :policy_ids)
                       AS t(project_ids
                    , component_ids
                    , vuln_ids
                    , states
                    , justifications
                    , responses
                    , details
                    , suppressed
                    , severities
                    , cvssv2vector
                    , cvssv2score
                    , cvssv3vector
                    , cvssv3score
                    , cvssv4vector
                    , cvssv4score
                    , owaspvector
                    , owaspscore
                    , policy_ids)
                ON CONFLICT ("PROJECT_ID", "COMPONENT_ID", "VULNERABILITY_ID") DO UPDATE SET
                  "STATE" = EXCLUDED."STATE",
                  "JUSTIFICATION" = EXCLUDED."JUSTIFICATION",
                  "RESPONSE" = EXCLUDED."RESPONSE",
                  "DETAILS" = EXCLUDED."DETAILS",
                  "SUPPRESSED" = EXCLUDED."SUPPRESSED",
                  "SEVERITY" = EXCLUDED."SEVERITY",
                  "CVSSV2VECTOR" = EXCLUDED."CVSSV2VECTOR",
                  "CVSSV2SCORE" = EXCLUDED."CVSSV2SCORE",
                  "CVSSV3VECTOR" = EXCLUDED."CVSSV3VECTOR",
                  "CVSSV3SCORE" = EXCLUDED."CVSSV3SCORE",
                  "CVSSV4VECTOR" = EXCLUDED."CVSSV4VECTOR",
                  "CVSSV4SCORE" = EXCLUDED."CVSSV4SCORE",
                  "OWASPVECTOR" = EXCLUDED."OWASPVECTOR",
                  "OWASPSCORE" = EXCLUDED."OWASPSCORE",
                  "VULNERABILITY_POLICY_ID" = EXCLUDED."VULNERABILITY_POLICY_ID"
                RETURNING "ID", "COMPONENT_ID", "VULNERABILITY_ID"
                """)
                .bind(
                        "project_ids",
                        plans.stream()
                                .mapToLong(p -> p.entry().finding().projectId())
                                .toArray())
                .bind(
                        "component_ids",
                        plans.stream()
                                .mapToLong(p -> p.entry().finding().componentId())
                                .toArray())
                .bind(
                        "vuln_ids",
                        plans.stream()
                                .mapToLong(p -> p.entry().finding().vulnerabilityId())
                                .toArray())
                .bind(
                        "states",
                        plans.stream()
                                .map(p -> p.plan().values().getAnalysisState().name())
                                .toArray(String[]::new))
                .bind(
                        "justifications",
                        plans.stream()
                                .map(p -> nameOrNull(p.plan().values().getAnalysisJustification()))
                                .toArray(String[]::new))
                .bind(
                        "responses",
                        plans.stream()
                                .map(p -> nameOrNull(p.plan().values().getAnalysisResponse()))
                                .toArray(String[]::new))
                .bind(
                        "details",
                        plans.stream()
                                .map(p -> p.plan().values().getAnalysisDetails())
                                .toArray(String[]::new))
                .bind(
                        "suppressed",
                        plans.stream()
                                .map(p -> p.plan().values().isSuppressed())
                                .toArray(Boolean[]::new))
                .bind(
                        "severities",
                        plans.stream()
                                .map(p -> nameOrNull(p.plan().values().getSeverity()))
                                .toArray(String[]::new))
                .bind(
                        "cvssv2vector",
                        plans.stream()
                                .map(p -> p.plan().values().getCvssV2Vector())
                                .toArray(String[]::new))
                .bind(
                        "cvssv2score",
                        plans.stream()
                                .map(p -> decimal(p.plan().values().getCvssV2Score()))
                                .toArray(String[]::new))
                .bind(
                        "cvssv3vector",
                        plans.stream()
                                .map(p -> p.plan().values().getCvssV3Vector())
                                .toArray(String[]::new))
                .bind(
                        "cvssv3score",
                        plans.stream()
                                .map(p -> decimal(p.plan().values().getCvssV3Score()))
                                .toArray(String[]::new))
                .bind(
                        "cvssv4vector",
                        plans.stream()
                                .map(p -> p.plan().values().getCvssV4Vector())
                                .toArray(String[]::new))
                .bind(
                        "cvssv4score",
                        plans.stream()
                                .map(p -> decimal(p.plan().values().getCvssV4Score()))
                                .toArray(String[]::new))
                .bind(
                        "owaspvector",
                        plans.stream()
                                .map(p -> p.plan().values().getOwaspVector())
                                .toArray(String[]::new))
                .bind(
                        "owaspscore",
                        plans.stream()
                                .map(p -> decimal(p.plan().values().getOwaspScore()))
                                .toArray(String[]::new))
                .bind(
                        "policy_ids",
                        plans.stream()
                                .map(p -> p.plan().values().getVulnerabilityPolicyId())
                                .toArray(Long[]::new))
                .map((rs, ctx) -> Map.entry(
                        new Key(rs.getLong("COMPONENT_ID"), rs.getLong("VULNERABILITY_ID")), rs.getLong("ID")))
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private static void insertComments(final Handle handle, final List<Planned> plans, final Map<Key, Long> ids) {
        final var analysisIds = new ArrayList<Long>();
        final var comments = new ArrayList<String>();
        final var commenters = new ArrayList<@Nullable String>();
        for (final var planned : plans) {
            for (final String comment : planned.plan().comments()) {
                analysisIds.add(requireNonNull(ids.get(planned.key())));
                comments.add(comment);
                commenters.add(planned.entry().commenter());
            }
        }
        if (comments.isEmpty()) {
            return;
        }
        handle.createUpdate("""
                INSERT INTO "ANALYSISCOMMENT" ("ANALYSIS_ID", "COMMENTER", "COMMENT", "TIMESTAMP")
                SELECT t.analysis_id, t.commenter, t.comment, :timestamp
                  FROM UNNEST(:analysisIds, :commenters, :comments) WITH ORDINALITY AS t(analysis_id, commenter, comment, position)
                 ORDER BY t.position
                """)
                .bind("analysisIds", analysisIds.toArray(Long[]::new))
                .bind("commenters", commenters.toArray(String[]::new))
                .bind("comments", comments.toArray(String[]::new))
                .bind("timestamp", new Date())
                .execute();
    }

    private static void emitDecisionChanges(final Handle handle, final List<Planned> plans) {
        record UuidKey(String component, String vulnerability) {}
        final var byKey = new HashMap<UuidKey, Planned>();
        final var queries = new ArrayList<GetProjectAuditChangeNotificationSubjectQuery>();
        for (final var p : plans) {
            if (!p.plan().notifyDecisionChange()) {
                continue;
            }
            final var finding = p.entry().finding();
            byKey.put(
                    new UuidKey(
                            finding.componentUuid().toString(),
                            finding.vulnerabilityUuid().toString()),
                    p);
            queries.add(new GetProjectAuditChangeNotificationSubjectQuery(
                    finding.componentId(),
                    finding.vulnerabilityId(),
                    p.plan().values().getAnalysisState(),
                    p.plan().values().isSuppressed()));
        }
        if (queries.isEmpty()) {
            return;
        }
        final var notifications =
                handle.attach(NotificationSubjectDao.class).getForProjectAuditChanges(queries).stream()
                        .map(subject -> {
                            final var p = requireNonNull(byKey.get(new UuidKey(
                                    subject.getComponent().getUuid(),
                                    subject.getVulnerability().getUuid())));
                            return createVulnerabilityAnalysisDecisionChangeNotification(
                                    subject.getProject(),
                                    subject.getComponent(),
                                    subject.getVulnerability(),
                                    subject.getAnalysis(),
                                    p.plan().stateChanged(),
                                    p.plan().suppressionChanged());
                        })
                        .toList();
        new JdbiNotificationEmitter(handle).emitAll(notifications);
    }
}
