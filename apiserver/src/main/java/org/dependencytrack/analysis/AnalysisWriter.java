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
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Severity;
import org.dependencytrack.notification.GetProjectAuditChangeNotificationSubjectQuery;
import org.dependencytrack.notification.JdbiNotificationEmitter;
import org.dependencytrack.notification.NotificationSubjectDao;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.SqlStatement;
import org.jspecify.annotations.Nullable;

import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.dependencytrack.notification.api.NotificationFactory.createVulnerabilityAnalysisDecisionChangeNotification;

/** Executes an authored analysis plan using only the caller's transaction and scalar finding identity. */
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

    public static long write(
            final Handle handle,
            final AnalysisMutationPlanner.Request command,
            final Finding finding,
            final @Nullable String commenter) {
        AssessmentMutationGuard.lockProject(handle, finding.projectUuid());
        final StoredAnalysis stored = loadAndLockAnalysis(handle, finding.componentId(), finding.vulnerabilityId());
        final var originDao = new AssessmentOriginDao(handle);
        final var origin = stored == null ? null : originDao.findOrigin(stored.id());
        final var plan = AnalysisMutationPlanner.plan(command, stored == null ? null : stored.values(), origin);
        final long id;
        if (stored == null) {
            id = insertAnalysis(
                    handle, finding.projectId(), finding.componentId(), finding.vulnerabilityId(), plan.values());
        } else {
            id = stored.id();
            if (plan.valuesChanged()) {
                updateAnalysis(handle, id, plan.values());
            }
        }
        insertComments(handle, id, commenter, plan.comments());
        if (plan.dropCopiedTrail()) {
            originDao.deleteCopiedContributions(id);
        }
        if (plan.owner() != null) {
            originDao.upsertOrigin(id, plan.owner(), plan.advanceDecisionVersion());
        }
        if (plan.recordChange()) {
            new AssessmentChangeRecorder(handle)
                    .record(AssessmentChange.finding(
                            finding.projectUuid(),
                            finding.componentUuid(),
                            finding.vulnerabilityUuid(),
                            AssessmentChange.Reason.AUTHORED,
                            finding.projectName(),
                            finding.projectVersion()));
        }
        if (plan.notifyDecisionChange()) {
            emitDecisionChange(
                    handle,
                    finding.componentId(),
                    finding.vulnerabilityId(),
                    plan.values(),
                    plan.stateChanged(),
                    plan.suppressionChanged());
        }
        return id;
    }

    /**
     * Decision fields of the stored analysis of one finding, locked for this transaction.
     */
    private record StoredAnalysis(long id, AnalysisValues values) {}

    private static @Nullable StoredAnalysis loadAndLockAnalysis(
            final Handle handle, final long componentId, final long vulnerabilityId) {
        return handle.createQuery(/* language=SQL */ """
                        SELECT "ID"
                             , "STATE"
                             , "JUSTIFICATION"
                             , "RESPONSE"
                             , "DETAILS"
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
                             , "VULNERABILITY_POLICY_ID"
                          FROM "ANALYSIS"
                         WHERE "COMPONENT_ID" = :componentId
                           AND "VULNERABILITY_ID" = :vulnerabilityId
                           FOR UPDATE
                        """)
                .bind("componentId", componentId)
                .bind("vulnerabilityId", vulnerabilityId)
                .map((rs, ctx) -> {
                    final var values = new AnalysisValues();
                    values.setAnalysisState(AnalysisState.valueOf(rs.getString("STATE")));
                    values.setAnalysisJustification(
                            enumOrNull(AnalysisJustification.class, rs.getString("JUSTIFICATION")));
                    values.setAnalysisResponse(enumOrNull(AnalysisResponse.class, rs.getString("RESPONSE")));
                    values.setAnalysisDetails(rs.getString("DETAILS"));
                    values.setSuppressed(rs.getBoolean("SUPPRESSED"));
                    values.setSeverity(enumOrNull(Severity.class, rs.getString("SEVERITY")));
                    values.setCvssV2Vector(rs.getString("CVSSV2VECTOR"));
                    values.setCvssV2Score(rs.getBigDecimal("CVSSV2SCORE"));
                    values.setCvssV3Vector(rs.getString("CVSSV3VECTOR"));
                    values.setCvssV3Score(rs.getBigDecimal("CVSSV3SCORE"));
                    values.setCvssV4Vector(rs.getString("CVSSV4VECTOR"));
                    values.setCvssV4Score(rs.getBigDecimal("CVSSV4SCORE"));
                    values.setOwaspVector(rs.getString("OWASPVECTOR"));
                    values.setOwaspScore(rs.getBigDecimal("OWASPSCORE"));
                    values.setVulnerabilityPolicyId(rs.getObject("VULNERABILITY_POLICY_ID", Long.class));
                    return new StoredAnalysis(rs.getLong("ID"), values);
                })
                .findOne()
                .orElse(null);
    }

    private static <E extends Enum<E>> @Nullable E enumOrNull(final Class<E> type, final @Nullable String name) {
        return name == null ? null : Enum.valueOf(type, name);
    }

    private static long insertAnalysis(
            final Handle handle,
            final long projectId,
            final long componentId,
            final long vulnerabilityId,
            final AnalysisValues values) {
        return bindValues(handle.createQuery(/* language=SQL */ """
                                INSERT INTO "ANALYSIS" (
                                  "PROJECT_ID"
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
                                , "VULNERABILITY_POLICY_ID"
                                )
                                VALUES (
                                  :projectId
                                , :componentId
                                , :vulnerabilityId
                                , :state
                                , :justification
                                , :response
                                , :details
                                , :suppressed
                                , CAST(:severity AS severity)
                                , :cvssV2Vector
                                , :cvssV2Score
                                , :cvssV3Vector
                                , :cvssV3Score
                                , :cvssV4Vector
                                , :cvssV4Score
                                , :owaspVector
                                , :owaspScore
                                , :policyId
                                )
                                RETURNING "ID"
                                """), values)
                .bind("projectId", projectId)
                .bind("componentId", componentId)
                .bind("vulnerabilityId", vulnerabilityId)
                .mapTo(long.class)
                .one();
    }

    private static void updateAnalysis(final Handle handle, final long analysisId, final AnalysisValues values) {
        bindValues(handle.createUpdate(/* language=SQL */ """
                                UPDATE "ANALYSIS"
                                   SET "STATE" = :state
                                     , "JUSTIFICATION" = :justification
                                     , "RESPONSE" = :response
                                     , "DETAILS" = :details
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
                                     , "VULNERABILITY_POLICY_ID" = :policyId
                                 WHERE "ID" = :analysisId
                                """), values)
                .bind("analysisId", analysisId)
                .execute();
    }

    private static <S extends SqlStatement<S>> S bindValues(final S statement, final AnalysisValues values) {
        return statement
                .bind("state", values.getAnalysisState().name())
                .bind("justification", nameOrNull(values.getAnalysisJustification()))
                .bind("response", nameOrNull(values.getAnalysisResponse()))
                .bind("details", values.getAnalysisDetails())
                .bind("suppressed", values.isSuppressed())
                .bind("severity", nameOrNull(values.getSeverity()))
                .bind("cvssV2Vector", values.getCvssV2Vector())
                .bind("cvssV2Score", values.getCvssV2Score())
                .bind("cvssV3Vector", values.getCvssV3Vector())
                .bind("cvssV3Score", values.getCvssV3Score())
                .bind("cvssV4Vector", values.getCvssV4Vector())
                .bind("cvssV4Score", values.getCvssV4Score())
                .bind("owaspVector", values.getOwaspVector())
                .bind("owaspScore", values.getOwaspScore())
                .bind("policyId", values.getVulnerabilityPolicyId());
    }

    private static @Nullable String nameOrNull(final @Nullable Enum<?> value) {
        return value == null ? null : value.name();
    }

    /**
     * Inserts the comments in order, so their ids follow the audit trail order.
     */
    private static void insertComments(
            final Handle handle, final long analysisId, final @Nullable String commenter, final List<String> comments) {
        if (comments.isEmpty()) {
            return;
        }
        handle.createUpdate(/* language=SQL */ """
                        INSERT INTO "ANALYSISCOMMENT" ("ANALYSIS_ID", "COMMENTER", "COMMENT", "TIMESTAMP")
                        SELECT :analysisId
                             , :commenter
                             , t.comment
                             , :timestamp
                          FROM UNNEST(:comments) WITH ORDINALITY AS t(comment, position)
                         ORDER BY t.position
                        """)
                .bind("analysisId", analysisId)
                .bind("commenter", commenter)
                .bind("comments", comments.toArray(String[]::new))
                .bind("timestamp", new Date())
                .execute();
    }

    private static void emitDecisionChange(
            final Handle handle,
            final long componentId,
            final long vulnerabilityId,
            final AnalysisValues values,
            final boolean stateChanged,
            final boolean suppressionChanged) {
        final var subjects = handle.attach(NotificationSubjectDao.class)
                .getForProjectAuditChanges(List.of(new GetProjectAuditChangeNotificationSubjectQuery(
                        componentId, vulnerabilityId, values.getAnalysisState(), values.isSuppressed())));
        if (subjects.isEmpty()) {
            return;
        }
        final var subject = subjects.getFirst();
        new JdbiNotificationEmitter(handle)
                .emit(createVulnerabilityAnalysisDecisionChangeNotification(
                        subject.getProject(),
                        subject.getComponent(),
                        subject.getVulnerability(),
                        subject.getAnalysis(),
                        stateChanged,
                        suppressionChanged));
    }
}
