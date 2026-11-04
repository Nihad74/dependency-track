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
package org.dependencytrack.persistence;

import alpine.model.auth.ApiKeyPrincipal;
import alpine.model.auth.UserPrincipal;
import alpine.resources.AlpineRequest;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.assessmentsync.AssessmentChange;
import org.dependencytrack.assessmentsync.AssessmentChangeRecorder;
import org.dependencytrack.assessmentsync.AssessmentMutationGuard;
import org.dependencytrack.assessmentsync.AssessmentNotReleasableException;
import org.dependencytrack.assessmentsync.AssessmentOriginDao;
import org.dependencytrack.assessmentsync.AssessmentOwnership;
import org.dependencytrack.assessmentsync.StaleAssessmentDecisionException;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.GetProjectAuditChangeNotificationSubjectQuery;
import org.dependencytrack.notification.JdbiNotificationEmitter;
import org.dependencytrack.notification.NotificationSubjectDao;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.command.MakeAnalysisCommand.DecisionAction;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.util.AnalysisCommentFormatter.AnalysisCommentField;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.SqlStatement;
import org.jspecify.annotations.Nullable;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static java.util.Objects.requireNonNullElse;
import static org.dependencytrack.notification.api.NotificationFactory.createVulnerabilityAnalysisDecisionChangeNotification;
import static org.dependencytrack.util.AnalysisCommentFormatter.formatComment;
import static org.dependencytrack.util.PersistenceUtil.assertPersistent;

public class AnalysisQueryManager extends QueryManager {

    /**
     * Constructs a new QueryManager.
     *
     * @param pm a PersistenceManager object
     */
    AnalysisQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     *
     * @param pm      a PersistenceManager object
     * @param request an AlpineRequest object
     */
    AnalysisQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a Analysis for the specified Project, Component, and Vulnerability.
     *
     * @param component     the Component
     * @param vulnerability the Vulnerability
     * @return a Analysis object, or null if not found
     */
    @Override
    public Analysis getAnalysis(Component component, Vulnerability vulnerability) {
        final Query<Analysis> query =
                pm.newQuery(Analysis.class, "component == :component && vulnerability == :vulnerability");
        query.setRange(0, 1);
        return singleResult(query.execute(component, vulnerability));
    }

    /**
     * @since 5.0.0
     */
    @Override
    public long makeAnalysis(final MakeAnalysisCommand command) {
        assertPersistent(command.component(), "component must be persistent");
        assertPersistent(command.vulnerability(), "vulnerability must be persistent");

        final long analysisId = callInTransaction(() -> {
            final Project project = command.component().getProject();
            if (project == null || project.getUuid() == null) {
                throw new IllegalStateException("component must belong to a project");
            }
            // JDO cannot load fields while the JDBI handle holds its connection, so read them first.
            final var finding = new FindingIds(
                    project.getId(),
                    project.getUuid(),
                    project.getName(),
                    project.getVersion(),
                    command.component().getId(),
                    command.component().getUuid(),
                    command.vulnerability().getId(),
                    command.vulnerability().getUuid());
            final String principalCommenter = commenter(command.commenter());
            return JdbiFactory.withJdbiHandle(this, handle -> write(handle, command, finding, principalCommenter));
        });
        // The row was written through JDBI; cached JDO copies would show the old values.
        pm.evictAll(false, Analysis.class);
        pm.evictAll(false, AnalysisComment.class);
        return analysisId;
    }

    /**
     * The JDO-loaded ids, UUIDs and names {@link #makeAnalysis} needs inside its JDBI handle.
     */
    private record FindingIds(
            long projectId,
            UUID projectUuid,
            @Nullable String projectName,
            @Nullable String projectVersion,
            long componentId,
            UUID componentUuid,
            long vulnerabilityId,
            UUID vulnerabilityUuid) {}

    private static long write(
            final Handle handle,
            final MakeAnalysisCommand command,
            final FindingIds finding,
            final @Nullable String commenter) {
        AssessmentMutationGuard.lockProject(handle, finding.projectUuid());
        final long componentId = finding.componentId();
        final long vulnerabilityId = finding.vulnerabilityId();
        final StoredAnalysis stored = lockAnalysis(handle, componentId, vulnerabilityId);
        final AssessmentOriginDao.Origin originBefore =
                stored == null ? null : new AssessmentOriginDao(handle).findOrigin(stored.id());
        final long decisionVersionBefore = originBefore == null ? 0 : originBefore.decisionVersion();

        if (command.expectedDecisionVersion() != null && decisionVersionBefore != command.expectedDecisionVersion()) {
            throw new StaleAssessmentDecisionException();
        }

        final Analysis analysis = stored == null ? newAnalysisValues() : stored.values();
        if (command.decisionAction() == DecisionAction.RELEASE_LOCAL
                && !isReleasable(stored == null ? null : analysis, originBefore)) {
            throw new AssessmentNotReleasableException();
        }

        final boolean inheritedBefore = originBefore != null && originBefore.owner() == AssessmentOwnership.INHERITED;
        final AssessmentOwnership ownerBefore = stored == null
                ? null
                : originBefore != null
                        ? originBefore.owner()
                        : AssessmentOwnership.ofUnlabeled(analysis.getVulnerabilityPolicyId() != null);
        final MakeAnalysisCommand effective = applyV1Defaults(command, inheritedBefore);

        final var auditTrailComments = new ArrayList<String>();
        final DecisionAction action = effective.decisionAction();
        final FieldUpdate update =
                switch (action) {
                    case COMMENT_ONLY -> {
                        if (effective.comment() == null || effective.comment().isBlank()) {
                            throw new IllegalArgumentException("COMMENT_ONLY requires a comment");
                        }
                        yield FieldUpdate.NONE;
                    }
                    case RELEASE_LOCAL -> releaseLocal(analysis, auditTrailComments);
                    case AUTO, TAKE_LOCAL -> applySuppliedFields(effective, analysis, auditTrailComments);
                };

        final boolean created = stored == null;
        final long id;
        if (created) {
            id = insertAnalysis(handle, finding.projectId(), componentId, vulnerabilityId, analysis);
        } else {
            id = stored.id();
            if (update.valuesChanged()) {
                updateAnalysis(handle, id, analysis);
            }
        }

        final List<String> comments = !effective.options().contains(MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL)
                ? auditTrailComments
                : new ArrayList<>();
        final boolean commentAdded = effective.comment() != null;
        if (commentAdded) {
            comments.add(effective.comment());
        }
        insertComments(handle, id, commenter, comments);

        final OriginWrite originWrite = planOriginWrite(action, update, created, commentAdded);
        final var originDao = new AssessmentOriginDao(handle);
        if (originWrite.dropTrail()) {
            originDao.deleteCopiedContributions(id);
        }
        if (originWrite.owner() != null) {
            // The DAO cannot tell that an unlabeled row changed owner, so that change also moves the version.
            final boolean versionMoves = update.valuesChanged()
                    || (originBefore == null && ownerBefore != null && originWrite.owner() != ownerBefore);
            originDao.upsertOrigin(id, originWrite.owner(), versionMoves);
        }
        if (originWrite.recordChange()) {
            new AssessmentChangeRecorder(handle)
                    .record(AssessmentChange.finding(
                            finding.projectUuid(),
                            finding.componentUuid(),
                            finding.vulnerabilityUuid(),
                            AssessmentChange.Reason.AUTHORED,
                            finding.projectName(),
                            finding.projectVersion()));
        }

        if (!effective.options().contains(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)
                && (update.stateChanged() || update.suppressionChanged())) {
            emitDecisionChange(
                    handle, componentId, vulnerabilityId, analysis, update.stateChanged(), update.suppressionChanged());
        }
        return id;
    }

    private static boolean isReleasable(final Analysis analysis, final AssessmentOriginDao.Origin origin) {
        if (analysis == null) {
            return false;
        }
        final AssessmentOwnership owner = origin != null
                ? origin.owner()
                : AssessmentOwnership.ofUnlabeled(analysis.getVulnerabilityPolicyId() != null);
        return owner == AssessmentOwnership.LOCAL;
    }

    /**
     * REST API v1 resets an omitted state, justification, or response to {@code NOT_SET}.
     * On an inherited analysis, omitted fields keep the inherited value instead (ADR 044).
     */
    private static MakeAnalysisCommand applyV1Defaults(
            final MakeAnalysisCommand command, final boolean inheritedBefore) {
        if (!command.options().contains(MakeAnalysisCommand.Option.V1_RESET_OMITTED_DECISION) || inheritedBefore) {
            return command;
        }
        return command.withState(requireNonNullElse(command.state(), AnalysisState.NOT_SET))
                .withJustification(requireNonNullElse(command.justification(), AnalysisJustification.NOT_SET))
                .withResponse(requireNonNullElse(command.response(), AnalysisResponse.NOT_SET));
    }

    /**
     * The source trail stays as provenance while a local owner keeps the inherited decision (ADR 044). Any later
     * change to the decision drops it, whichever action makes the change.
     */
    private static OriginWrite planOriginWrite(
            final DecisionAction action, final FieldUpdate update, final boolean created, final boolean commentAdded) {
        return switch (action) {
            case RELEASE_LOCAL -> OriginWrite.claim(AssessmentOwnership.NEUTRAL).droppingTrailIf(true);
            case TAKE_LOCAL -> OriginWrite.claim(AssessmentOwnership.LOCAL).droppingTrailIf(update.decisionChanged());
            case COMMENT_ONLY -> created ? OriginWrite.claim(AssessmentOwnership.NEUTRAL) : OriginWrite.COMMENT_ONLY;
            case AUTO -> {
                if (update.valuesChanged()) {
                    yield OriginWrite.claim(AssessmentOwnership.LOCAL).droppingTrailIf(update.decisionChanged());
                }
                if (created) {
                    yield OriginWrite.claim(AssessmentOwnership.NEUTRAL).recordingChangeIf(commentAdded);
                }
                yield commentAdded ? OriginWrite.COMMENT_ONLY : OriginWrite.NONE;
            }
        };
    }

    /**
     * Blank and null details are the same explanation. Clients send either for an empty field.
     */
    private static boolean sameDetails(final String left, final String right) {
        return StringUtils.isBlank(left) ? StringUtils.isBlank(right) : left.equals(right);
    }

    private static FieldUpdate applySuppliedFields(
            final MakeAnalysisCommand command, final Analysis analysis, final List<String> auditTrailComments) {
        boolean stateChanged = false;
        boolean suppressionChanged = false;
        boolean decisionChanged = false;
        boolean detailsChanged = false;

        if (command.state() != null && command.state() != analysis.getAnalysisState()) {
            auditTrailComments.add("Analysis: %s → %s".formatted(analysis.getAnalysisState(), command.state()));
            analysis.setAnalysisState(command.state());
            stateChanged = true;
            decisionChanged = true;
        }
        if (command.justification() != null && command.justification() != analysis.getAnalysisJustification()) {
            auditTrailComments.add(
                    "Justification: %s → %s".formatted(analysis.getAnalysisJustification(), command.justification()));
            analysis.setAnalysisJustification(command.justification());
            decisionChanged = true;
        }
        if (command.response() != null && command.response() != analysis.getAnalysisResponse()) {
            auditTrailComments.add(
                    "Vendor Response: %s → %s".formatted(analysis.getAnalysisResponse(), command.response()));
            analysis.setAnalysisResponse(command.response());
            decisionChanged = true;
        }
        if (command.details() != null && !sameDetails(command.details(), analysis.getAnalysisDetails())) {
            auditTrailComments.add("Details: %s".formatted(command.details()));
            analysis.setAnalysisDetails(command.details());
            detailsChanged = true;
        }
        if (command.suppress() != null && command.suppress() != analysis.isSuppressed()) {
            auditTrailComments.add(command.suppress() ? "Suppressed" : "Unsuppressed");
            analysis.setSuppressed(command.suppress());
            suppressionChanged = true;
            decisionChanged = true;
        }
        if (command.owaspVector() != null && !command.owaspVector().equals(analysis.getOwaspVector())) {
            auditTrailComments.add(
                    formatComment(AnalysisCommentField.OWASP_VECTOR, analysis.getOwaspVector(), command.owaspVector()));
            analysis.setOwaspVector(command.owaspVector());
            decisionChanged = true;
        }
        if (command.owaspScore() != null
                && (analysis.getOwaspScore() == null
                        || command.owaspScore().compareTo(analysis.getOwaspScore()) != 0)) {
            auditTrailComments.add(
                    formatComment(AnalysisCommentField.OWASP_SCORE, analysis.getOwaspScore(), command.owaspScore()));
            analysis.setOwaspScore(command.owaspScore());
            decisionChanged = true;
        }
        return new FieldUpdate(stateChanged, suppressionChanged, decisionChanged, detailsChanged);
    }

    private static FieldUpdate releaseLocal(final Analysis analysis, final List<String> auditTrailComments) {
        boolean stateChanged = false;
        boolean suppressionChanged = false;
        boolean decisionChanged = false;

        if (analysis.getAnalysisState() != AnalysisState.NOT_SET) {
            auditTrailComments.add("Analysis: %s → %s".formatted(analysis.getAnalysisState(), AnalysisState.NOT_SET));
            analysis.setAnalysisState(AnalysisState.NOT_SET);
            stateChanged = true;
            decisionChanged = true;
        }
        if (analysis.getAnalysisJustification() != AnalysisJustification.NOT_SET) {
            auditTrailComments.add("Justification: %s → %s"
                    .formatted(analysis.getAnalysisJustification(), AnalysisJustification.NOT_SET));
            analysis.setAnalysisJustification(AnalysisJustification.NOT_SET);
            decisionChanged = true;
        }
        if (analysis.getAnalysisResponse() != AnalysisResponse.NOT_SET) {
            auditTrailComments.add(
                    "Vendor Response: %s → %s".formatted(analysis.getAnalysisResponse(), AnalysisResponse.NOT_SET));
            analysis.setAnalysisResponse(AnalysisResponse.NOT_SET);
            decisionChanged = true;
        }
        final boolean detailsChanged = clearField(
                auditTrailComments,
                AnalysisCommentField.DETAILS,
                analysis.getAnalysisDetails(),
                () -> analysis.setAnalysisDetails(null));
        if (analysis.isSuppressed()) {
            auditTrailComments.add("Unsuppressed");
            analysis.setSuppressed(false);
            suppressionChanged = true;
            decisionChanged = true;
        }
        decisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.SEVERITY,
                analysis.getSeverity(),
                () -> analysis.setSeverity(null));
        decisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.CVSSV2_VECTOR,
                analysis.getCvssV2Vector(),
                () -> analysis.setCvssV2Vector(null));
        decisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.CVSSV2_SCORE,
                analysis.getCvssV2Score(),
                () -> analysis.setCvssV2Score(null));
        decisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.CVSSV3_VECTOR,
                analysis.getCvssV3Vector(),
                () -> analysis.setCvssV3Vector(null));
        decisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.CVSSV3_SCORE,
                analysis.getCvssV3Score(),
                () -> analysis.setCvssV3Score(null));
        decisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.CVSSV4_VECTOR,
                analysis.getCvssV4Vector(),
                () -> analysis.setCvssV4Vector(null));
        decisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.CVSSV4_SCORE,
                analysis.getCvssV4Score(),
                () -> analysis.setCvssV4Score(null));
        decisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.OWASP_VECTOR,
                analysis.getOwaspVector(),
                () -> analysis.setOwaspVector(null));
        decisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.OWASP_SCORE,
                analysis.getOwaspScore(),
                () -> analysis.setOwaspScore(null));
        if (analysis.getVulnerabilityPolicyId() != null) {
            analysis.setVulnerabilityPolicyId(null);
            decisionChanged = true;
        }
        return new FieldUpdate(stateChanged, suppressionChanged, decisionChanged, detailsChanged);
    }

    private static boolean clearField(
            final List<String> auditTrailComments,
            final AnalysisCommentField field,
            final Object currentValue,
            final Runnable clear) {
        if (currentValue == null) {
            return false;
        }
        auditTrailComments.add(formatComment(field, currentValue, null));
        clear.run();
        return true;
    }

    private record FieldUpdate(
            boolean stateChanged, boolean suppressionChanged, boolean decisionChanged, boolean detailsChanged) {

        private static final FieldUpdate NONE = new FieldUpdate(false, false, false, false);

        /**
         * The structured decision or the free-text details changed.
         */
        private boolean valuesChanged() {
            return decisionChanged || detailsChanged;
        }
    }

    /**
     * What an authored write does to the origin. {@code owner} is null when ownership stays as it is.
     */
    private record OriginWrite(@Nullable AssessmentOwnership owner, boolean dropTrail, boolean recordChange) {

        private static final OriginWrite COMMENT_ONLY = new OriginWrite(null, false, true);
        private static final OriginWrite NONE = new OriginWrite(null, false, false);

        /**
         * Sets the owner and records an assessment change.
         */
        private static OriginWrite claim(final AssessmentOwnership owner) {
            return new OriginWrite(owner, false, true);
        }

        private OriginWrite droppingTrailIf(final boolean drop) {
            return new OriginWrite(owner, drop, recordChange);
        }

        private OriginWrite recordingChangeIf(final boolean record) {
            return new OriginWrite(owner, dropTrail, record);
        }
    }

    /**
     * Decision fields of the stored analysis of one finding, locked for this transaction.
     */
    private record StoredAnalysis(long id, Analysis values) {}

    private static @Nullable StoredAnalysis lockAnalysis(
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
                    final var values = new Analysis();
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

    /**
     * Values of a new analysis before the command is applied. Not persisted.
     */
    private static Analysis newAnalysisValues() {
        final var values = new Analysis();
        values.setAnalysisState(AnalysisState.NOT_SET);
        values.setAnalysisJustification(AnalysisJustification.NOT_SET);
        values.setAnalysisResponse(AnalysisResponse.NOT_SET);
        values.setSuppressed(false);
        return values;
    }

    private static long insertAnalysis(
            final Handle handle,
            final long projectId,
            final long componentId,
            final long vulnerabilityId,
            final Analysis values) {
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

    private static void updateAnalysis(final Handle handle, final long analysisId, final Analysis values) {
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

    private static <S extends SqlStatement<S>> S bindValues(final S statement, final Analysis values) {
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
            final Analysis values,
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

    /**
     * The commenter the command names, else the calling principal.
     */
    private @Nullable String commenter(final @Nullable String commenter) {
        final String commenterToUse;
        if (commenter == null) {
            commenterToUse = switch (principal) {
                case UserPrincipal user -> user.username();
                case ApiKeyPrincipal apiKey ->
                    apiKey.teams().isEmpty()
                            ? apiKey.maskedKey()
                            : apiKey.teams().getFirst().name();
                case null -> null;
            };
        } else {
            commenterToUse = commenter;
        }

        return commenterToUse;
    }
}
