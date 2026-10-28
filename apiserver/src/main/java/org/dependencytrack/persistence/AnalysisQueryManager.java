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
import org.dependencytrack.assessmentsync.AssessmentChange;
import org.dependencytrack.assessmentsync.AssessmentChangeRecorder;
import org.dependencytrack.assessmentsync.AssessmentMutationGuard;
import org.dependencytrack.assessmentsync.AssessmentNotReleasableException;
import org.dependencytrack.assessmentsync.AssessmentOwnership;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao;
import org.dependencytrack.assessmentsync.StaleAssessmentDecisionException;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.VulnerabilityKey;
import org.dependencytrack.notification.JdoNotificationEmitter;
import org.dependencytrack.notification.NotificationModelConverter;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.command.MakeAnalysisCommand.DecisionAction;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.util.AnalysisCommentFormatter.AnalysisCommentField;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import static org.dependencytrack.assessmentsync.AssessmentChange.Scope.FINDING;
import static org.dependencytrack.assessmentsync.AssessmentChangeRecorder.AUTHORED;
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

        return callInTransaction(() -> {
            final Project project = command.component().getProject();
            if (project == null || project.getUuid() == null) {
                throw new IllegalStateException("component must belong to a project");
            }
            JdbiFactory.useJdbiHandle(this, handle -> AssessmentMutationGuard.lockProject(handle, project.getUuid()));

            Analysis analysis = getAnalysis(command.component(), command.vulnerability());
            final AssessmentProjectionDao.Origin originBefore =
                    analysis == null ? null : currentOrigin(analysis.getId());
            if (command.expectedDecisionVersion() != null
                    && (originBefore == null || originBefore.decisionVersion() != command.expectedDecisionVersion())) {
                throw new StaleAssessmentDecisionException();
            }
            if (command.decisionAction() == DecisionAction.RELEASE_LOCAL
                    && (analysis == null
                            || (originBefore != null && originBefore.owner() != AssessmentOwnership.LOCAL))) {
                throw new AssessmentNotReleasableException();
            }

            final boolean created = analysis == null;
            if (created) {
                analysis = new Analysis();
                analysis.setComponent(command.component());
                analysis.setVulnerability(command.vulnerability());
                analysis.setAnalysisState(AnalysisState.NOT_SET);
                analysis.setAnalysisJustification(AnalysisJustification.NOT_SET);
                analysis.setAnalysisResponse(AnalysisResponse.NOT_SET);
                analysis.setSuppressed(false);
                persist(analysis);
            }

            final var auditTrailComments = new ArrayList<String>();
            final DecisionAction action = command.decisionAction();
            final FieldUpdate update =
                    switch (action) {
                        case COMMENT_ONLY -> {
                            if (command.comment() == null || command.comment().isBlank()) {
                                throw new IllegalArgumentException("COMMENT_ONLY requires a comment");
                            }
                            yield FieldUpdate.none();
                        }
                        case RELEASE_LOCAL -> releaseLocal(analysis, auditTrailComments);
                        case AUTO, TAKE_LOCAL, VEX -> applySuppliedFields(command, analysis, auditTrailComments);
                    };

            final List<String> comments = !command.options().contains(MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL)
                    ? auditTrailComments
                    : new ArrayList<>();
            if (command.comment() != null) {
                comments.add(command.comment());
            }
            final boolean commentAdded = command.comment() != null;
            createAnalysisComments(analysis, command.commenter(), comments);

            final boolean machineChanged = update.decisionChanged() || update.detailsChanged();
            final OriginWrite originWrite =
                    switch (action) {
                        case RELEASE_LOCAL -> new OriginWrite(AssessmentOwnership.NEUTRAL, true, true);
                        case TAKE_LOCAL -> new OriginWrite(AssessmentOwnership.LOCAL, true, true);
                        case VEX -> new OriginWrite(AssessmentOwnership.LOCAL, true, true);
                        case COMMENT_ONLY ->
                            created
                                    ? new OriginWrite(AssessmentOwnership.NEUTRAL, false, true)
                                    : OriginWrite.commentOnly();
                        case AUTO -> {
                            if (machineChanged) {
                                final boolean clearCopied =
                                        originBefore != null && originBefore.owner() == AssessmentOwnership.INHERITED;
                                yield new OriginWrite(AssessmentOwnership.LOCAL, clearCopied, true);
                            }
                            if (created) {
                                yield new OriginWrite(AssessmentOwnership.NEUTRAL, false, commentAdded);
                            }
                            yield commentAdded ? OriginWrite.commentOnly() : OriginWrite.none();
                        }
                    };

            if (originWrite.writeOrigin() || originWrite.clearContributions() || originWrite.record()) {
                pm.flush();
                final long analysisId = analysis.getId();
                final AssessmentChange change = new AssessmentChange(
                        FINDING,
                        project.getUuid(),
                        command.component().getUuid(),
                        command.vulnerability().getUuid(),
                        AUTHORED,
                        AssessmentChangeRecorder.lookupKeys(project.getName(), project.getVersion()));
                JdbiFactory.useJdbiHandle(this, handle -> {
                    final var dao = new AssessmentProjectionDao(handle);
                    if (originWrite.clearContributions()) {
                        dao.deleteCopiedContributions(analysisId);
                    }
                    if (originWrite.writeOrigin()) {
                        final boolean ownerChanged =
                                originBefore == null || originBefore.owner() != originWrite.owner();
                        dao.upsertOrigin(analysisId, originWrite.owner(), null);
                        if (machineChanged && !ownerChanged) {
                            dao.bumpDecisionVersion(analysisId);
                        }
                    }
                    if (originWrite.record()) {
                        new AssessmentChangeRecorder(handle).record(change);
                    }
                });
            }

            if (!command.options().contains(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)
                    && (update.stateChanged() || update.suppressionChanged())) {
                // NB: KEV is a transient field and must be computed ad-hoc.
                final boolean isKev = !super.getKev(List.of(VulnerabilityKey.of(analysis.getVulnerability())))
                        .isEmpty();
                analysis.getVulnerability().setKev(isKev);

                new JdoNotificationEmitter(this)
                        .emit(createVulnerabilityAnalysisDecisionChangeNotification(
                                NotificationModelConverter.convert(analysis.getProject()),
                                NotificationModelConverter.convert(analysis.getComponent()),
                                NotificationModelConverter.convert(analysis.getVulnerability()),
                                NotificationModelConverter.convert(analysis),
                                update.stateChanged(),
                                update.suppressionChanged()));
            }

            return analysis.getId();
        });
    }

    private AssessmentProjectionDao.Origin currentOrigin(final long analysisId) {
        return JdbiFactory.withJdbiHandle(this, handle -> new AssessmentProjectionDao(handle).findOrigin(analysisId));
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
        if (command.details() != null && !command.details().equals(analysis.getAnalysisDetails())) {
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
        boolean detailsChanged = false;

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
        if (analysis.getAnalysisDetails() != null) {
            auditTrailComments.add(formatComment(AnalysisCommentField.DETAILS, analysis.getAnalysisDetails(), null));
            analysis.setAnalysisDetails(null);
            detailsChanged = true;
        }
        if (analysis.isSuppressed()) {
            auditTrailComments.add("Unsuppressed");
            analysis.setSuppressed(false);
            suppressionChanged = true;
            decisionChanged = true;
        }
        if (analysis.getSeverity() != null) {
            auditTrailComments.add(formatComment(AnalysisCommentField.SEVERITY, analysis.getSeverity(), null));
            analysis.setSeverity(null);
            decisionChanged = true;
        }
        if (analysis.getCvssV2Vector() != null) {
            auditTrailComments.add(formatComment(AnalysisCommentField.CVSSV2_VECTOR, analysis.getCvssV2Vector(), null));
            analysis.setCvssV2Vector(null);
            decisionChanged = true;
        }
        if (analysis.getCvssV2Score() != null) {
            auditTrailComments.add(formatComment(AnalysisCommentField.CVSSV2_SCORE, analysis.getCvssV2Score(), null));
            analysis.setCvssV2Score(null);
            decisionChanged = true;
        }
        if (analysis.getCvssV3Vector() != null) {
            auditTrailComments.add(formatComment(AnalysisCommentField.CVSSV3_VECTOR, analysis.getCvssV3Vector(), null));
            analysis.setCvssV3Vector(null);
            decisionChanged = true;
        }
        if (analysis.getCvssV3Score() != null) {
            auditTrailComments.add(formatComment(AnalysisCommentField.CVSSV3_SCORE, analysis.getCvssV3Score(), null));
            analysis.setCvssV3Score(null);
            decisionChanged = true;
        }
        if (analysis.getCvssV4Vector() != null) {
            auditTrailComments.add(formatComment(AnalysisCommentField.CVSSV4_VECTOR, analysis.getCvssV4Vector(), null));
            analysis.setCvssV4Vector(null);
            decisionChanged = true;
        }
        if (analysis.getCvssV4Score() != null) {
            auditTrailComments.add(formatComment(AnalysisCommentField.CVSSV4_SCORE, analysis.getCvssV4Score(), null));
            analysis.setCvssV4Score(null);
            decisionChanged = true;
        }
        if (analysis.getOwaspVector() != null) {
            auditTrailComments.add(formatComment(AnalysisCommentField.OWASP_VECTOR, analysis.getOwaspVector(), null));
            analysis.setOwaspVector(null);
            decisionChanged = true;
        }
        if (analysis.getOwaspScore() != null) {
            auditTrailComments.add(formatComment(AnalysisCommentField.OWASP_SCORE, analysis.getOwaspScore(), null));
            analysis.setOwaspScore(null);
            decisionChanged = true;
        }
        if (analysis.getVulnerabilityPolicyId() != null) {
            analysis.setVulnerabilityPolicyId(null);
            decisionChanged = true;
        }
        return new FieldUpdate(stateChanged, suppressionChanged, decisionChanged, detailsChanged);
    }

    private record FieldUpdate(
            boolean stateChanged, boolean suppressionChanged, boolean decisionChanged, boolean detailsChanged) {

        private static FieldUpdate none() {
            return new FieldUpdate(false, false, false, false);
        }
    }

    private record OriginWrite(
            AssessmentOwnership owner, boolean clearContributions, boolean writeOrigin, boolean record) {

        private OriginWrite(final AssessmentOwnership owner, final boolean clearContributions, final boolean record) {
            this(owner, clearContributions, true, record);
        }

        private static OriginWrite commentOnly() {
            return new OriginWrite(null, false, false, true);
        }

        private static OriginWrite none() {
            return new OriginWrite(null, false, false, false);
        }
    }

    private void createAnalysisComments(final Analysis analysis, final String commenter, final List<String> comments) {
        assertPersistent(analysis, "analysis must be persistent");

        if (comments == null || comments.isEmpty()) {
            return;
        }

        final var now = new Date();

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

        runInTransaction(() -> {
            final var analysisComments = new ArrayList<AnalysisComment>(comments.size());

            for (final String comment : comments) {
                final var analysisComment = new AnalysisComment();
                analysisComment.setAnalysis(analysis);
                analysisComment.setCommenter(commenterToUse);
                analysisComment.setComment(comment);
                analysisComment.setTimestamp(now);
                analysisComments.add(analysisComment);
            }

            persist(analysisComments);

            if (analysis.getAnalysisComments() != null) {
                analysis.getAnalysisComments().addAll(analysisComments);
            } else {
                analysis.setAnalysisComments(analysisComments);
            }
        });
    }
}
