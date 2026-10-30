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

import static java.util.Objects.requireNonNullElse;
import static org.dependencytrack.assessmentsync.AssessmentChange.Scope.FINDING;
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
            final AssessmentOriginDao.Origin originBefore = analysis == null ? null : currentOrigin(analysis.getId());
            final long decisionVersionBefore = originBefore == null ? 0 : originBefore.decisionVersion();
            if (command.expectedDecisionVersion() != null
                    && decisionVersionBefore != command.expectedDecisionVersion()) {
                throw new StaleAssessmentDecisionException();
            }
            if (command.decisionAction() == DecisionAction.RELEASE_LOCAL && !isReleasable(analysis, originBefore)) {
                throw new AssessmentNotReleasableException();
            }
            final boolean inheritedBefore =
                    originBefore != null && originBefore.owner() == AssessmentOwnership.INHERITED;
            final MakeAnalysisCommand effective = applyV1Defaults(command, inheritedBefore);

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
            final DecisionAction action = effective.decisionAction();
            final FieldUpdate update =
                    switch (action) {
                        case COMMENT_ONLY -> {
                            if (effective.comment() == null
                                    || effective.comment().isBlank()) {
                                throw new IllegalArgumentException("COMMENT_ONLY requires a comment");
                            }
                            yield FieldUpdate.NONE;
                        }
                        case RELEASE_LOCAL -> releaseLocal(analysis, auditTrailComments);
                        case AUTO, TAKE_LOCAL -> applySuppliedFields(effective, analysis, auditTrailComments);
                    };

            final List<String> comments = !effective.options().contains(MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL)
                    ? auditTrailComments
                    : new ArrayList<>();
            final boolean commentAdded = effective.comment() != null;
            if (commentAdded) {
                comments.add(effective.comment());
            }
            createAnalysisComments(analysis, effective.commenter(), comments);

            final OriginWrite originWrite = originWrite(action, update, created, commentAdded, inheritedBefore);
            if (originWrite.writesAnything()) {
                pm.flush();
                final long analysisId = analysis.getId();
                final AssessmentChange change = new AssessmentChange(
                        FINDING,
                        project.getUuid(),
                        effective.component().getUuid(),
                        effective.vulnerability().getUuid(),
                        AssessmentChange.Reason.AUTHORED,
                        AssessmentChange.LookupKey.listOf(project.getName(), project.getVersion()));
                JdbiFactory.useJdbiHandle(this, handle -> {
                    final var dao = new AssessmentOriginDao(handle);
                    if (originWrite.clearContributions()) {
                        dao.deleteCopiedContributions(analysisId);
                    }
                    if (originWrite.owner() != null) {
                        dao.upsertOrigin(analysisId, originWrite.owner(), update.machineChanged());
                    }
                    if (originWrite.recordChange()) {
                        new AssessmentChangeRecorder(handle).record(change);
                    }
                });
            }

            if (!effective.options().contains(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)
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

    /// A row without an origin is local, unless a vulnerability policy wrote it.
    private static boolean isReleasable(final Analysis analysis, final AssessmentOriginDao.Origin origin) {
        if (analysis == null) {
            return false;
        }
        if (origin == null) {
            return analysis.getVulnerabilityPolicyId() == null;
        }
        return origin.owner() == AssessmentOwnership.LOCAL;
    }

    /// REST API v1 resets an omitted state, justification, or response to {@code NOT_SET}.
    /// On an inherited analysis, omitted fields keep the inherited value instead (ADR 044).
    private static MakeAnalysisCommand applyV1Defaults(
            final MakeAnalysisCommand command, final boolean inheritedBefore) {
        if (!command.options().contains(MakeAnalysisCommand.Option.V1_RESET_OMITTED_DECISION) || inheritedBefore) {
            return command;
        }
        return command.withState(requireNonNullElse(command.state(), AnalysisState.NOT_SET))
                .withJustification(requireNonNullElse(command.justification(), AnalysisJustification.NOT_SET))
                .withResponse(requireNonNullElse(command.response(), AnalysisResponse.NOT_SET));
    }

    private static OriginWrite originWrite(
            final DecisionAction action,
            final FieldUpdate update,
            final boolean created,
            final boolean commentAdded,
            final boolean inheritedBefore) {
        return switch (action) {
            case RELEASE_LOCAL -> OriginWrite.owner(AssessmentOwnership.NEUTRAL, true, true);
            // The source trail stays as provenance while the decision is still the inherited one (ADR 044).
            case TAKE_LOCAL -> OriginWrite.owner(AssessmentOwnership.LOCAL, update.decisionChanged(), true);
            case COMMENT_ONLY ->
                created ? OriginWrite.owner(AssessmentOwnership.NEUTRAL, false, true) : OriginWrite.COMMENT_ONLY;
            case AUTO -> {
                if (update.machineChanged()) {
                    yield OriginWrite.owner(
                            AssessmentOwnership.LOCAL, inheritedBefore && update.decisionChanged(), true);
                }
                if (created) {
                    yield OriginWrite.owner(AssessmentOwnership.NEUTRAL, false, commentAdded);
                }
                yield commentAdded ? OriginWrite.COMMENT_ONLY : OriginWrite.NONE;
            }
        };
    }

    /// Blank and null details are the same explanation. Clients send either for an empty field.
    private static boolean sameDetails(final String left, final String right) {
        return StringUtils.isBlank(left) ? StringUtils.isBlank(right) : left.equals(right);
    }

    private AssessmentOriginDao.Origin currentOrigin(final long analysisId) {
        return JdbiFactory.withJdbiHandle(this, handle -> new AssessmentOriginDao(handle).findOrigin(analysisId));
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

        private boolean machineChanged() {
            return decisionChanged || detailsChanged;
        }
    }

    /// {@code owner} is null when ownership stays as it is.
    private record OriginWrite(AssessmentOwnership owner, boolean clearContributions, boolean recordChange) {

        private static final OriginWrite COMMENT_ONLY = new OriginWrite(null, false, true);
        private static final OriginWrite NONE = new OriginWrite(null, false, false);

        private static OriginWrite owner(
                final AssessmentOwnership owner, final boolean clearContributions, final boolean recordChange) {
            return new OriginWrite(owner, clearContributions, recordChange);
        }

        private boolean writesAnything() {
            return owner != null || clearContributions || recordChange;
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
