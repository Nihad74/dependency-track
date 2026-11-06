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

import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.assessmentsync.AssessmentNotReleasableException;
import org.dependencytrack.assessmentsync.AssessmentOriginDao;
import org.dependencytrack.assessmentsync.AssessmentOwnership;
import org.dependencytrack.assessmentsync.StaleAssessmentDecisionException;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.command.MakeAnalysisCommand.DecisionAction;
import org.dependencytrack.persistence.command.MakeAnalysisCommand.Option;
import org.dependencytrack.util.AnalysisCommentFormatter.AnalysisCommentField;
import org.jspecify.annotations.Nullable;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import static java.util.Objects.requireNonNullElse;
import static org.dependencytrack.util.AnalysisCommentFormatter.formatComment;

/**
 * Plans an authored analysis change without database access or mutation of the supplied values.
 * The writer executes the returned effects in the transaction that loaded and locked the finding.
 */
public final class AnalysisMutationPlanner {

    private AnalysisMutationPlanner() {}

    /** Scalar request values; no persistent entities can be loaded while planning or writing. */
    public record Request(
            @Nullable AnalysisState state,
            @Nullable AnalysisJustification justification,
            @Nullable AnalysisResponse response,
            @Nullable String details,
            @Nullable Boolean suppress,
            @Nullable String comment,
            @Nullable String owaspVector,
            @Nullable BigDecimal owaspScore,
            Set<Option> options,
            DecisionAction decisionAction,
            @Nullable Long expectedDecisionVersion) {

        public Request {
            options = Set.copyOf(options);
            if (decisionAction == DecisionAction.COMMENT_ONLY && StringUtils.isBlank(comment)) {
                throw new IllegalArgumentException("COMMENT_ONLY requires a comment");
            }
        }
    }

    /**
     * All effects of a write. A null owner leaves origin metadata unchanged. The version flag includes
     * both value changes and ownership transitions, including unlabeled legacy rows.
     * Values are a fresh scalar snapshot, with no references to persistent entities.
     */
    public record Plan(
            AnalysisValues values,
            boolean valuesChanged,
            boolean stateChanged,
            boolean suppressionChanged,
            @Nullable AssessmentOwnership owner,
            boolean advanceDecisionVersion,
            boolean dropCopiedTrail,
            boolean recordChange,
            boolean notifyDecisionChange,
            List<String> comments) {}

    public static Plan plan(
            final Request command,
            final @Nullable AnalysisValues stored,
            final AssessmentOriginDao.@Nullable Origin originBefore) {
        final long decisionVersionBefore = originBefore == null ? 0 : originBefore.decisionVersion();
        if (command.expectedDecisionVersion() != null && decisionVersionBefore != command.expectedDecisionVersion()) {
            throw new StaleAssessmentDecisionException();
        }
        if (command.decisionAction() == DecisionAction.RELEASE_LOCAL && !isReleasable(stored, originBefore)) {
            throw new AssessmentNotReleasableException();
        }
        final AnalysisValues analysis = stored == null ? newAnalysisValues() : copyValues(stored);
        final boolean inheritedBefore = originBefore != null && originBefore.owner() == AssessmentOwnership.INHERITED;
        final AssessmentOwnership ownerBefore = stored == null
                ? null
                : originBefore != null
                        ? originBefore.owner()
                        : AssessmentOwnership.ofUnlabeled(stored.getVulnerabilityPolicyId() != null);
        final Request effective = applyV1Defaults(command, inheritedBefore);
        final var auditTrailComments = new ArrayList<String>();
        final FieldUpdate update =
                switch (effective.decisionAction()) {
                    case COMMENT_ONLY -> FieldUpdate.NONE;
                    case RELEASE_LOCAL -> releaseLocal(analysis, auditTrailComments);
                    case AUTO, TAKE_LOCAL -> applySuppliedFields(effective, analysis, auditTrailComments);
                };
        final boolean created = stored == null;
        final boolean commentAdded = effective.comment() != null;
        final OriginWrite originWrite = planOriginWrite(effective.decisionAction(), update, created, commentAdded);
        final boolean versionMoves = update.valuesChanged()
                || (ownerBefore != null && originWrite.owner() != null && originWrite.owner() != ownerBefore);
        final List<String> comments =
                effective.options().contains(Option.OMIT_AUDIT_TRAIL) ? new ArrayList<>() : auditTrailComments;
        if (effective.comment() != null) {
            comments.add(effective.comment());
        }
        return new Plan(
                analysis,
                update.valuesChanged(),
                update.stateChanged(),
                update.suppressionChanged(),
                originWrite.owner(),
                versionMoves,
                originWrite.dropTrail(),
                originWrite.recordChange(),
                !effective.options().contains(Option.OMIT_NOTIFICATION)
                        && (update.stateChanged() || update.suppressionChanged()),
                List.copyOf(comments));
    }

    private static boolean isReleasable(
            final @Nullable AnalysisValues analysis, final AssessmentOriginDao.@Nullable Origin origin) {
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
    private static Request applyV1Defaults(final Request command, final boolean inheritedBefore) {
        if (!command.options().contains(MakeAnalysisCommand.Option.V1_RESET_OMITTED_DECISION) || inheritedBefore) {
            return command;
        }
        return new Request(
                requireNonNullElse(command.state(), AnalysisState.NOT_SET),
                requireNonNullElse(command.justification(), AnalysisJustification.NOT_SET),
                requireNonNullElse(command.response(), AnalysisResponse.NOT_SET),
                command.details(),
                command.suppress(),
                command.comment(),
                command.owaspVector(),
                command.owaspScore(),
                command.options(),
                command.decisionAction(),
                command.expectedDecisionVersion());
    }

    /**
     * The source trail stays as provenance while a local owner keeps the inherited decision (ADR 044). Any later
     * change to the decision drops it, whichever action makes the change.
     */
    private static OriginWrite planOriginWrite(
            final DecisionAction action, final FieldUpdate update, final boolean created, final boolean commentAdded) {
        return switch (action) {
            case RELEASE_LOCAL -> OriginWrite.claim(AssessmentOwnership.NEUTRAL).droppingTrailIf(true);
            case TAKE_LOCAL ->
                OriginWrite.claim(AssessmentOwnership.LOCAL).droppingTrailIf(update.structuredDecisionChanged());
            case COMMENT_ONLY -> created ? OriginWrite.claim(AssessmentOwnership.NEUTRAL) : OriginWrite.COMMENT_ONLY;
            case AUTO -> {
                if (update.valuesChanged()) {
                    yield OriginWrite.claim(AssessmentOwnership.LOCAL)
                            .droppingTrailIf(update.structuredDecisionChanged());
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
    private static boolean sameDetails(final String left, final @Nullable String right) {
        return StringUtils.isBlank(left) ? StringUtils.isBlank(right) : left.equals(right);
    }

    private static FieldUpdate applySuppliedFields(
            final Request command, final AnalysisValues analysis, final List<String> auditTrailComments) {
        boolean stateChanged = false;
        boolean suppressionChanged = false;
        boolean structuredDecisionChanged = false;
        boolean detailsChanged = false;

        if (command.state() != null && command.state() != analysis.getAnalysisState()) {
            auditTrailComments.add("Analysis: %s → %s".formatted(analysis.getAnalysisState(), command.state()));
            analysis.setAnalysisState(command.state());
            stateChanged = true;
            structuredDecisionChanged = true;
        }
        if (command.justification() != null && command.justification() != analysis.getAnalysisJustification()) {
            auditTrailComments.add(
                    "Justification: %s → %s".formatted(analysis.getAnalysisJustification(), command.justification()));
            analysis.setAnalysisJustification(command.justification());
            structuredDecisionChanged = true;
        }
        if (command.response() != null && command.response() != analysis.getAnalysisResponse()) {
            auditTrailComments.add(
                    "Vendor Response: %s → %s".formatted(analysis.getAnalysisResponse(), command.response()));
            analysis.setAnalysisResponse(command.response());
            structuredDecisionChanged = true;
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
            structuredDecisionChanged = true;
        }
        if (command.owaspVector() != null && !command.owaspVector().equals(analysis.getOwaspVector())) {
            auditTrailComments.add(
                    formatComment(AnalysisCommentField.OWASP_VECTOR, analysis.getOwaspVector(), command.owaspVector()));
            analysis.setOwaspVector(command.owaspVector());
            structuredDecisionChanged = true;
        }
        if (command.owaspScore() != null
                && (analysis.getOwaspScore() == null
                        || command.owaspScore().compareTo(analysis.getOwaspScore()) != 0)) {
            auditTrailComments.add(
                    formatComment(AnalysisCommentField.OWASP_SCORE, analysis.getOwaspScore(), command.owaspScore()));
            analysis.setOwaspScore(command.owaspScore());
            structuredDecisionChanged = true;
        }
        return new FieldUpdate(stateChanged, suppressionChanged, structuredDecisionChanged, detailsChanged);
    }

    private static FieldUpdate releaseLocal(final AnalysisValues analysis, final List<String> auditTrailComments) {
        boolean stateChanged = false;
        boolean suppressionChanged = false;
        boolean structuredDecisionChanged = false;

        if (analysis.getAnalysisState() != AnalysisState.NOT_SET) {
            auditTrailComments.add("Analysis: %s → %s".formatted(analysis.getAnalysisState(), AnalysisState.NOT_SET));
            analysis.setAnalysisState(AnalysisState.NOT_SET);
            stateChanged = true;
            structuredDecisionChanged = true;
        }
        if (analysis.getAnalysisJustification() != AnalysisJustification.NOT_SET) {
            auditTrailComments.add("Justification: %s → %s"
                    .formatted(analysis.getAnalysisJustification(), AnalysisJustification.NOT_SET));
            analysis.setAnalysisJustification(AnalysisJustification.NOT_SET);
            structuredDecisionChanged = true;
        }
        if (analysis.getAnalysisResponse() != AnalysisResponse.NOT_SET) {
            auditTrailComments.add(
                    "Vendor Response: %s → %s".formatted(analysis.getAnalysisResponse(), AnalysisResponse.NOT_SET));
            analysis.setAnalysisResponse(AnalysisResponse.NOT_SET);
            structuredDecisionChanged = true;
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
            structuredDecisionChanged = true;
        }
        structuredDecisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.SEVERITY,
                analysis.getSeverity(),
                () -> analysis.setSeverity(null));
        structuredDecisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.CVSSV2_VECTOR,
                analysis.getCvssV2Vector(),
                () -> analysis.setCvssV2Vector(null));
        structuredDecisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.CVSSV2_SCORE,
                analysis.getCvssV2Score(),
                () -> analysis.setCvssV2Score(null));
        structuredDecisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.CVSSV3_VECTOR,
                analysis.getCvssV3Vector(),
                () -> analysis.setCvssV3Vector(null));
        structuredDecisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.CVSSV3_SCORE,
                analysis.getCvssV3Score(),
                () -> analysis.setCvssV3Score(null));
        structuredDecisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.CVSSV4_VECTOR,
                analysis.getCvssV4Vector(),
                () -> analysis.setCvssV4Vector(null));
        structuredDecisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.CVSSV4_SCORE,
                analysis.getCvssV4Score(),
                () -> analysis.setCvssV4Score(null));
        structuredDecisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.OWASP_VECTOR,
                analysis.getOwaspVector(),
                () -> analysis.setOwaspVector(null));
        structuredDecisionChanged |= clearField(
                auditTrailComments,
                AnalysisCommentField.OWASP_SCORE,
                analysis.getOwaspScore(),
                () -> analysis.setOwaspScore(null));
        if (analysis.getVulnerabilityPolicyId() != null) {
            analysis.setVulnerabilityPolicyId(null);
            structuredDecisionChanged = true;
        }
        return new FieldUpdate(stateChanged, suppressionChanged, structuredDecisionChanged, detailsChanged);
    }

    private static boolean clearField(
            final List<String> auditTrailComments,
            final AnalysisCommentField field,
            final @Nullable Object currentValue,
            final Runnable clear) {
        if (currentValue == null) {
            return false;
        }
        auditTrailComments.add(formatComment(field, currentValue, null));
        clear.run();
        return true;
    }

    private record FieldUpdate(
            boolean stateChanged,
            boolean suppressionChanged,
            boolean structuredDecisionChanged,
            boolean detailsChanged) {

        private static final FieldUpdate NONE = new FieldUpdate(false, false, false, false);

        /**
         * The structured decision or the free-text details changed.
         */
        private boolean valuesChanged() {
            return structuredDecisionChanged || detailsChanged;
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
     * Values of a new analysis before the command is applied. Not persisted.
     */
    private static AnalysisValues newAnalysisValues() {
        final var values = new AnalysisValues();
        values.setAnalysisState(AnalysisState.NOT_SET);
        values.setAnalysisJustification(AnalysisJustification.NOT_SET);
        values.setAnalysisResponse(AnalysisResponse.NOT_SET);
        values.setSuppressed(false);
        return values;
    }

    private static AnalysisValues copyValues(final AnalysisValues source) {
        final var values = new AnalysisValues();
        values.setAnalysisState(source.getAnalysisState());
        values.setAnalysisJustification(source.getAnalysisJustification());
        values.setAnalysisResponse(source.getAnalysisResponse());
        values.setAnalysisDetails(source.getAnalysisDetails());
        values.setSuppressed(source.isSuppressed());
        values.setSeverity(source.getSeverity());
        values.setCvssV2Vector(source.getCvssV2Vector());
        values.setCvssV2Score(source.getCvssV2Score());
        values.setCvssV3Vector(source.getCvssV3Vector());
        values.setCvssV3Score(source.getCvssV3Score());
        values.setCvssV4Vector(source.getCvssV4Vector());
        values.setCvssV4Score(source.getCvssV4Score());
        values.setOwaspVector(source.getOwaspVector());
        values.setOwaspScore(source.getOwaspScore());
        values.setVulnerabilityPolicyId(source.getVulnerabilityPolicyId());
        return values;
    }
}
