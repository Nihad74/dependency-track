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
package org.dependencytrack.resources.v1.vo;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import org.dependencytrack.assessmentsync.AssessmentOwnership;
import org.dependencytrack.assessmentsync.AssessmentTrailAssembler;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Severity;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;

/// @since 5.2.0
@NullMarked
@JsonInclude(JsonInclude.Include.NON_NULL)
public record AnalysisTrailResponse(
        @Schema(description = "The state of the analysis decision", requiredMode = Schema.RequiredMode.REQUIRED)
        AnalysisState analysisState,

        @Schema(description = "The justification of the analysis decision") @Nullable
        AnalysisJustification analysisJustification,

        @Schema(description = "The vendor response to the vulnerability") @Nullable
        AnalysisResponse analysisResponse,

        @Schema(description = "Free-form details of the analysis decision") @Nullable
        String analysisDetails,

        @Schema(description = "Audit trail of analysis comments", requiredMode = Schema.RequiredMode.REQUIRED)
        List<Comment> analysisComments,

        @JsonProperty("isSuppressed")
        @Schema(description = "Whether the finding is suppressed", requiredMode = Schema.RequiredMode.REQUIRED)
        boolean isSuppressed,

        @Schema(description = "Severity assigned by the analysis") @Nullable
        Severity severity,

        @Schema(description = "CVSS v2 vector assigned by the analysis") @Nullable
        String cvssV2Vector,

        @Schema(description = "CVSS v2 score assigned by the analysis") @Nullable
        BigDecimal cvssV2Score,

        @Schema(description = "CVSS v3 vector assigned by the analysis") @Nullable
        String cvssV3Vector,

        @Schema(description = "CVSS v3 score assigned by the analysis") @Nullable
        BigDecimal cvssV3Score,

        @Schema(description = "CVSS v4 vector assigned by the analysis") @Nullable
        String cvssV4Vector,

        @Schema(description = "CVSS v4 score assigned by the analysis") @Nullable
        BigDecimal cvssV4Score,

        @Schema(description = "OWASP Risk Rating vector assigned by the analysis") @Nullable
        String owaspVector,

        @Schema(description = "OWASP Risk Rating score assigned by the analysis") @Nullable
        BigDecimal owaspScore,

        @Schema(description = "Who owns the structured decision. Null when no origin row exists") @Nullable
        AssessmentOwnership decisionOrigin,

        @Schema(
                description = "Origin version, or 0 when no origin row exists",
                requiredMode = Schema.RequiredMode.REQUIRED)
        long decisionVersion,

        @Schema(description = "Generic inheritance status. Contains no source name or count") @Nullable
        String inheritanceStatus,

        @JsonInclude(JsonInclude.Include.NON_EMPTY)
        @Schema(description = "Source assessments the caller can currently read. Hidden sources are omitted")
        List<SourceAssessment> sourceAssessments) {

    public static AnalysisTrailResponse of(Analysis analysis) {
        return of(analysis, null);
    }

    /// Machine fields come from the target analysis. Inherited rows do not expose copied details here.
    public static AnalysisTrailResponse of(Analysis analysis, AssessmentTrailAssembler.@Nullable Trail trail) {
        final List<AnalysisComment> jdoComments = analysis.getAnalysisComments();
        final List<Comment> comments =
                jdoComments != null ? jdoComments.stream().map(Comment::of).toList() : List.of();
        final String details = trail == null ? analysis.getAnalysisDetails() : trail.localDetails();

        return new AnalysisTrailResponse(
                analysis.getAnalysisState(),
                analysis.getAnalysisJustification(),
                analysis.getAnalysisResponse(),
                details,
                comments,
                analysis.isSuppressed(),
                analysis.getSeverity(),
                analysis.getCvssV2Vector(),
                analysis.getCvssV2Score(),
                analysis.getCvssV3Vector(),
                analysis.getCvssV3Score(),
                analysis.getCvssV4Vector(),
                analysis.getCvssV4Score(),
                analysis.getOwaspVector(),
                analysis.getOwaspScore(),
                trail == null ? null : trail.decisionOrigin(),
                trail == null ? 0 : trail.decisionVersion(),
                trail == null ? null : trail.inheritanceStatus(),
                sourceAssessments(trail));
    }

    private static List<SourceAssessment> sourceAssessments(AssessmentTrailAssembler.@Nullable Trail trail) {
        if (trail == null || trail.sourceAssessments().isEmpty()) {
            return List.of();
        }
        final var groups =
                new ArrayList<SourceAssessment>(trail.sourceAssessments().size());
        for (final AssessmentTrailAssembler.SourceAssessment source : trail.sourceAssessments()) {
            final var comments = new ArrayList<SourceComment>(source.comments().size());
            for (final AssessmentTrailAssembler.SourceComment comment : source.comments()) {
                comments.add(new SourceComment(Date.from(comment.timestamp()), comment.comment(), comment.author()));
            }
            groups.add(new SourceAssessment(
                    new ProjectIdentity(
                            source.project().uuid(),
                            source.project().name(),
                            source.project().version()),
                    new ComponentIdentity(
                            source.component().uuid(),
                            source.component().name(),
                            source.component().version()),
                    source.sourceDetails(),
                    List.copyOf(comments)));
        }
        return List.copyOf(groups);
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record Comment(
            @Schema(description = "Timestamp the comment was recorded at", requiredMode = Schema.RequiredMode.REQUIRED)
            Date timestamp,

            @Schema(description = "The comment text", requiredMode = Schema.RequiredMode.REQUIRED)
            String comment,

            @Schema(description = "Identifier of the user who wrote the comment") @Nullable
            String commenter) {

        public static Comment of(AnalysisComment jdo) {
            return new Comment(jdo.getTimestamp(), jdo.getComment(), jdo.getCommenter());
        }
    }

    /// One source project the caller can read. There is no companion count of hidden sources.
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record SourceAssessment(
            @Schema(description = "Source project", requiredMode = Schema.RequiredMode.REQUIRED)
            ProjectIdentity project,

            @Schema(description = "Source component", requiredMode = Schema.RequiredMode.REQUIRED)
            ComponentIdentity component,

            @Schema(description = "Explanation copied from the source assessment") @Nullable
            String sourceDetails,

            @Schema(description = "Original source comments", requiredMode = Schema.RequiredMode.REQUIRED)
            List<SourceComment> comments) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ProjectIdentity(
            @Schema(description = "Project UUID", requiredMode = Schema.RequiredMode.REQUIRED)
            UUID uuid,

            @Schema(description = "Project name", requiredMode = Schema.RequiredMode.REQUIRED)
            String name,

            @Schema(description = "Project version") @Nullable
            String version) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record ComponentIdentity(
            @Schema(description = "Component UUID", requiredMode = Schema.RequiredMode.REQUIRED)
            UUID uuid,

            @Schema(description = "Component name", requiredMode = Schema.RequiredMode.REQUIRED)
            String name,

            @Schema(description = "Component version") @Nullable
            String version) {}

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record SourceComment(
            @Schema(description = "Original comment timestamp", requiredMode = Schema.RequiredMode.REQUIRED)
            Date timestamp,

            @Schema(description = "Original comment text", requiredMode = Schema.RequiredMode.REQUIRED)
            String comment,

            @Schema(description = "Original comment author") @Nullable
            String commenter) {}
}
