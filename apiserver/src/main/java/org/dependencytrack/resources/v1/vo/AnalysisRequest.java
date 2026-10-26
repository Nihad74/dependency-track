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

import alpine.common.validation.RegexSequence;
import alpine.server.json.TrimmedStringDeserializer;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.jspecify.annotations.Nullable;

import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;

/**
 * Defines a custom request object used when updating analysis decisions.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
public class AnalysisRequest {

    /**
     * @deprecated The project is inferred from {@link #component}. This value is ignored.
     */
    @Deprecated(since = "5.0.0", forRemoval = true)
    @Pattern(
            regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            message = "The project must be a valid 36 character UUID")
    private final String project;

    @NotNull
    @Pattern(
            regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            message = "The component must be a valid 36 character UUID")
    private final String component;

    @NotNull
    @Pattern(
            regexp = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
            message = "The vulnerability must be a valid 36 character UUID")
    private final String vulnerability;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(
            regexp = RegexSequence.Definition.PRINTABLE_CHARS_PLUS,
            message = "The comment may only contain printable characters")
    private final String comment;

    @JsonDeserialize(using = TrimmedStringDeserializer.class)
    @Pattern(
            regexp = RegexSequence.Definition.PRINTABLE_CHARS_PLUS,
            message = "The comment may only contain printable characters")
    private final String analysisDetails;

    private final AnalysisState analysisState;

    private final AnalysisJustification analysisJustification;

    private final AnalysisResponse analysisResponse;

    // Optional. If not specified, we do not want to set value to false,
    // thus using Boolean object rather than primitive.
    private final Boolean suppressed;

    private final DecisionAction decisionAction;

    private final @Nullable Long expectedDecisionVersion;

    /**
     * How the caller wants an existing decision changed.
     * Clients cannot select policy or inherited ownership.
     */
    public enum DecisionAction {
        AUTO,
        COMMENT_ONLY,
        TAKE_LOCAL,
        RELEASE_LOCAL
    }

    public AnalysisRequest(
            String project,
            String component,
            String vulnerability,
            AnalysisState analysisState,
            AnalysisJustification analysisJustification,
            AnalysisResponse analysisResponse,
            String analysisDetails,
            String comment,
            Boolean suppressed) {
        this(
                project,
                component,
                vulnerability,
                analysisState,
                analysisJustification,
                analysisResponse,
                analysisDetails,
                comment,
                suppressed,
                DecisionAction.AUTO,
                null);
    }

    @JsonCreator
    public AnalysisRequest(
            @JsonProperty(value = "project") String project,
            @JsonProperty(value = "component", required = true) String component,
            @JsonProperty(value = "vulnerability", required = true) String vulnerability,
            @JsonProperty(value = "analysisState") AnalysisState analysisState,
            @JsonProperty(value = "analysisJustification") AnalysisJustification analysisJustification,
            @JsonProperty(value = "analysisResponse") AnalysisResponse analysisResponse,
            @JsonProperty(value = "analysisDetails") String analysisDetails,
            @JsonProperty(value = "comment") String comment,
            @JsonProperty(value = "isSuppressed") Boolean suppressed,
            @JsonProperty(value = "decisionAction") DecisionAction decisionAction,
            @JsonProperty(value = "expectedDecisionVersion") Long expectedDecisionVersion) {
        this.project = project;
        this.component = component;
        this.vulnerability = vulnerability;
        this.analysisState = analysisState;
        this.analysisJustification = analysisJustification;
        this.analysisResponse = analysisResponse;
        this.analysisDetails = analysisDetails;
        this.comment = comment;
        this.suppressed = suppressed;
        this.decisionAction = decisionAction == null ? DecisionAction.AUTO : decisionAction;
        this.expectedDecisionVersion = expectedDecisionVersion;
    }

    public String getProject() {
        return project;
    }

    public String getComponent() {
        return component;
    }

    public String getVulnerability() {
        return vulnerability;
    }

    @JsonIgnore
    public AnalysisState getRawAnalysisState() {
        return analysisState;
    }

    public AnalysisState getAnalysisState() {
        if (analysisState == null) {
            return AnalysisState.NOT_SET;
        } else {
            return analysisState;
        }
    }

    @JsonIgnore
    public AnalysisJustification getRawAnalysisJustification() {
        return analysisJustification;
    }

    public AnalysisJustification getAnalysisJustification() {
        if (analysisJustification == null) {
            return AnalysisJustification.NOT_SET;
        } else {
            return analysisJustification;
        }
    }

    @JsonIgnore
    public AnalysisResponse getRawAnalysisResponse() {
        return analysisResponse;
    }

    public AnalysisResponse getAnalysisResponse() {
        if (analysisResponse == null) {
            return AnalysisResponse.NOT_SET;
        } else {
            return analysisResponse;
        }
    }

    public String getAnalysisDetails() {
        return analysisDetails;
    }

    public String getComment() {
        return comment;
    }

    public Boolean isSuppressed() {
        return suppressed;
    }

    @JsonIgnore
    public Boolean getRawSuppressed() {
        return suppressed;
    }

    public DecisionAction getDecisionAction() {
        return decisionAction;
    }

    public @Nullable Long getExpectedDecisionVersion() {
        return expectedDecisionVersion;
    }
}
