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

import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Severity;
import org.jspecify.annotations.Nullable;

import java.math.BigDecimal;

/**
 * Scalar analysis values, independent of JDO entities and lazy loading. Only the planner and writer
 * in this package can populate them; consumers of a completed plan can read the resulting values.
 */
public final class AnalysisValues {
    private AnalysisState analysisState = AnalysisState.NOT_SET;
    private @Nullable AnalysisJustification analysisJustification = AnalysisJustification.NOT_SET;
    private @Nullable AnalysisResponse analysisResponse = AnalysisResponse.NOT_SET;
    private @Nullable String analysisDetails;
    private boolean suppressed;
    private @Nullable Severity severity;
    private @Nullable String cvssV2Vector;
    private @Nullable BigDecimal cvssV2Score;
    private @Nullable String cvssV3Vector;
    private @Nullable BigDecimal cvssV3Score;
    private @Nullable String cvssV4Vector;
    private @Nullable BigDecimal cvssV4Score;
    private @Nullable String owaspVector;
    private @Nullable BigDecimal owaspScore;
    private @Nullable Long vulnerabilityPolicyId;

    public AnalysisState getAnalysisState() {
        return analysisState;
    }

    void setAnalysisState(final AnalysisState analysisState) {
        this.analysisState = analysisState;
    }

    public @Nullable AnalysisJustification getAnalysisJustification() {
        return analysisJustification;
    }

    void setAnalysisJustification(final @Nullable AnalysisJustification analysisJustification) {
        this.analysisJustification = analysisJustification;
    }

    public @Nullable AnalysisResponse getAnalysisResponse() {
        return analysisResponse;
    }

    void setAnalysisResponse(final @Nullable AnalysisResponse analysisResponse) {
        this.analysisResponse = analysisResponse;
    }

    public @Nullable String getAnalysisDetails() {
        return analysisDetails;
    }

    void setAnalysisDetails(final @Nullable String analysisDetails) {
        this.analysisDetails = analysisDetails;
    }

    public boolean isSuppressed() {
        return suppressed;
    }

    void setSuppressed(final boolean suppressed) {
        this.suppressed = suppressed;
    }

    public @Nullable Severity getSeverity() {
        return severity;
    }

    void setSeverity(final @Nullable Severity severity) {
        this.severity = severity;
    }

    public @Nullable String getCvssV2Vector() {
        return cvssV2Vector;
    }

    void setCvssV2Vector(final @Nullable String cvssV2Vector) {
        this.cvssV2Vector = cvssV2Vector;
    }

    public @Nullable BigDecimal getCvssV2Score() {
        return cvssV2Score;
    }

    void setCvssV2Score(final @Nullable BigDecimal cvssV2Score) {
        this.cvssV2Score = cvssV2Score;
    }

    public @Nullable String getCvssV3Vector() {
        return cvssV3Vector;
    }

    void setCvssV3Vector(final @Nullable String cvssV3Vector) {
        this.cvssV3Vector = cvssV3Vector;
    }

    public @Nullable BigDecimal getCvssV3Score() {
        return cvssV3Score;
    }

    void setCvssV3Score(final @Nullable BigDecimal cvssV3Score) {
        this.cvssV3Score = cvssV3Score;
    }

    public @Nullable String getCvssV4Vector() {
        return cvssV4Vector;
    }

    void setCvssV4Vector(final @Nullable String cvssV4Vector) {
        this.cvssV4Vector = cvssV4Vector;
    }

    public @Nullable BigDecimal getCvssV4Score() {
        return cvssV4Score;
    }

    void setCvssV4Score(final @Nullable BigDecimal cvssV4Score) {
        this.cvssV4Score = cvssV4Score;
    }

    public @Nullable String getOwaspVector() {
        return owaspVector;
    }

    void setOwaspVector(final @Nullable String owaspVector) {
        this.owaspVector = owaspVector;
    }

    public @Nullable BigDecimal getOwaspScore() {
        return owaspScore;
    }

    void setOwaspScore(final @Nullable BigDecimal owaspScore) {
        this.owaspScore = owaspScore;
    }

    public @Nullable Long getVulnerabilityPolicyId() {
        return vulnerabilityPolicyId;
    }

    void setVulnerabilityPolicyId(final @Nullable Long vulnerabilityPolicyId) {
        this.vulnerabilityPolicyId = vulnerabilityPolicyId;
    }
}
