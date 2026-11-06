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
package org.dependencytrack.parser.cyclonedx.util;

import org.dependencytrack.assessmentsync.AssessmentOwnership;
import org.dependencytrack.assessmentsync.AssessmentTrailAssembler.AnalysisSnapshot;
import org.dependencytrack.assessmentsync.AssessmentTrailAssembler.ComponentIdentity;
import org.dependencytrack.assessmentsync.AssessmentTrailAssembler.ProjectIdentity;
import org.dependencytrack.assessmentsync.AssessmentTrailAssembler.SourceAssessment;
import org.dependencytrack.assessmentsync.AssessmentTrailAssembler.Trail;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class ExportedExplanationTest {
    private static final UUID FIRST = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID SECOND = UUID.fromString("00000000-0000-0000-0000-000000000002");

    @Test
    void absentAuthorizedTrailCannotFallBackToStaleAnalysisDetails() {
        final Analysis analysis = analysis();
        analysis.setAnalysisDetails("stale copied text");
        assertThat(ExportedExplanation.of(analysis, Map.of())).isEqualTo(ExportedExplanation.none());
        assertThat(ExportedExplanation.of(null, Map.of())).isEqualTo(ExportedExplanation.none());
    }

    @Test
    void freshLocalDetailsTakePrecedenceAndAnEmptyTrailHasNoExplanation() {
        final Analysis analysis = analysis();
        analysis.setAnalysisDetails("stale local text");
        final var local = trail(" fresh local text ", List.of(source(FIRST, "1", "source text")));
        assertThat(ExportedExplanation.of(analysis, Map.of(1L, local)))
                .isEqualTo(new ExportedExplanation("fresh local text", List.of()));
        assertThat(ExportedExplanation.of(analysis, Map.of(1L, trail(null, List.of()))))
                .isEqualTo(ExportedExplanation.none());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" "})
    void missingSourceTextPreventsAnUnattributedExplanation(final String missing) {
        final var sources = List.of(source(FIRST, "1", "agreed"), source(SECOND, "1", missing));
        assertThat(ExportedExplanation.of(analysis(), Map.of(1L, trail(null, sources))))
                .isEqualTo(ExportedExplanation.none());
    }

    @Test
    void differingAuthorizedTextsAreOmitted() {
        assertThat(ExportedExplanation.of(
                        analysis(),
                        Map.of(1L, trail(null, List.of(source(FIRST, "1", "first"), source(SECOND, "1", "second"))))))
                .isEqualTo(ExportedExplanation.none());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "1"})
    void agreeingTextsAreTrimmedAndAttributedInProjectOrder(final String version) {
        final var explanation = ExportedExplanation.of(
                analysis(),
                Map.of(
                        1L,
                        trail(null, List.of(source(SECOND, version, " agreed "), source(FIRST, version, "agreed")))));
        assertThat(explanation.detail()).isEqualTo("agreed");
        assertThat(explanation.sources())
                .extracting(ExportedExplanation.SourceAttribution::projectUuid)
                .containsExactly(FIRST, SECOND);
        final String suffix = version == null || version.isBlank() ? "" : "@" + version;
        assertThat(explanation.sources().getFirst().label())
                .isEqualTo("project" + suffix + " component" + suffix + " " + FIRST);
    }

    private static Analysis analysis() {
        final var analysis = new Analysis();
        analysis.setId(1);
        return analysis;
    }

    private static Trail trail(final String localDetails, final List<SourceAssessment> sources) {
        return new Trail(
                1,
                new AnalysisSnapshot(
                        AnalysisState.NOT_SET, null, null, false, null, null, null, null, null, null, null, null, null),
                AssessmentOwnership.INHERITED,
                1,
                localDetails,
                sources);
    }

    private static SourceAssessment source(final UUID project, final String version, final String details) {
        return new SourceAssessment(
                new ProjectIdentity(project, "project", version),
                new ComponentIdentity(UUID.randomUUID(), "component", version),
                details,
                List.of());
    }
}
