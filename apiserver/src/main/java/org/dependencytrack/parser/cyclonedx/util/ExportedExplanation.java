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

import org.dependencytrack.assessmentsync.AssessmentTrailAssembler.SourceAssessment;
import org.dependencytrack.assessmentsync.AssessmentTrailAssembler.Trail;
import org.dependencytrack.model.Analysis;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.apache.commons.lang3.StringUtils.trimToNull;

/**
 * The one {@code analysis.detail} string CycloneDX allows for a finding, and the sources it is copied from.
 *
 * <p>Target-local details win. Otherwise source text is copied only when every source the caller may read has
 * that same text, and those sources are named. Differing or missing text is omitted.
 */
record ExportedExplanation(@Nullable String detail, List<SourceAttribution> sources) {

    ExportedExplanation {
        sources = List.copyOf(sources);
    }

    static ExportedExplanation none() {
        return new ExportedExplanation(null, List.of());
    }

    /**
     * {@code trails} holds the readable source trails by target analysis id.
     */
    static ExportedExplanation of(final @Nullable Analysis analysis, final Map<Long, Trail> trails) {
        if (analysis == null) {
            return none();
        }
        final Trail trail = trails.get(analysis.getId());
        final String local =
                trail == null ? trimToNull(analysis.getAnalysisDetails()) : trimToNull(trail.localDetails());
        if (local != null) {
            return new ExportedExplanation(local, List.of());
        }
        if (trail == null || trail.sourceAssessments().isEmpty()) {
            return none();
        }
        final var sources = new ArrayList<SourceAttribution>();
        for (final SourceAssessment source : trail.sourceAssessments()) {
            final String text = trimToNull(source.sourceDetails());
            if (text == null) {
                return none();
            }
            sources.add(new SourceAttribution(source.project().uuid(), label(source), text));
        }
        final List<String> distinctTexts =
                sources.stream().map(SourceAttribution::text).distinct().toList();
        if (distinctTexts.size() != 1) {
            return none();
        }
        sources.sort(Comparator.comparing(SourceAttribution::projectUuid));
        return new ExportedExplanation(distinctTexts.getFirst(), sources);
    }

    List<UUID> sourceProjectUuids() {
        return sources.stream().map(SourceAttribution::projectUuid).toList();
    }

    /**
     * "name@version name@version uuid" of the source project and component, as exported in a property.
     */
    private static String label(final SourceAssessment source) {
        return identity(source.project().name(), source.project().version())
                + " "
                + identity(source.component().name(), source.component().version())
                + " "
                + source.project().uuid();
    }

    private static String identity(final String name, final @Nullable String version) {
        return version == null || version.isBlank() ? name : name + "@" + version;
    }

    record SourceAttribution(UUID projectUuid, String label, String text) {}
}
