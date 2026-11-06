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
package org.dependencytrack.assessmentsync;

import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.common.ConfigKeys;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AssessmentSyncModeTest {

    @ParameterizedTest
    @CsvSource({"OFF,false,false", "CAPTURE,true,false", "ACTIVE,true,true", "WITHDRAW,false,false"})
    void modesHaveTheDocumentedCapabilities(final String raw, final boolean captures, final boolean applies) {
        final var mode = AssessmentSyncMode.from(new SmallRyeConfigBuilder()
                .withDefaultValue(ConfigKeys.ASSESSMENT_SYNC_MODE, raw)
                .build());
        assertThat(mode.name()).isEqualTo(raw);
        assertThat(mode.recordsOutbox()).isEqualTo(captures);
        assertThat(mode.appliesAssessments()).isEqualTo(applies);
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "\t"})
    void missingAndBlankModesAreOff(final String raw) {
        final var builder = new SmallRyeConfigBuilder();
        if (raw != null) {
            builder.withDefaultValue(ConfigKeys.ASSESSMENT_SYNC_MODE, raw);
        }
        assertThat(AssessmentSyncMode.from(builder.build())).isEqualTo(AssessmentSyncMode.OFF);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ACTIV", "active", " ACTIVE "})
    void rejectsUnknownAndMisspelledModes(final String raw) {
        assertThatThrownBy(() -> AssessmentSyncMode.from(new SmallRyeConfigBuilder()
                        .withDefaultValue(ConfigKeys.ASSESSMENT_SYNC_MODE, raw)
                        .build()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(ConfigKeys.ASSESSMENT_SYNC_MODE)
                .hasMessageContaining(raw);
    }
}
