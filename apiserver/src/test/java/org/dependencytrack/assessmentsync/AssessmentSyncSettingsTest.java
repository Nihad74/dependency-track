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
import org.eclipse.microprofile.config.Config;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AssessmentSyncSettingsTest {

    @Test
    void startupRejectsAnUnknownMode() {
        final Config config = configWithMode("ACTIV");

        assertThatThrownBy(() -> AssessmentSyncSettings.read(config))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(ConfigKeys.ASSESSMENT_SYNC_MODE)
                .hasMessageContaining("ACTIV");
    }

    @Test
    void rejectsNonPositiveRelayBounds() {
        assertThatThrownBy(() -> new AssessmentSyncSettings(0, 50, 5_000, 100, 200, 50))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AssessmentSyncSettings(1_000, 0, 5_000, 100, 200, 50))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AssessmentSyncSettings(1_000, 50, 0, 100, 200, 50))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AssessmentSyncSettings(1_000, 50, 500, 100, 200, 50))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(ConfigKeys.ASSESSMENT_SYNC_RELAY_MAX_BACKOFF_MS);
    }

    private static Config configWithMode(final String mode) {
        return new SmallRyeConfigBuilder()
                .withDefaultValue(ConfigKeys.ASSESSMENT_SYNC_MODE, mode)
                .withDefaultValue(ConfigKeys.ASSESSMENT_SYNC_RELAY_POLL_INTERVAL_MS, "1000")
                .withDefaultValue(ConfigKeys.ASSESSMENT_SYNC_RELAY_BATCH_SIZE, "50")
                .withDefaultValue(ConfigKeys.ASSESSMENT_SYNC_RELAY_MAX_BACKOFF_MS, "60000")
                .withDefaultValue(ConfigKeys.ASSESSMENT_SYNC_FANOUT_BATCH_SIZE, "100")
                .withDefaultValue(ConfigKeys.ASSESSMENT_SYNC_RECONCILE_BATCH_SIZE, "200")
                .withDefaultValue(ConfigKeys.ASSESSMENT_SYNC_WORKFLOW_MAX_BATCHES, "50")
                .build();
    }
}
