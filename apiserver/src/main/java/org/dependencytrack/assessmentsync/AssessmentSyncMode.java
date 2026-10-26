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

import org.dependencytrack.common.ConfigKeys;
import org.eclipse.microprofile.config.ConfigProvider;

/// Cluster-wide deployment mode for assessment synchronization.
///
/// Read on each capture. This type does not cache the value.
public enum AssessmentSyncMode {
    OFF,
    CAPTURE,
    ACTIVE,
    WITHDRAW;

    /// Outbox rows are written in capture and active modes only.
    public boolean recordsOutbox() {
        return this == CAPTURE || this == ACTIVE;
    }

    /// Current mode. A missing property is OFF. Any other unknown value is rejected.
    public static AssessmentSyncMode current() {
        final String raw = ConfigProvider.getConfig()
                .getOptionalValue(ConfigKeys.ASSESSMENT_SYNC_MODE, String.class)
                .filter(value -> !value.isBlank())
                .orElse(OFF.name());
        try {
            return AssessmentSyncMode.valueOf(raw);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Unknown " + ConfigKeys.ASSESSMENT_SYNC_MODE + " value: " + raw, e);
        }
    }
}
