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
import org.eclipse.microprofile.config.Config;

/// Validated assessment-sync settings. Non-positive batch and poll values are rejected.
public record AssessmentSyncSettings(
        long pollIntervalMillis,
        int relayBatchSize,
        long maxBackoffMillis,
        int fanoutBatchSize,
        int reconcileBatchSize,
        int maxBatches) {

    public AssessmentSyncSettings {
        requirePositive(pollIntervalMillis, ConfigKeys.ASSESSMENT_SYNC_RELAY_POLL_INTERVAL_MS);
        requirePositive(relayBatchSize, ConfigKeys.ASSESSMENT_SYNC_RELAY_BATCH_SIZE);
        requirePositive(maxBackoffMillis, ConfigKeys.ASSESSMENT_SYNC_RELAY_MAX_BACKOFF_MS);
        requirePositive(fanoutBatchSize, ConfigKeys.ASSESSMENT_SYNC_FANOUT_BATCH_SIZE);
        requirePositive(reconcileBatchSize, ConfigKeys.ASSESSMENT_SYNC_RECONCILE_BATCH_SIZE);
        requirePositive(maxBatches, ConfigKeys.ASSESSMENT_SYNC_WORKFLOW_MAX_BATCHES);
        if (maxBackoffMillis < pollIntervalMillis) {
            throw new IllegalArgumentException(ConfigKeys.ASSESSMENT_SYNC_RELAY_MAX_BACKOFF_MS
                    + " must be greater than or equal to " + ConfigKeys.ASSESSMENT_SYNC_RELAY_POLL_INTERVAL_MS);
        }
    }

    /// Also rejects an unknown mode, so a typo fails startup instead of every later write.
    public static AssessmentSyncSettings read(final Config config) {
        AssessmentSyncMode.from(config);
        return new AssessmentSyncSettings(
                config.getValue(ConfigKeys.ASSESSMENT_SYNC_RELAY_POLL_INTERVAL_MS, long.class),
                config.getValue(ConfigKeys.ASSESSMENT_SYNC_RELAY_BATCH_SIZE, int.class),
                config.getValue(ConfigKeys.ASSESSMENT_SYNC_RELAY_MAX_BACKOFF_MS, long.class),
                config.getValue(ConfigKeys.ASSESSMENT_SYNC_FANOUT_BATCH_SIZE, int.class),
                config.getValue(ConfigKeys.ASSESSMENT_SYNC_RECONCILE_BATCH_SIZE, int.class),
                config.getValue(ConfigKeys.ASSESSMENT_SYNC_WORKFLOW_MAX_BATCHES, int.class));
    }

    public static int positiveInt(final Config config, final String key) {
        final int value = config.getValue(key, int.class);
        requirePositive(value, key);
        return value;
    }

    private static void requirePositive(final long value, final String key) {
        if (value <= 0) {
            throw new IllegalArgumentException(key + " must be positive");
        }
    }
}
