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

import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/// Backlog, mode, and drift gauges. Labels are the mode name or the maintenance operation.
public final class AssessmentSyncMetrics {

    private static final Logger LOGGER = LoggerFactory.getLogger(AssessmentSyncMetrics.class);

    public static final String MODE = "dt.assessment_sync.mode";
    public static final String BACKLOG_EVENTS = "dt.assessment_sync.backlog.events";
    public static final String BACKLOG_WORK = "dt.assessment_sync.backlog.work";
    public static final String OLDEST_EVENT_AGE_SECONDS = "dt.assessment_sync.backlog.oldest_event_age_seconds";
    public static final String INHERITED = "dt.assessment_sync.inherited";
    public static final String ROLLBACK_INCOMPLETE = "dt.assessment_sync.rollback.incomplete";
    public static final String DRIFT = "dt.assessment_sync.drift";

    private static final String MODE_TAG = "mode";

    private AssessmentSyncMetrics() {}

    /// Registers gauges on {@code registry}. A second call with the same registry does nothing.
    public static void bind(final MeterRegistry registry) {
        requireNonNull(registry, "registry must not be null");
        if (registry.find(MODE).tag(MODE_TAG, AssessmentSyncMode.OFF.name()).gauge() != null) {
            return;
        }
        for (final AssessmentSyncMode mode : AssessmentSyncMode.values()) {
            Gauge.builder(MODE, mode, candidate -> AssessmentSyncMode.current() == candidate ? 1d : 0d)
                    .description("1 when assessment synchronization is in this mode")
                    .tag(MODE_TAG, mode.name())
                    .strongReference(true)
                    .register(registry);
        }
        Gauge.builder(BACKLOG_EVENTS, AssessmentSyncMetrics::pendingEvents)
                .description("Assessment sync outbox rows still waiting")
                .strongReference(true)
                .register(registry);
        Gauge.builder(BACKLOG_WORK, AssessmentSyncMetrics::pendingWork)
                .description("Target projects whose reconciliation or refresh is unfinished")
                .strongReference(true)
                .register(registry);
        Gauge.builder(OLDEST_EVENT_AGE_SECONDS, AssessmentSyncMetrics::oldestEventAgeSeconds)
                .description("Age in seconds of the oldest assessment sync outbox row")
                .strongReference(true)
                .register(registry);
        Gauge.builder(INHERITED, AssessmentSyncMetrics::inheritedRows)
                .description("Analyses whose origin is still INHERITED")
                .strongReference(true)
                .register(registry);
        Gauge.builder(ROLLBACK_INCOMPLETE, AssessmentSyncMetrics::rollbackIncomplete)
                .description("1 when mode is OFF and inherited projections remain")
                .strongReference(true)
                .register(registry);
    }

    private static double pendingEvents() {
        return query(/* language=SQL */ """
                SELECT COUNT(*)::float8
                  FROM "ASSESSMENT_SYNC_OUTBOX"
                """);
    }

    private static double pendingWork() {
        return query(/* language=SQL */ """
                SELECT COUNT(*)::float8
                  FROM "ASSESSMENT_SYNC_WORK"
                 WHERE "REQUESTED_REVISION" > "COMPLETED_REVISION"
                    OR "REFRESH_REQUESTED" > "REFRESH_COMPLETED"
                """);
    }

    private static double oldestEventAgeSeconds() {
        return query(/* language=SQL */ """
                SELECT COALESCE(
                         EXTRACT(EPOCH FROM (clock_timestamp() - MIN("CREATED_AT")))
                       , 0
                       )::float8
                  FROM "ASSESSMENT_SYNC_OUTBOX"
                """);
    }

    private static double inheritedRows() {
        return query(/* language=SQL */ """
                SELECT COUNT(*)::float8
                  FROM "ASSESSMENT_ORIGIN"
                 WHERE "OWNER" = 'INHERITED'
                """);
    }

    private static double rollbackIncomplete() {
        if (AssessmentSyncMode.current() != AssessmentSyncMode.OFF) {
            return 0d;
        }
        return inheritedRows() > 0d ? 1d : 0d;
    }

    private static double query(final String sql) {
        try {
            final Double value = withJdbiHandle(
                    handle -> handle.createQuery(sql).mapTo(Double.class).one());
            return value == null ? 0d : value;
        } catch (RuntimeException e) {
            LOGGER.warn("Assessment sync metric query failed", e);
            return 0d;
        }
    }
}
