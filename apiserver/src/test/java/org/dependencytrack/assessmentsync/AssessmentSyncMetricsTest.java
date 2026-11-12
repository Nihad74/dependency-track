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

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import io.smallrye.config.SmallRyeConfigBuilder;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.eclipse.microprofile.config.spi.ConfigProviderResolver;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

class AssessmentSyncMetricsTest extends PersistenceCapableTest {

    @Test
    void backlogIsZeroWhenNothingIsPending() {
        final var registry = new SimpleMeterRegistry();
        AssessmentSyncMetrics.bind(registry);

        assertThat(registry.get(AssessmentSyncMetrics.BACKLOG_EVENTS).gauge().value())
                .isZero();
    }

    @ParameterizedTest
    @EnumSource(AssessmentSyncMode.class)
    void modesRemainOneHotAndBindingIsIdempotent(final AssessmentSyncMode mode) {
        final var registry = new SimpleMeterRegistry();
        AssessmentSyncMetrics.bind(registry);
        final int count = registry.getMeters().size();
        AssessmentSyncMetrics.bind(registry);
        assertThat(registry.getMeters()).hasSize(count);
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, mode.name());
        final Thread thread = Thread.currentThread();
        final ClassLoader applicationLoader = thread.getContextClassLoader();
        final ClassLoader managementLoader = new ClassLoader(applicationLoader) {};
        final var managementConfig = new SmallRyeConfigBuilder()
                .withDefaultValue(ConfigKeys.ASSESSMENT_SYNC_MODE, "OFF")
                .build();
        final var resolver = ConfigProviderResolver.instance();
        resolver.registerConfig(managementConfig, managementLoader);
        try {
            thread.setContextClassLoader(managementLoader);
            for (final var candidate : AssessmentSyncMode.values()) {
                assertThat(registry.get(AssessmentSyncMetrics.MODE)
                                .tag("mode", candidate.name())
                                .gauge()
                                .value())
                        .isEqualTo(candidate == mode ? 1d : 0d);
            }
            assertThat(registry.get(AssessmentSyncMetrics.ROLLBACK_INCOMPLETE)
                            .gauge()
                            .value())
                    .isZero();
        } finally {
            thread.setContextClassLoader(applicationLoader);
            resolver.releaseConfig(managementConfig);
            MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
        }
    }

    @Test
    void nullRegistryIsRejected() {
        assertThatThrownBy(() -> AssessmentSyncMetrics.bind(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("registry must not be null");
    }

    @Test
    void backlogAndAgeGaugesFollowBothKindsOfPendingWorkUntilCompletion() {
        final var registry = new SimpleMeterRegistry();
        AssessmentSyncMetrics.bind(registry);
        final UUID reconciliation = UUID.randomUUID();
        final UUID refresh = UUID.randomUUID();
        final UUID both = UUID.randomUUID();
        final UUID completed = UUID.randomUUID();
        useJdbiTransaction(handle -> {
            final var work = new AssessmentSyncWorkDao(handle);
            work.requestFull(reconciliation);
            work.requestRefresh(refresh);
            work.requestFull(both);
            work.requestRefresh(both);
            work.requestFull(completed);
            work.acknowledgeCancellation(completed);
            new AssessmentSyncOutboxDao(handle)
                    .recordAll(List.of(new AssessmentChange(
                            AssessmentChange.Scope.PROJECT,
                            reconciliation,
                            null,
                            null,
                            AssessmentChange.Reason.PROJECT_UPDATED,
                            List.of())));
            handle.execute("""
                    UPDATE "ASSESSMENT_SYNC_WORK" SET "PENDING_SINCE" = clock_timestamp() - INTERVAL '2 minutes'
                     WHERE "PENDING_SINCE" IS NOT NULL
                    """);
            handle.execute("""
                    UPDATE "ASSESSMENT_SYNC_OUTBOX" SET "CREATED_AT" = clock_timestamp() - INTERVAL '3 minutes'
                    """);
        });
        assertThat(registry.get(AssessmentSyncMetrics.BACKLOG_EVENTS).gauge().value())
                .isEqualTo(1d);
        assertThat(registry.get(AssessmentSyncMetrics.BACKLOG_WORK).gauge().value())
                .isEqualTo(3d);
        assertThat(registry.get(AssessmentSyncMetrics.OLDEST_EVENT_AGE_SECONDS)
                        .gauge()
                        .value())
                .isBetween(180d, 210d);
        assertThat(registry.get(AssessmentSyncMetrics.OLDEST_WORK_AGE_SECONDS)
                        .gauge()
                        .value())
                .isBetween(120d, 150d);
        useJdbiTransaction(handle -> {
            final var work = new AssessmentSyncWorkDao(handle);
            work.acknowledgeCancellation(reconciliation);
            work.acknowledgeRefresh(refresh, 1);
            work.acknowledgeCancellation(both);
            handle.execute("DELETE FROM \"ASSESSMENT_SYNC_OUTBOX\"");
        });
        for (final String metric : List.of(
                AssessmentSyncMetrics.BACKLOG_EVENTS,
                AssessmentSyncMetrics.BACKLOG_WORK,
                AssessmentSyncMetrics.OLDEST_EVENT_AGE_SECONDS,
                AssessmentSyncMetrics.OLDEST_WORK_AGE_SECONDS)) {
            assertThat(registry.get(metric).gauge().value()).as(metric).isZero();
        }
    }

    @Test
    void rollbackStaysIncompleteWhileALocalRowKeepsCopiedSourceText() {
        final var registry = new SimpleMeterRegistry();
        AssessmentSyncMetrics.bind(registry);
        final var project = qm.createProject("acme-app", null, "1.0.0", null, null, null, null, false);
        final var component = new Component();
        component.setProject(project);
        component.setName("acme-lib");
        component.setVersion("1.0.0");
        final Component persisted = qm.createComponent(component, false);
        final var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-ROLLBACK");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        final Vulnerability persistedVulnerability = qm.createVulnerability(vulnerability);
        final long analysisId = qm.makeAnalysis(new MakeAnalysisCommand(persisted, persistedVulnerability)
                .withState(AnalysisState.NOT_AFFECTED)
                .withOptions(Set.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        useJdbiTransaction(handle ->
                handle.createUpdate("""
                        INSERT INTO "ASSESSMENT_SOURCE_CONTRIBUTION" (
                          "TARGET_ANALYSIS_ID", "SOURCE_PROJECT_UUID", "SOURCE_COMPONENT_UUID"
                        , "SOURCE_VULNERABILITY_UUID", "SOURCE_ANALYSIS_ID", "SOURCE_DETAILS"
                        )
                        VALUES (:analysisId, gen_random_uuid(), gen_random_uuid(), gen_random_uuid(), 42, 'kept')
                        """).bind("analysisId", analysisId).execute());
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "OFF");
        try {
            assertThat(registry.get(AssessmentSyncMetrics.INHERITED).gauge().value())
                    .isZero();
            assertThat(registry.get(AssessmentSyncMetrics.ROLLBACK_INCOMPLETE)
                            .gauge()
                            .value())
                    .isEqualTo(1d);
        } finally {
            MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
        }
    }

    @Test
    void gaugeWhoseQueryFailsReportsNaNInsteadOfAnEmptyBacklog() {
        final var registry = new SimpleMeterRegistry();
        AssessmentSyncMetrics.bind(registry);
        useJdbiTransaction(handle -> handle.execute("""
                ALTER TABLE "ASSESSMENT_SYNC_OUTBOX" RENAME TO "ASSESSMENT_SYNC_OUTBOX_HIDDEN"
                """));
        try {
            assertThat(registry.get(AssessmentSyncMetrics.BACKLOG_EVENTS)
                            .gauge()
                            .value())
                    .isNaN();
            assertThat(registry.get(AssessmentSyncMetrics.OLDEST_EVENT_AGE_SECONDS)
                            .gauge()
                            .value())
                    .isNaN();
        } finally {
            useJdbiTransaction(handle -> handle.execute("""
                    ALTER TABLE "ASSESSMENT_SYNC_OUTBOX_HIDDEN" RENAME TO "ASSESSMENT_SYNC_OUTBOX"
                    """));
        }
    }
}
