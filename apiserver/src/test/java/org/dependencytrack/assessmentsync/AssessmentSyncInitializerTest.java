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

import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.dex.engine.api.DexEngine;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AssessmentSyncInitializerTest {
    private final SimpleMeterRegistry registry = new SimpleMeterRegistry();
    private final AssessmentSyncInitializer initializer = new AssessmentSyncInitializer();
    private final ServletContext context = mock(ServletContext.class);
    private final ServletContextEvent event = new ServletContextEvent(context);

    @BeforeEach
    void setUp() {
        Metrics.addRegistry(registry);
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "OFF");
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_RELAY_POLL_INTERVAL_MS, "1");
    }

    @AfterEach
    void tearDown() {
        initializer.contextDestroyed(event);
        Metrics.removeRegistry(registry);
        registry.close();
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_RELAY_POLL_INTERVAL_MS);
    }

    @Test
    void startsTheRelayAndRegistersMetricsAfterDexIsAvailable() {
        final var engine = mock(DexEngine.class);
        when(context.getAttribute(DexEngine.class.getName())).thenReturn(engine);
        initializer.contextInitialized(event);
        await("scheduled relay cycle").atMost(Duration.ofSeconds(2)).untilAsserted(() -> {
            final var cycles = registry.find("dt.assessment_sync.relay.cycles")
                    .tag("outcome", "SKIPPED")
                    .counter();
            assertThat(cycles).isNotNull();
            assertThat(cycles.count()).isPositive();
        });
        assertThat(registry.find(AssessmentSyncMetrics.MODE).tag("mode", "OFF").gauge())
                .isNotNull();
        verifyNoInteractions(engine);
        initializer.contextDestroyed(event);
    }

    @Test
    void failsBeforeStartingTheRelayWhenDexIsMissing() {
        assertThatThrownBy(() -> initializer.contextInitialized(event))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("dexEngine has not been initialized");
    }

    @Test
    void rejectsInvalidSettingsBeforeLookingUpDex() {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_RELAY_POLL_INTERVAL_MS, "0");
        assertThatThrownBy(() -> initializer.contextInitialized(event))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(ConfigKeys.ASSESSMENT_SYNC_RELAY_POLL_INTERVAL_MS);
        verifyNoInteractions(context);
    }

    @Test
    void destroyingBeforeInitializationIsHarmless() {
        initializer.contextDestroyed(event);
        initializer.contextDestroyed(event);
        verifyNoInteractions(context);
    }
}
