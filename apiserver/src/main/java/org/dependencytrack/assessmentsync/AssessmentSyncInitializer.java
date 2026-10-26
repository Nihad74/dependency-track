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
import org.dependencytrack.dex.engine.api.DexEngine;
import org.eclipse.microprofile.config.Config;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;

import static java.util.Objects.requireNonNull;

/// Starts the assessment sync relay after the Dex engine is available.
public final class AssessmentSyncInitializer implements ServletContextListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(AssessmentSyncInitializer.class);

    private final Config config = ConfigProvider.getConfig();
    private @Nullable AssessmentSyncRelay relay;

    @Override
    public void contextInitialized(final ServletContextEvent event) {
        final AssessmentSyncSettings settings = AssessmentSyncSettings.read(config);
        final ServletContext servletContext = event.getServletContext();
        final var dexEngine = (DexEngine) servletContext.getAttribute(DexEngine.class.getName());
        requireNonNull(dexEngine, "dexEngine has not been initialized");

        LOGGER.info("Starting assessment sync relay");
        relay = new AssessmentSyncRelay(
                dexEngine,
                Metrics.globalRegistry,
                settings.pollIntervalMillis(),
                settings.relayBatchSize(),
                settings.maxBackoffMillis());
        AssessmentSyncMetrics.bind(Metrics.globalRegistry);
        relay.start();
    }

    @Override
    public void contextDestroyed(final ServletContextEvent event) {
        if (relay != null) {
            LOGGER.info("Stopping assessment sync relay");
            relay.close();
        }
    }
}
