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

import org.jdbi.v3.core.Handle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collection;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Writes assessment invalidations through the caller's transaction.
 *
 * <p>Does not commit, open a transaction, or call Dex.
 */
public final class AssessmentChangeRecorder {

    private static final Logger LOGGER = LoggerFactory.getLogger(AssessmentChangeRecorder.class);

    private final Handle handle;

    public AssessmentChangeRecorder(final Handle handle) {
        this.handle = requireNonNull(handle, "handle must not be null");
    }

    /**
     * Records one change when the current mode captures outbox rows.
     */
    public void record(final AssessmentChange change) {
        recordAll(List.of(change));
    }

    /**
     * Records a batch when the current mode captures outbox rows.
     */
    public void recordAll(final Collection<AssessmentChange> changes) {
        requireNonNull(changes, "changes must not be null");
        if (changes.isEmpty()) {
            return;
        }
        final AssessmentSyncMode mode = AssessmentSyncMode.current();
        if (!mode.recordsOutbox()) {
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("Assessment sync capture skipped mode={} changes={}", mode, changes.size());
            }
            return;
        }
        new AssessmentSyncOutboxDao(handle).recordAll(changes);
        if (LOGGER.isDebugEnabled()) {
            for (final AssessmentChange change : changes) {
                LOGGER.debug(
                        "Staged assessment sync change projectUuid={} componentUuid={} vulnerabilityUuid={} scope={} reason={} mode={}",
                        change.projectUuid(),
                        change.componentUuid(),
                        change.vulnerabilityUuid(),
                        change.scope(),
                        change.reason(),
                        mode);
            }
        }
    }
}
