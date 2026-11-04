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
package org.dependencytrack.assessmentsync.workflow;

import org.dependencytrack.assessmentsync.AssessmentSyncSettings;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jspecify.annotations.Nullable;

import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.dex.api.payload.PayloadConverters.stringConverter;

/**
 * Validation shared by the assessment sync workflows and activities. Bad arguments are terminal.
 */
final class AssessmentSyncArguments {

    private AssessmentSyncArguments() {}

    static <T> T require(final @Nullable T argument) {
        if (argument == null) {
            throw new TerminalApplicationFailureException("argument must not be null");
        }
        return argument;
    }

    static UUID projectUuid(final String projectUuid) {
        return uuid("project_uuid", projectUuid);
    }

    /**
     * {@code field} is the proto field name used in the failure message.
     */
    static UUID uuid(final String field, final String value) {
        if (value.isBlank()) {
            throw new TerminalApplicationFailureException(field + " must be a UUID");
        }
        try {
            return UUID.fromString(value);
        } catch (IllegalArgumentException e) {
            throw new TerminalApplicationFailureException(field + " must be a UUID", e);
        }
    }

    static long positive(final String field, final long value) {
        if (value <= 0) {
            throw new TerminalApplicationFailureException(field + " must be positive");
        }
        return value;
    }

    /**
     * Batches per run before continue-as-new, read once per run as a side effect so replay sees the same value.
     */
    static int maxBatches(final WorkflowContext<?> ctx) {
        return Integer.parseInt(requireNonNull(
                ctx.executeSideEffect(
                                "max-batches",
                                stringConverter(),
                                () -> Integer.toString(AssessmentSyncSettings.positiveInt(
                                        ConfigProvider.getConfig(), ConfigKeys.ASSESSMENT_SYNC_WORKFLOW_MAX_BATCHES)))
                        .await(),
                "max-batches"));
    }
}
