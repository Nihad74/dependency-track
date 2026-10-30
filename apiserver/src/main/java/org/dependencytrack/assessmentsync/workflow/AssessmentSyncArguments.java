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

import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.jspecify.annotations.Nullable;

import java.util.UUID;

/// Validation shared by the assessment sync workflows and activities. Bad arguments are terminal.
final class AssessmentSyncArguments {

    private AssessmentSyncArguments() {}

    static <T> T require(final @Nullable T argument) {
        if (argument == null) {
            throw new TerminalApplicationFailureException("argument must not be null");
        }
        return argument;
    }

    static UUID projectUuid(final String projectUuid) {
        if (projectUuid.isBlank()) {
            throw new TerminalApplicationFailureException("project_uuid must be a UUID");
        }
        try {
            return UUID.fromString(projectUuid);
        } catch (IllegalArgumentException e) {
            throw new TerminalApplicationFailureException("project_uuid must be a UUID", e);
        }
    }
}
