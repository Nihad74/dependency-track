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

import org.dependencytrack.assessmentsync.AssessmentSyncMode;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.proto.internal.workflow.v1.AssessmentMaintenanceOperation;
import org.dependencytrack.proto.internal.workflow.v1.MaintainAssessmentProjectionsArg;
import org.jspecify.annotations.Nullable;

/**
 * Which maintenance operation each mode runs, and whether an operation may keep running in a mode.
 */
final class MaintenanceOperations {

    private static final String INVALID = "operation must be BOOTSTRAP, VERIFY, or WITHDRAW";

    private MaintenanceOperations() {}

    /**
     * The operation the daily schedule starts. {@code OFF} starts nothing.
     */
    static @Nullable AssessmentMaintenanceOperation scheduledFor(final AssessmentSyncMode mode) {
        return switch (mode) {
            case CAPTURE -> AssessmentMaintenanceOperation.ASSESSMENT_MAINTENANCE_OPERATION_BOOTSTRAP;
            case ACTIVE -> AssessmentMaintenanceOperation.ASSESSMENT_MAINTENANCE_OPERATION_VERIFY;
            case WITHDRAW -> AssessmentMaintenanceOperation.ASSESSMENT_MAINTENANCE_OPERATION_WITHDRAW;
            case OFF -> null;
        };
    }

    /**
     * Backfill and verification keep running across {@code CAPTURE} and {@code ACTIVE}; withdrawal only in
     * {@code WITHDRAW}. A scan stops at the next project once its operation may no longer run.
     */
    static boolean runsIn(final AssessmentMaintenanceOperation operation, final AssessmentSyncMode mode) {
        return switch (operation) {
            case ASSESSMENT_MAINTENANCE_OPERATION_BOOTSTRAP, ASSESSMENT_MAINTENANCE_OPERATION_VERIFY ->
                mode.recordsOutbox();
            case ASSESSMENT_MAINTENANCE_OPERATION_WITHDRAW -> mode == AssessmentSyncMode.WITHDRAW;
            case ASSESSMENT_MAINTENANCE_OPERATION_UNSPECIFIED, UNRECOGNIZED -> false;
        };
    }

    static String name(final AssessmentMaintenanceOperation operation) {
        return switch (operation) {
            case ASSESSMENT_MAINTENANCE_OPERATION_BOOTSTRAP -> "BOOTSTRAP";
            case ASSESSMENT_MAINTENANCE_OPERATION_VERIFY -> "VERIFY";
            case ASSESSMENT_MAINTENANCE_OPERATION_WITHDRAW -> "WITHDRAW";
            case ASSESSMENT_MAINTENANCE_OPERATION_UNSPECIFIED, UNRECOGNIZED ->
                throw new TerminalApplicationFailureException(INVALID);
        };
    }

    static AssessmentMaintenanceOperation require(final @Nullable MaintainAssessmentProjectionsArg argument) {
        final AssessmentMaintenanceOperation operation =
                AssessmentSyncArguments.require(argument).getOperation();
        name(operation);
        return operation;
    }
}
