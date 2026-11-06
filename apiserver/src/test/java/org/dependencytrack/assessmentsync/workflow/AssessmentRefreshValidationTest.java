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

import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.proto.internal.workflow.v1.RefreshSynchronizedAssessmentsArg;
import org.dependencytrack.proto.internal.workflow.v1.SynchronizeProjectAssessmentsArg;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AssessmentRefreshValidationTest {

    private static final ActivityContext CONTEXT = () -> UUID.randomUUID();

    @Test
    void missingArgumentsFailTerminallyAtEachRefreshEntryPoint() {
        assertThatThrownBy(() -> new RefreshSynchronizedAssessmentsWorkflow().execute(null, null))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("argument must not be null");
        assertThatThrownBy(() -> new CompleteAssessmentRefreshActivity().execute(CONTEXT, null))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("argument must not be null");
        assertThatThrownBy(() -> new ReadAssessmentSyncPendingActivity().execute(CONTEXT, null))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("argument must not be null");
    }

    @ParameterizedTest
    @ValueSource(strings = {"", " ", "not-a-uuid"})
    void malformedTargetsFailTerminallyBeforeSchedulingOrDatabaseWork(final String uuid) {
        final var refresh = RefreshSynchronizedAssessmentsArg.newBuilder()
                .setProjectUuid(uuid)
                .setRefreshRevision(1)
                .build();
        assertThatThrownBy(() -> new RefreshSynchronizedAssessmentsWorkflow().execute(null, refresh))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("project_uuid must be a UUID");
        assertThatThrownBy(() -> new CompleteAssessmentRefreshActivity().execute(CONTEXT, refresh))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("project_uuid must be a UUID");
        assertThatThrownBy(() -> new ReadAssessmentSyncPendingActivity()
                        .execute(
                                CONTEXT,
                                SynchronizeProjectAssessmentsArg.newBuilder()
                                        .setProjectUuid(uuid)
                                        .build()))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("project_uuid must be a UUID");
    }

    @ParameterizedTest
    @ValueSource(longs = {0, -1})
    void nonPositiveRefreshRevisionsAreRejected(final long revision) {
        final UUID project = UUID.randomUUID();
        final var argument = RefreshSynchronizedAssessmentsArg.newBuilder()
                .setProjectUuid(project.toString())
                .setRefreshRevision(revision)
                .build();
        assertThatThrownBy(() -> new RefreshSynchronizedAssessmentsWorkflow().execute(null, argument))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("refresh_revision must be positive");
        assertThatThrownBy(() -> new CompleteAssessmentRefreshActivity().execute(CONTEXT, argument))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("refresh_revision must be positive");
        assertThatThrownBy(() -> RefreshSynchronizedAssessmentsWorkflow.instanceId(project, revision))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("refreshRevision must be positive");
    }

    @Test
    void stableRefreshIdSupportsTheLargestCapturedRevision() {
        final UUID project = UUID.randomUUID();
        assertThat(RefreshSynchronizedAssessmentsWorkflow.instanceId(project, Long.MAX_VALUE))
                .isEqualTo("assessment-refresh:" + project + ":" + Long.MAX_VALUE);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void interruptedCompletionAndPendingReadStopBeforeArgumentOrDatabaseWork(final boolean read) {
        Thread.currentThread().interrupt();
        try {
            assertThatThrownBy(() -> {
                        if (read) {
                            new ReadAssessmentSyncPendingActivity().execute(CONTEXT, null);
                        } else {
                            new CompleteAssessmentRefreshActivity().execute(CONTEXT, null);
                        }
                    })
                    .isInstanceOf(InterruptedException.class);
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void refreshInstanceIdRejectsAMissingTarget() {
        assertThatThrownBy(() -> RefreshSynchronizedAssessmentsWorkflow.instanceId(null, 1))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("targetUuid must not be null");
    }
}
