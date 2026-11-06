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

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.ContinueAsNewOptions;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowRunContinuedAsNewError;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.proto.internal.workflow.v1.AssessmentMaintenanceOperation;
import org.dependencytrack.proto.internal.workflow.v1.MaintainAssessmentProjectionsArg;
import org.dependencytrack.proto.internal.workflow.v1.MaintainAssessmentProjectionsRes;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;

import java.util.UUID;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("unchecked") // Class literals cannot retain workflow and call-option argument types.
class AssessmentMaintenanceValidationTest {
    private static final MaintainAssessmentProjectionsArg ARGUMENT = MaintainAssessmentProjectionsArg.newBuilder()
            .setOperation(AssessmentMaintenanceOperation.ASSESSMENT_MAINTENANCE_OPERATION_VERIFY)
            .build();

    @ParameterizedTest
    @CsvSource({"0,1,projectBatchSize", "-1,1,projectBatchSize", "1,0,findingBatchSize", "1,-1,findingBatchSize"})
    void rejectsNonPositiveBatchSizes(final int projects, final int findings, final String field) {
        assertThatThrownBy(
                        () -> new MaintainAssessmentProjectionsActivity(projects, findings, new SimpleMeterRegistry()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage(field + " must be positive");
    }

    @Test
    void requiresAMeterRegistry() {
        assertThatThrownBy(() -> new MaintainAssessmentProjectionsActivity(1, 1, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("meterRegistry must not be null");
    }

    @Test
    void missingArgumentIsTerminalForTheActivityAndWorkflow() {
        assertThatThrownBy(() -> activity().execute(() -> UUID.randomUUID(), null))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("argument must not be null");
        assertThatThrownBy(() -> new MaintainAssessmentProjectionsWorkflow().execute(mock(WorkflowContext.class), null))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("argument must not be null");
    }

    @ParameterizedTest
    @ValueSource(ints = {0, -1, 4})
    void invalidOperationsFailBeforeAnyDatabaseWork(final int operation) {
        final var argument = ARGUMENT.toBuilder().setOperationValue(operation).build();
        assertThatThrownBy(() -> activity().execute(() -> UUID.randomUUID(), argument))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("operation must be BOOTSTRAP, VERIFY, or WITHDRAW");
        assertThatThrownBy(() ->
                        new MaintainAssessmentProjectionsWorkflow().execute(mock(WorkflowContext.class), argument))
                .isInstanceOf(TerminalApplicationFailureException.class);
        assertThatThrownBy(() -> MaintainAssessmentProjectionsWorkflow.instanceId(argument.getOperation()))
                .isInstanceOf(TerminalApplicationFailureException.class);
    }

    @Test
    void malformedCursorIsTerminalBeforeOpeningAConnection() {
        assertThatThrownBy(() -> activity()
                        .execute(
                                () -> UUID.randomUUID(),
                                ARGUMENT.toBuilder()
                                        .setProjectUuidCursor("invalid")
                                        .build()))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessageContaining("project_uuid_cursor");
    }

    @Test
    void interruptionIsPropagatedBeforeDatabaseWork() {
        Thread.currentThread().interrupt();
        try {
            assertThatThrownBy(() -> activity().execute(() -> UUID.randomUUID(), ARGUMENT))
                    .isInstanceOf(InterruptedException.class)
                    .hasMessage("Interrupted before assessment maintenance");
        } finally {
            Thread.interrupted();
        }
    }

    @Test
    void missingActivityResultIsTerminal() {
        final var ctx = context();
        when(ctx.activity(MaintainAssessmentProjectionsActivity.class)
                        .call(any(ActivityCallOptions.class))
                        .await())
                .thenReturn(null);
        assertThatThrownBy(() -> new MaintainAssessmentProjectionsWorkflow().execute(ctx, ARGUMENT))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("Maintenance activity returned no result");
    }

    @Test
    void moreWorkWithoutACursorIsTerminal() {
        final var ctx = context();
        when(ctx.activity(MaintainAssessmentProjectionsActivity.class)
                        .call(any(ActivityCallOptions.class))
                        .await())
                .thenReturn(MaintainAssessmentProjectionsRes.newBuilder()
                        .setHasMore(true)
                        .build());
        assertThatThrownBy(() -> new MaintainAssessmentProjectionsWorkflow().execute(ctx, ARGUMENT))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("project_uuid_cursor is required when has_more is set");
    }

    @Test
    void eachPageCarriesTheCursorAndContinuationPreservesTheOperation() {
        final var ctx = context();
        final String first = UUID.randomUUID().toString();
        final String last = UUID.randomUUID().toString();
        when(ctx.activity(MaintainAssessmentProjectionsActivity.class)
                        .call(any(ActivityCallOptions.class))
                        .await())
                .thenReturn(
                        MaintainAssessmentProjectionsRes.newBuilder()
                                .setHasMore(true)
                                .setProjectUuidCursor(first)
                                .build(),
                        MaintainAssessmentProjectionsRes.newBuilder()
                                .setHasMore(true)
                                .setProjectUuidCursor(last)
                                .build());
        org.mockito.Mockito.clearInvocations(ctx.activity(MaintainAssessmentProjectionsActivity.class));
        doThrow(new WorkflowRunContinuedAsNewError(null)).when(ctx).continueAsNew(any(ContinueAsNewOptions.class));
        assertThatThrownBy(() -> new MaintainAssessmentProjectionsWorkflow().execute(ctx, ARGUMENT))
                .isInstanceOf(WorkflowRunContinuedAsNewError.class);
        final ArgumentCaptor<ActivityCallOptions<MaintainAssessmentProjectionsArg>> pages =
                ArgumentCaptor.forClass(ActivityCallOptions.class);
        verify(ctx.activity(MaintainAssessmentProjectionsActivity.class), org.mockito.Mockito.times(2))
                .call(pages.capture());
        assertThat(pages.getAllValues().get(0).argument()).isEqualTo(ARGUMENT);
        assertThat(pages.getAllValues().get(1).argument())
                .isEqualTo(ARGUMENT.toBuilder().setProjectUuidCursor(first).build());
        final ArgumentCaptor<ContinueAsNewOptions<MaintainAssessmentProjectionsArg>> continued =
                ArgumentCaptor.forClass(ContinueAsNewOptions.class);
        verify(ctx).continueAsNew(continued.capture());
        assertThat(continued.getValue().argument())
                .isEqualTo(ARGUMENT.toBuilder().setProjectUuidCursor(last).build());
    }

    private static MaintainAssessmentProjectionsActivity activity() {
        return new MaintainAssessmentProjectionsActivity(1, 1, new SimpleMeterRegistry());
    }

    private static WorkflowContext<MaintainAssessmentProjectionsArg> context() {
        final WorkflowContext<MaintainAssessmentProjectionsArg> ctx = mock(WorkflowContext.class, RETURNS_DEEP_STUBS);
        when(ctx.<String>executeSideEffect(
                                eq("max-batches"), any(), org.mockito.ArgumentMatchers.<Supplier<String>>any())
                        .await())
                .thenReturn("2");
        return ctx;
    }
}
