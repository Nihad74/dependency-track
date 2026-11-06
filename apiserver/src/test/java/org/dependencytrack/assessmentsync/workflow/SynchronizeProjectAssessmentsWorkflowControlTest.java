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

import org.dependencytrack.analysis.AnalyzeProjectWorkflow;
import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.ContinueAsNewOptions;
import org.dependencytrack.dex.api.WorkflowCallOptions;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowRunContinuedAsNewError;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.proto.internal.workflow.v1.AssessmentSyncPendingRes;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileProjectAssessmentsRes;
import org.dependencytrack.proto.internal.workflow.v1.RefreshSynchronizedAssessmentsArg;
import org.dependencytrack.proto.internal.workflow.v1.SynchronizeProjectAssessmentsArg;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
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
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SuppressWarnings("unchecked") // Class literals cannot retain workflow and call-option argument types.
class SynchronizeProjectAssessmentsWorkflowControlTest {

    private final UUID target = UUID.randomUUID();
    private final SynchronizeProjectAssessmentsArg argument = SynchronizeProjectAssessmentsArg.newBuilder()
            .setProjectUuid(target.toString())
            .build();
    private final WorkflowContext<SynchronizeProjectAssessmentsArg> ctx =
            mock(WorkflowContext.class, RETURNS_DEEP_STUBS);

    private void prepare() {
        when(ctx.<String>executeSideEffect(
                                eq("max-batches"), any(), org.mockito.ArgumentMatchers.<Supplier<String>>any())
                        .await())
                .thenReturn("2");
        when(ctx.activity(ReconcileProjectAssessmentsActivity.class)
                        .call(any(ActivityCallOptions.class))
                        .await())
                .thenReturn(ReconcileProjectAssessmentsRes.getDefaultInstance());
        doThrow(new WorkflowRunContinuedAsNewError(null)).when(ctx).continueAsNew(any(ContinueAsNewOptions.class));
    }

    @Test
    void missingReconciliationResultIsTerminal() {
        prepare();
        when(ctx.activity(ReconcileProjectAssessmentsActivity.class)
                        .call(any(ActivityCallOptions.class))
                        .await())
                .thenReturn(null);
        assertThatThrownBy(() -> new SynchronizeProjectAssessmentsWorkflow().execute(ctx, argument))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("Reconciliation activity returned no result");
    }

    @Test
    void missingPendingResultIsTerminal() {
        prepare();
        when(ctx.activity(ReadAssessmentSyncPendingActivity.class)
                        .call(any(ActivityCallOptions.class))
                        .await())
                .thenReturn(null);
        assertThatThrownBy(() -> new SynchronizeProjectAssessmentsWorkflow().execute(ctx, argument))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("Pending-work activity returned no result");
    }

    @Test
    void deletionDuringReconciliationStopsBeforeRefreshAndPendingRead() {
        prepare();
        when(ctx.activity(ReconcileProjectAssessmentsActivity.class)
                        .call(any(ActivityCallOptions.class))
                        .await())
                .thenReturn(ReconcileProjectAssessmentsRes.newBuilder()
                        .setTargetDeleted(true)
                        .setRefreshRevision(1)
                        .build());
        new SynchronizeProjectAssessmentsWorkflow().execute(ctx, argument);
        verify(ctx, never()).workflow(RefreshSynchronizedAssessmentsWorkflow.class);
        verify(ctx, never()).activity(ReadAssessmentSyncPendingActivity.class);
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void deletionObservedBeforeOrAfterRefreshEndsTheRun(final boolean afterRefresh) {
        prepare();
        final var deleted =
                AssessmentSyncPendingRes.newBuilder().setTargetDeleted(true).build();
        when(ctx.activity(ReadAssessmentSyncPendingActivity.class)
                        .call(any(ActivityCallOptions.class))
                        .await())
                .thenReturn(
                        afterRefresh
                                ? AssessmentSyncPendingRes.newBuilder()
                                        .setRefreshPending(true)
                                        .setRefreshRequested(3)
                                        .build()
                                : deleted,
                        deleted);
        new SynchronizeProjectAssessmentsWorkflow().execute(ctx, argument);
        verify(ctx, never()).continueAsNew(any(ContinueAsNewOptions.class));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void workArrivingDuringAnAdditionalRefreshContinuesWithTheSameTarget(final boolean reconciliation) {
        prepare();
        when(ctx.activity(ReadAssessmentSyncPendingActivity.class)
                        .call(any(ActivityCallOptions.class))
                        .await())
                .thenReturn(
                        AssessmentSyncPendingRes.newBuilder()
                                .setRefreshPending(true)
                                .setRefreshRequested(3)
                                .build(),
                        AssessmentSyncPendingRes.newBuilder()
                                .setReconciliationPending(reconciliation)
                                .setRefreshPending(!reconciliation)
                                .build());
        assertThatThrownBy(() -> new SynchronizeProjectAssessmentsWorkflow().execute(ctx, argument))
                .isInstanceOf(WorkflowRunContinuedAsNewError.class);
        final ArgumentCaptor<WorkflowCallOptions<RefreshSynchronizedAssessmentsArg>> child =
                ArgumentCaptor.forClass(WorkflowCallOptions.class);
        verify(ctx.workflow(RefreshSynchronizedAssessmentsWorkflow.class)).call(child.capture());
        assertThat(child.getValue().workflowInstanceId())
                .isEqualTo(RefreshSynchronizedAssessmentsWorkflow.instanceId(target, 3));
        assertThat(child.getValue().concurrencyKey())
                .isEqualTo(AnalyzeProjectWorkflow.concurrencyKeyForProject(target));
        assertThat(child.getValue().argument())
                .isEqualTo(RefreshSynchronizedAssessmentsArg.newBuilder()
                        .setProjectUuid(target.toString())
                        .setRefreshRevision(3)
                        .build());
        final ArgumentCaptor<ContinueAsNewOptions<SynchronizeProjectAssessmentsArg>> continued =
                ArgumentCaptor.forClass(ContinueAsNewOptions.class);
        verify(ctx).continueAsNew(continued.capture());
        assertThat(continued.getValue().argument()).isEqualTo(argument);
    }

    @Test
    void unacknowledgedCapturedRefreshContinuesInsteadOfDroppingTheRefresh() {
        prepare();
        when(ctx.activity(ReconcileProjectAssessmentsActivity.class)
                        .call(any(ActivityCallOptions.class))
                        .await())
                .thenReturn(ReconcileProjectAssessmentsRes.newBuilder()
                        .setRefreshRevision(2)
                        .build());
        when(ctx.activity(ReadAssessmentSyncPendingActivity.class)
                        .call(any(ActivityCallOptions.class))
                        .await())
                .thenReturn(AssessmentSyncPendingRes.newBuilder()
                        .setRefreshPending(true)
                        .setRefreshRequested(2)
                        .build());
        assertThatThrownBy(() -> new SynchronizeProjectAssessmentsWorkflow().execute(ctx, argument))
                .isInstanceOf(WorkflowRunContinuedAsNewError.class);
    }
}
