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

import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.proto.internal.workflow.v1.ExpandAssessmentChangesArg;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ExpandAssessmentChangesValidationTest {
    private static final ActivityContext CONTEXT = () -> UUID.randomUUID();

    @Test
    @SuppressWarnings("unchecked") // Class literals cannot retain WorkflowContext's argument type.
    void aMissingActivityResultFailsTheWorkflowTerminally() {
        final WorkflowContext<ExpandAssessmentChangesArg> ctx = mock(WorkflowContext.class, RETURNS_DEEP_STUBS);
        when(ctx.<String>executeSideEffect(
                                eq("max-batches"), any(), org.mockito.ArgumentMatchers.<Supplier<String>>any())
                        .await())
                .thenReturn("1");
        when(ctx.activity(ExpandAssessmentChangesActivity.class)
                        .call(any(ActivityCallOptions.class))
                        .await())
                .thenReturn(null);
        assertThatThrownBy(() -> new ExpandAssessmentChangesWorkflow()
                        .execute(
                                ctx,
                                ExpandAssessmentChangesArg.newBuilder()
                                        .setOutboxId(1)
                                        .build()))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("Expansion activity returned no result");
    }

    @ParameterizedTest
    @CsvSource({
        "0,2,fanoutBatchSize",
        "-1,2,fanoutBatchSize",
        "2,0,reconcileBatchSize",
        "2,-1,reconcileBatchSize",
        "2147483647,2,fanoutBatchSize",
        "2,2147483647,reconcileBatchSize"
    })
    void rejectsSizesThatCannotProduceABoundedLookahead(final int fanout, final int reconcile, final String field) {
        assertThatThrownBy(() -> new ExpandAssessmentChangesActivity(fanout, reconcile))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining(field);
    }

    @Test
    void acceptsTheLargestRepresentableLookaheadAndRejectsANullHook() {
        assertThat(new ExpandAssessmentChangesActivity(Integer.MAX_VALUE - 1, Integer.MAX_VALUE - 1))
                .isNotNull();
        assertThatThrownBy(() -> new ExpandAssessmentChangesActivity(1, 1, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("beforeExpand must not be null");
    }

    @Test
    void interruptionIsCheckedBeforeTheHookOrAnyDatabaseWork() {
        final var entered = new AtomicBoolean();
        final var activity = new ExpandAssessmentChangesActivity(1, 1, () -> entered.set(true));
        Thread.currentThread().interrupt();
        try {
            assertThatThrownBy(() -> activity.execute(
                            CONTEXT,
                            ExpandAssessmentChangesArg.newBuilder()
                                    .setOutboxId(1)
                                    .build()))
                    .isInstanceOf(InterruptedException.class)
                    .hasMessage("Interrupted before assessment expansion");
        } finally {
            Thread.interrupted();
        }
        assertThat(entered).isFalse();
    }

    @Test
    void missingArgumentIsTerminalWithoutOpeningADatabaseConnection() {
        assertThatThrownBy(() -> new ExpandAssessmentChangesActivity(1, 1).execute(CONTEXT, null))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("argument must not be null");
    }

    @ParameterizedTest
    @ValueSource(longs = {0, -1})
    void nonPositiveOutboxIdsAreRejectedByTheActivityAndInstanceKey(final long id) {
        assertThatThrownBy(() -> new ExpandAssessmentChangesActivity(1, 1)
                        .execute(
                                CONTEXT,
                                ExpandAssessmentChangesArg.newBuilder()
                                        .setOutboxId(id)
                                        .build()))
                .isInstanceOf(TerminalApplicationFailureException.class)
                .hasMessage("outbox_id must be positive");
        assertThatThrownBy(() -> ExpandAssessmentChangesWorkflow.instanceId(id))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("outboxId must be positive");
    }

    @Test
    void stableInstanceKeySupportsPositiveBigintIds() {
        assertThat(ExpandAssessmentChangesWorkflow.instanceId(Long.MAX_VALUE))
                .isEqualTo("assessment-expand:9223372036854775807");
    }
}
