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
import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.ContinueAsNewOptions;
import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.proto.internal.workflow.v1.ExpandAssessmentChangesArg;
import org.dependencytrack.proto.internal.workflow.v1.ExpandAssessmentChangesRes;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jspecify.annotations.Nullable;

import java.time.Duration;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.dex.api.payload.PayloadConverters.stringConverter;

/// Expands one outbox row into target work. The activity owns the cursor.
@WorkflowSpec(name = ExpandAssessmentChangesWorkflow.NAME)
public final class ExpandAssessmentChangesWorkflow implements Workflow<ExpandAssessmentChangesArg, Void> {

    public static final String NAME = "expand-assessment-changes";

    private static final RetryPolicy EXPAND_RETRY_POLICY =
            new RetryPolicy(Duration.ofSeconds(1), 2.0, 0.2, Duration.ofSeconds(10), 3);

    /// Instance id and concurrency key for one outbox row.
    public static String instanceId(final long outboxId) {
        if (outboxId <= 0) {
            throw new IllegalArgumentException("outboxId must be positive");
        }
        return "assessment-expand:" + outboxId;
    }

    @Override
    public @Nullable Void execute(
            final WorkflowContext<ExpandAssessmentChangesArg> ctx, final @Nullable ExpandAssessmentChangesArg arg) {
        requireArgument(arg);
        final int maxBatches = Integer.parseInt(requireNonNull(
                ctx.executeSideEffect(
                                "max-batches",
                                stringConverter(),
                                () -> Integer.toString(AssessmentSyncSettings.positiveInt(
                                        ConfigProvider.getConfig(), ConfigKeys.ASSESSMENT_SYNC_WORKFLOW_MAX_BATCHES)))
                        .await(),
                "max-batches"));

        var completedBatches = 0;
        while (true) {
            if (completedBatches >= maxBatches) {
                ctx.continueAsNew(new ContinueAsNewOptions<ExpandAssessmentChangesArg>().withArgument(arg));
                return null;
            }
            final ExpandAssessmentChangesRes result = ctx.activity(ExpandAssessmentChangesActivity.class)
                    .call(new ActivityCallOptions<ExpandAssessmentChangesArg>()
                            .withRetryPolicy(EXPAND_RETRY_POLICY)
                            .withArgument(arg))
                    .await();
            if (result == null) {
                throw new TerminalApplicationFailureException("Expansion activity returned no result");
            }
            completedBatches++;
            ctx.logger()
                    .debug(
                            "Expanded {} targets, hasMore={}, alreadyCompleted={}",
                            result.getTargetsRequested(),
                            result.getHasMore(),
                            result.getAlreadyCompleted());
            if (result.getAlreadyCompleted() || !result.getHasMore()) {
                return null;
            }
        }
    }

    static void requireArgument(final @Nullable ExpandAssessmentChangesArg arg) {
        if (arg == null || arg.getOutboxId() <= 0) {
            throw new TerminalApplicationFailureException("outbox_id must be positive");
        }
        if (arg.getSchemaVersion() != AssessmentSyncSettings.SUPPORTED_SCHEMA_VERSION) {
            throw new TerminalApplicationFailureException("unsupported schema_version");
        }
    }
}
