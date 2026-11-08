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
import org.dependencytrack.dex.api.ContinueAsNewOptions;
import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.proto.internal.workflow.v1.ExpandAssessmentChangesArg;
import org.dependencytrack.proto.internal.workflow.v1.ExpandAssessmentChangesRes;
import org.jspecify.annotations.Nullable;

import java.time.Duration;

/**
 * Expands one outbox row into target work. The activity owns the cursor.
 */
@WorkflowSpec(name = ExpandAssessmentChangesWorkflow.NAME)
public final class ExpandAssessmentChangesWorkflow implements Workflow<ExpandAssessmentChangesArg, Void> {

    public static final String NAME = "expand-assessment-changes";

    private static final RetryPolicy EXPAND_RETRY_POLICY =
            new RetryPolicy(Duration.ofSeconds(1), 2.0, 0.2, Duration.ofSeconds(10), 3);

    /**
     * Instance id and concurrency key for one outbox row.
     */
    public static String instanceId(final long outboxId) {
        if (outboxId <= 0) {
            throw new IllegalArgumentException("outboxId must be positive");
        }
        return "assessment-expand:" + outboxId;
    }

    @Override
    public @Nullable Void execute(
            final WorkflowContext<ExpandAssessmentChangesArg> ctx, final @Nullable ExpandAssessmentChangesArg arg) {
        final long outboxId = AssessmentSyncArguments.require(arg).getOutboxId();
        AssessmentSyncArguments.positive("outbox_id", outboxId);
        final int maxBatches = AssessmentSyncArguments.maxBatches(ctx);

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
            if (result.getTargetsRequested() > 0 && ctx.logger().isInfoEnabled()) {
                ctx.logger()
                        .info(
                                "Assessment sync targets requested outboxId={} targets={} hasMore={}",
                                outboxId,
                                result.getTargetsRequested(),
                                result.getHasMore());
            } else if (ctx.logger().isDebugEnabled()) {
                ctx.logger()
                        .debug(
                                "Assessment sync expansion outboxId={} targets={} hasMore={} alreadyCompleted={}",
                                outboxId,
                                result.getTargetsRequested(),
                                result.getHasMore(),
                                result.getAlreadyCompleted());
            }
            if (result.getAlreadyCompleted() || !result.getHasMore()) {
                return null;
            }
        }
    }
}
