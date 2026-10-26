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
import org.dependencytrack.assessmentsync.AssessmentSyncSettings;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.ContinueAsNewOptions;
import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowCallOptions;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.proto.internal.workflow.v1.AssessmentSyncPendingRes;
import org.dependencytrack.proto.internal.workflow.v1.ReconcileProjectAssessmentsRes;
import org.dependencytrack.proto.internal.workflow.v1.RefreshSynchronizedAssessmentsArg;
import org.dependencytrack.proto.internal.workflow.v1.SynchronizeProjectAssessmentsArg;
import org.eclipse.microprofile.config.ConfigProvider;
import org.jspecify.annotations.Nullable;

import java.time.Duration;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.dex.api.payload.PayloadConverters.stringConverter;

/// Reconciles one target project. Each activity call is its own transaction.
@WorkflowSpec(name = SynchronizeProjectAssessmentsWorkflow.NAME)
public final class SynchronizeProjectAssessmentsWorkflow implements Workflow<SynchronizeProjectAssessmentsArg, Void> {

    public static final String NAME = "synchronize-project-assessments";

    private static final RetryPolicy RECONCILE_RETRY_POLICY =
            new RetryPolicy(Duration.ofSeconds(1), 2.0, 0.2, Duration.ofSeconds(10), 3);

    /// Instance id and concurrency key for one target project.
    public static String instanceId(final UUID targetUuid) {
        if (targetUuid == null) {
            throw new IllegalArgumentException("targetUuid must not be null");
        }
        return "assessment-sync:" + targetUuid;
    }

    @Override
    public @Nullable Void execute(
            final WorkflowContext<SynchronizeProjectAssessmentsArg> ctx,
            final @Nullable SynchronizeProjectAssessmentsArg arg) {
        if (arg == null || arg.getProjectUuid().isBlank()) {
            throw new TerminalApplicationFailureException("project_uuid must be a UUID");
        }
        final UUID projectUuid;
        try {
            projectUuid = UUID.fromString(arg.getProjectUuid());
        } catch (IllegalArgumentException e) {
            throw new TerminalApplicationFailureException("project_uuid must be a UUID", e);
        }
        final int maxBatches = Integer.parseInt(requireNonNull(
                ctx.executeSideEffect(
                                "max-batches",
                                stringConverter(),
                                () -> Integer.toString(AssessmentSyncSettings.positiveInt(
                                        ConfigProvider.getConfig(), ConfigKeys.ASSESSMENT_SYNC_WORKFLOW_MAX_BATCHES)))
                        .await(),
                "max-batches"));

        var completedBatches = 0;
        var highestRefresh = 0L;
        while (completedBatches < maxBatches) {
            final ReconcileProjectAssessmentsRes result = ctx.activity(ReconcileProjectAssessmentsActivity.class)
                    .call(new ActivityCallOptions<SynchronizeProjectAssessmentsArg>()
                            .withRetryPolicy(RECONCILE_RETRY_POLICY)
                            .withArgument(arg))
                    .await();
            if (result == null) {
                throw new TerminalApplicationFailureException("Reconciliation activity returned no result");
            }
            completedBatches++;
            ctx.logger()
                    .debug(
                            "Reconciled {} applied={}, withdrawn={}, skipped={}, hasMore={}, refreshRevision={}, targetDeleted={}",
                            projectUuid,
                            result.getApplied(),
                            result.getWithdrawn(),
                            result.getSkipped(),
                            result.getHasMore(),
                            result.getRefreshRevision(),
                            result.getTargetDeleted());
            if (result.getRefreshRevision() > highestRefresh) {
                highestRefresh = result.getRefreshRevision();
            }
            if (result.getTargetDeleted()) {
                return null;
            }
            if (!result.getHasMore()) {
                break;
            }
        }

        if (highestRefresh > 0) {
            awaitRefresh(ctx, projectUuid, highestRefresh);
        }

        var pending = readPending(ctx, arg);
        if (pending.getTargetDeleted()) {
            return null;
        }
        if (pending.getReconciliationPending()) {
            ctx.continueAsNew(new ContinueAsNewOptions<SynchronizeProjectAssessmentsArg>().withArgument(arg));
            return null;
        }
        if (pending.getRefreshPending() && pending.getRefreshRequested() > highestRefresh) {
            awaitRefresh(ctx, projectUuid, pending.getRefreshRequested());
            pending = readPending(ctx, arg);
            if (pending.getTargetDeleted()) {
                return null;
            }
            if (pending.getReconciliationPending() || pending.getRefreshPending()) {
                ctx.continueAsNew(new ContinueAsNewOptions<SynchronizeProjectAssessmentsArg>().withArgument(arg));
            }
            return null;
        }
        if (pending.getRefreshPending()) {
            ctx.continueAsNew(new ContinueAsNewOptions<SynchronizeProjectAssessmentsArg>().withArgument(arg));
        }
        return null;
    }

    /// The child uses the project analysis key, never this workflow's assessment-sync key.
    private static void awaitRefresh(
            final WorkflowContext<SynchronizeProjectAssessmentsArg> ctx,
            final UUID projectUuid,
            final long refreshRevision) {
        final var argument = RefreshSynchronizedAssessmentsArg.newBuilder()
                .setProjectUuid(projectUuid.toString())
                .setRefreshRevision(refreshRevision)
                .build();
        ctx.workflow(RefreshSynchronizedAssessmentsWorkflow.class)
                .call(new WorkflowCallOptions<RefreshSynchronizedAssessmentsArg>()
                        .withWorkflowInstanceId(
                                RefreshSynchronizedAssessmentsWorkflow.instanceId(projectUuid, refreshRevision))
                        .withConcurrencyKey(AnalyzeProjectWorkflow.concurrencyKeyForProject(projectUuid))
                        .withArgument(argument))
                .await();
    }

    private static AssessmentSyncPendingRes readPending(
            final WorkflowContext<SynchronizeProjectAssessmentsArg> ctx, final SynchronizeProjectAssessmentsArg arg) {
        final AssessmentSyncPendingRes pending = ctx.activity(ReadAssessmentSyncPendingActivity.class)
                .call(new ActivityCallOptions<SynchronizeProjectAssessmentsArg>()
                        .withRetryPolicy(RECONCILE_RETRY_POLICY)
                        .withArgument(arg))
                .await();
        if (pending == null) {
            throw new TerminalApplicationFailureException("Pending-work activity returned no result");
        }
        return pending;
    }
}
