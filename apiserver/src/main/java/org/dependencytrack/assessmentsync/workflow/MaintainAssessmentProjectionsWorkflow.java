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
import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.ContinueAsNewOptions;
import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.dex.engine.api.request.CreateWorkflowRunRequest;
import org.dependencytrack.proto.internal.workflow.v1.AssessmentMaintenanceOperation;
import org.dependencytrack.proto.internal.workflow.v1.MaintainAssessmentProjectionsArg;
import org.dependencytrack.proto.internal.workflow.v1.MaintainAssessmentProjectionsRes;
import org.jspecify.annotations.Nullable;

import java.time.Duration;

import static java.util.Objects.requireNonNull;

/**
 * Scans projects by UUID. The continue-as-new argument is the only scan cursor.
 */
@WorkflowSpec(name = MaintainAssessmentProjectionsWorkflow.NAME)
public final class MaintainAssessmentProjectionsWorkflow implements Workflow<MaintainAssessmentProjectionsArg, Void> {

    public static final String NAME = "maintain-assessment-projections";

    private static final RetryPolicy MAINTAIN_RETRY_POLICY =
            new RetryPolicy(Duration.ofSeconds(1), 2.0, 0.2, Duration.ofSeconds(10), 3);

    /**
     * Instance id and concurrency key for one maintenance operation.
     */
    public static String instanceId(final AssessmentMaintenanceOperation operation) {
        return "assessment-maintenance:" + MaintenanceOperations.name(operation);
    }

    /**
     * Daily run selected from the current mode. {@code OFF} starts nothing.
     */
    public static @Nullable CreateWorkflowRunRequest<MaintainAssessmentProjectionsArg> scheduledRun() {
        final AssessmentMaintenanceOperation operation =
                MaintenanceOperations.scheduledFor(AssessmentSyncMode.current());
        if (operation == null) {
            return null;
        }
        final String instanceId = instanceId(operation);
        return new CreateWorkflowRunRequest<>(MaintainAssessmentProjectionsWorkflow.class)
                .withWorkflowInstanceId(instanceId)
                .withConcurrencyKey(instanceId)
                .withArgument(MaintainAssessmentProjectionsArg.newBuilder()
                        .setOperation(operation)
                        .build());
    }

    @Override
    public @Nullable Void execute(
            final WorkflowContext<MaintainAssessmentProjectionsArg> ctx,
            final @Nullable MaintainAssessmentProjectionsArg argument) {
        MaintenanceOperations.require(argument);
        final MaintainAssessmentProjectionsArg initial = requireNonNull(argument);
        final int maxBatches = AssessmentSyncArguments.maxBatches(ctx);

        var current = initial;
        var completedBatches = 0;
        while (true) {
            final MaintainAssessmentProjectionsRes result = ctx.activity(MaintainAssessmentProjectionsActivity.class)
                    .call(new ActivityCallOptions<MaintainAssessmentProjectionsArg>()
                            .withRetryPolicy(MAINTAIN_RETRY_POLICY)
                            .withArgument(current))
                    .await();
            if (result == null) {
                throw new TerminalApplicationFailureException("Maintenance activity returned no result");
            }
            completedBatches++;
            if (ctx.logger().isInfoEnabled()) {
                ctx.logger()
                        .info(
                                "Assessment sync maintenance operation={} scanned={} drift={} enqueued={} hasMore={}",
                                initial.getOperation(),
                                result.getScanned(),
                                result.getDrift(),
                                result.getEnqueued(),
                                result.getHasMore());
            }
            if (!result.getHasMore()) {
                return null;
            }
            if (result.getProjectUuidCursor().isBlank()) {
                throw new TerminalApplicationFailureException("project_uuid_cursor is required when has_more is set");
            }
            current = current.toBuilder()
                    .setProjectUuidCursor(result.getProjectUuidCursor())
                    .build();
            if (completedBatches >= maxBatches) {
                ctx.continueAsNew(new ContinueAsNewOptions<MaintainAssessmentProjectionsArg>().withArgument(current));
                return null;
            }
        }
    }
}
