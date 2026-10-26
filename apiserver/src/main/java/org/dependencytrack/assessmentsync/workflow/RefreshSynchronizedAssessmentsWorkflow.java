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

import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.metrics.UpdateProjectMetricsActivity;
import org.dependencytrack.policy.EvalProjectPoliciesActivity;
import org.dependencytrack.proto.internal.workflow.v1.EvalProjectPoliciesArg;
import org.dependencytrack.proto.internal.workflow.v1.RefreshSynchronizedAssessmentsArg;
import org.dependencytrack.proto.internal.workflow.v1.UpdateProjectMetricsArg;
import org.jspecify.annotations.Nullable;

import java.util.UUID;

/// Runs stored policy evaluation and project metrics for one captured refresh revision.
///
/// Does not run vulnerability analyzers. The caller supplies the instance id and concurrency key.
@WorkflowSpec(name = RefreshSynchronizedAssessmentsWorkflow.NAME)
public final class RefreshSynchronizedAssessmentsWorkflow implements Workflow<RefreshSynchronizedAssessmentsArg, Void> {

    public static final String NAME = "refresh-synchronized-assessments";

    /// Instance id for one captured refresh of one target.
    public static String instanceId(final UUID targetUuid, final long refreshRevision) {
        if (targetUuid == null) {
            throw new IllegalArgumentException("targetUuid must not be null");
        }
        if (refreshRevision <= 0) {
            throw new IllegalArgumentException("refreshRevision must be positive");
        }
        return "assessment-refresh:" + targetUuid + ":" + refreshRevision;
    }

    @Override
    public @Nullable Void execute(
            final WorkflowContext<RefreshSynchronizedAssessmentsArg> ctx,
            final @Nullable RefreshSynchronizedAssessmentsArg arg) {
        if (arg == null || arg.getProjectUuid().isBlank()) {
            throw new TerminalApplicationFailureException("project_uuid must be a UUID");
        }
        final UUID projectUuid;
        try {
            projectUuid = UUID.fromString(arg.getProjectUuid());
        } catch (IllegalArgumentException e) {
            throw new TerminalApplicationFailureException("project_uuid must be a UUID", e);
        }
        if (arg.getRefreshRevision() <= 0) {
            throw new TerminalApplicationFailureException("refresh_revision must be positive");
        }
        final String projectUuidText = projectUuid.toString();

        ctx.activity(EvalProjectPoliciesActivity.class)
                .call(EvalProjectPoliciesArg.newBuilder()
                        .setProjectUuid(projectUuidText)
                        .build())
                .await();

        ctx.activity(UpdateProjectMetricsActivity.class)
                .call(UpdateProjectMetricsArg.newBuilder()
                        .setProjectUuid(projectUuidText)
                        .build())
                .await();

        ctx.activity(CompleteAssessmentRefreshActivity.class).call(arg).await();
        return null;
    }
}
