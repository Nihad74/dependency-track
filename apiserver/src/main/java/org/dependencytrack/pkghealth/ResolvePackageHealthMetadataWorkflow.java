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
package org.dependencytrack.pkghealth;

import org.dependencytrack.dex.api.ActivityCallOptions;
import org.dependencytrack.dex.api.ContinueAsNewOptions;
import org.dependencytrack.dex.api.RetryPolicy;
import org.dependencytrack.dex.api.Workflow;
import org.dependencytrack.dex.api.WorkflowContext;
import org.dependencytrack.dex.api.WorkflowSpec;
import org.dependencytrack.dex.api.failure.ActivityFailureException;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageHealthMetadataCandidatesArg;
import org.dependencytrack.proto.internal.workflow.v1.FetchPackageHealthMetadataCandidatesRes;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataActivityArg;
import org.dependencytrack.proto.internal.workflow.v1.ResolvePackageHealthMetadataWorkflowArg;
import org.jspecify.annotations.Nullable;

import java.time.Duration;

@WorkflowSpec(name = "resolve-package-health-metadata")
public final class ResolvePackageHealthMetadataWorkflow
        implements Workflow<ResolvePackageHealthMetadataWorkflowArg, Void> {

    public static final String INSTANCE_ID = "resolve-package-health-metadata";

    private static final RetryPolicy RESOLVE_RETRY_POLICY = new RetryPolicy(
            /* initialDelay */ Duration.ofSeconds(5),
            /* delayMultiplier */ 2.0,
            /* randomizationFactor */ 0.3,
            /* maxDelay */ Duration.ofHours(2),
            /* maxAttempts */ 3);

    @Override
    public @Nullable Void execute(
            final WorkflowContext<@Nullable ResolvePackageHealthMetadataWorkflowArg> ctx,
            final @Nullable ResolvePackageHealthMetadataWorkflowArg arg)
            throws Exception {
        ctx.logger().debug("Scheduling fetch of package health metadata candidates");

        final FetchPackageHealthMetadataCandidatesRes fetchResult = ctx.activity(
                        FetchPackageHealthMetadataCandidatesActivity.class)
                .call(new ActivityCallOptions<FetchPackageHealthMetadataCandidatesArg>()
                        .withArgument(FetchPackageHealthMetadataCandidatesArg.newBuilder()
                                .setCursor(arg != null ? arg.getCursor() : "")
                                .build()))
                .await();

        if (fetchResult == null) {
            ctx.logger().info("No packages due for health metadata resolution");
            return null;
        }

        if (!fetchResult.getPurlsList().isEmpty()) {
            ctx.logger().debug("Resolving health metadata for {} packages", fetchResult.getPurlsCount());

            try {
                ctx.activity(ResolvePackageHealthMetadataActivity.class)
                        .call(new ActivityCallOptions<ResolvePackageHealthMetadataActivityArg>()
                                .withRetryPolicy(RESOLVE_RETRY_POLICY)
                                .withArgument(ResolvePackageHealthMetadataActivityArg.newBuilder()
                                        .addAllPurls(fetchResult.getPurlsList())
                                        .build()))
                        .await();

                ctx.logger().debug("Package health metadata resolution completed");
            } catch (ActivityFailureException e) {
                ctx.logger().warn("Package health metadata resolution failed", e);
            }
        }

        if (fetchResult.getHasMore()) {
            ctx.continueAsNew(new ContinueAsNewOptions<ResolvePackageHealthMetadataWorkflowArg>()
                    .withArgument(ResolvePackageHealthMetadataWorkflowArg.newBuilder()
                            .setCursor(fetchResult.getNextCursor())
                            .build()));
        } else {
            ctx.logger().info("No more packages due for health metadata resolution");
        }

        return null;
    }
}
