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

import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.proto.internal.workflow.v1.RefreshSynchronizedAssessmentsArg;
import org.jspecify.annotations.Nullable;

import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

/**
 * Acknowledges one captured refresh revision. Does not reconcile findings.
 */
@ActivitySpec(name = "complete-assessment-refresh", defaultTaskQueue = CompleteAssessmentRefreshActivity.QUEUE_NAME)
public final class CompleteAssessmentRefreshActivity implements Activity<RefreshSynchronizedAssessmentsArg, Void> {

    public static final String QUEUE_NAME = ExpandAssessmentChangesActivity.QUEUE_NAME;

    @Override
    public @Nullable Void execute(final ActivityContext ctx, final @Nullable RefreshSynchronizedAssessmentsArg argument)
            throws InterruptedException {
        if (Thread.interrupted()) {
            throw new InterruptedException("Interrupted before assessment refresh completion");
        }
        final RefreshSynchronizedAssessmentsArg arg = AssessmentSyncArguments.require(argument);
        final UUID targetUuid = AssessmentSyncArguments.projectUuid(arg.getProjectUuid());
        final long capturedRefresh = AssessmentSyncArguments.positive("refresh_revision", arg.getRefreshRevision());
        useJdbiTransaction(handle -> {
            final var workDao = new AssessmentSyncWorkDao(handle);
            // A deleted target's row may already be gone; that refresh has nothing left to acknowledge.
            if (handle.attach(ProjectDao.class).getProjectId(targetUuid) == null && workDao.find(targetUuid) == null) {
                return;
            }
            workDao.acknowledgeRefresh(targetUuid, capturedRefresh);
        });
        return null;
    }
}
