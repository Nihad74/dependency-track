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
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.proto.internal.workflow.v1.RefreshSynchronizedAssessmentsArg;
import org.jspecify.annotations.Nullable;

import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

/// Acknowledges one captured refresh revision. Does not reconcile findings.
@ActivitySpec(name = "complete-assessment-refresh", defaultTaskQueue = CompleteAssessmentRefreshActivity.QUEUE_NAME)
public final class CompleteAssessmentRefreshActivity implements Activity<RefreshSynchronizedAssessmentsArg, Void> {

    public static final String QUEUE_NAME = ExpandAssessmentChangesActivity.QUEUE_NAME;

    @Override
    public @Nullable Void execute(
            final ActivityContext ctx, final @Nullable RefreshSynchronizedAssessmentsArg argument) {
        if (argument == null || argument.getProjectUuid().isBlank()) {
            throw new TerminalApplicationFailureException("project_uuid must be a UUID");
        }
        final UUID targetUuid;
        try {
            targetUuid = UUID.fromString(argument.getProjectUuid());
        } catch (IllegalArgumentException e) {
            throw new TerminalApplicationFailureException("project_uuid must be a UUID", e);
        }
        final long capturedRefresh = argument.getRefreshRevision();
        if (capturedRefresh <= 0) {
            throw new TerminalApplicationFailureException("refresh_revision must be positive");
        }
        useJdbiTransaction(handle -> {
            final boolean projectExists = handle.createQuery(/* language=SQL */ """
                            SELECT 1
                              FROM "PROJECT"
                             WHERE "UUID" = :targetUuid
                            """)
                    .bind("targetUuid", targetUuid)
                    .mapTo(int.class)
                    .findOne()
                    .isPresent();
            final var workDao = new AssessmentSyncWorkDao(handle);
            if (workDao.find(targetUuid) == null) {
                if (projectExists) {
                    throw new IllegalStateException("No assessment sync work for " + targetUuid);
                }
                return;
            }
            workDao.acknowledgeRefresh(targetUuid, capturedRefresh);
        });
        return null;
    }
}
