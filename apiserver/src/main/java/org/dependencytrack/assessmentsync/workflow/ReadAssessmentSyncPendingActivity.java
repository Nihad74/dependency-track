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
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao.WorkRow;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.proto.internal.workflow.v1.AssessmentSyncPendingRes;
import org.dependencytrack.proto.internal.workflow.v1.SynchronizeProjectAssessmentsArg;
import org.jspecify.annotations.Nullable;

import java.util.UUID;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;

/// Reads the work row. Does not reconcile findings or acknowledge refresh.
@ActivitySpec(name = "read-assessment-sync-pending", defaultTaskQueue = ReadAssessmentSyncPendingActivity.QUEUE_NAME)
public final class ReadAssessmentSyncPendingActivity
        implements Activity<SynchronizeProjectAssessmentsArg, AssessmentSyncPendingRes> {

    public static final String QUEUE_NAME = ExpandAssessmentChangesActivity.QUEUE_NAME;

    @Override
    public AssessmentSyncPendingRes execute(
            final ActivityContext ctx, final @Nullable SynchronizeProjectAssessmentsArg argument) {
        final UUID targetUuid = requireTarget(argument);
        return inJdbiTransaction(handle -> {
            final boolean projectExists = handle.createQuery(/* language=SQL */ """
                            SELECT 1
                              FROM "PROJECT"
                             WHERE "UUID" = :targetUuid
                            """)
                    .bind("targetUuid", targetUuid)
                    .mapTo(int.class)
                    .findOne()
                    .isPresent();
            if (!projectExists) {
                return AssessmentSyncPendingRes.newBuilder()
                        .setTargetDeleted(true)
                        .build();
            }
            final WorkRow row = new AssessmentSyncWorkDao(handle).find(targetUuid);
            if (row == null) {
                return AssessmentSyncPendingRes.getDefaultInstance();
            }
            return AssessmentSyncPendingRes.newBuilder()
                    .setReconciliationPending(row.completedRevision() < row.requestedRevision())
                    .setRefreshPending(row.refreshCompleted() < row.refreshRequested())
                    .setRefreshRequested(row.refreshRequested())
                    .setTargetDeleted(false)
                    .build();
        });
    }

    private static UUID requireTarget(final @Nullable SynchronizeProjectAssessmentsArg argument) {
        if (argument == null || argument.getProjectUuid().isBlank()) {
            throw new TerminalApplicationFailureException("project_uuid must be a UUID");
        }
        try {
            return UUID.fromString(argument.getProjectUuid());
        } catch (IllegalArgumentException e) {
            throw new TerminalApplicationFailureException("project_uuid must be a UUID", e);
        }
    }
}
