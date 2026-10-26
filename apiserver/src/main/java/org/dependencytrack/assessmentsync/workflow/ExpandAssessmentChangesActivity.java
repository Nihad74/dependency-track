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

import org.dependencytrack.assessmentsync.AssessmentChange.Scope;
import org.dependencytrack.assessmentsync.AssessmentSyncFanoutDao;
import org.dependencytrack.assessmentsync.AssessmentSyncFanoutDao.TargetFinding;
import org.dependencytrack.assessmentsync.AssessmentSyncOutboxDao;
import org.dependencytrack.assessmentsync.AssessmentSyncOutboxDao.OutboxEntry;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.dex.api.failure.TerminalApplicationFailureException;
import org.dependencytrack.model.FindingKey;
import org.dependencytrack.proto.internal.workflow.v1.ExpandAssessmentChangesArg;
import org.dependencytrack.proto.internal.workflow.v1.ExpandAssessmentChangesRes;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;

/// Schedules one page of target work and advances the outbox cursor in that same transaction.
@ActivitySpec(name = "expand-assessment-changes", defaultTaskQueue = ExpandAssessmentChangesActivity.QUEUE_NAME)
public final class ExpandAssessmentChangesActivity
        implements Activity<ExpandAssessmentChangesArg, ExpandAssessmentChangesRes> {

    public static final String QUEUE_NAME = "assessment-sync";

    private static final AtomicBoolean FAIL_TERMINAL = new AtomicBoolean();

    private final int fanoutBatchSize;
    private final int reconcileBatchSize;

    public ExpandAssessmentChangesActivity(final int fanoutBatchSize, final int reconcileBatchSize) {
        if (fanoutBatchSize <= 0) {
            throw new IllegalArgumentException("fanoutBatchSize must be positive");
        }
        if (reconcileBatchSize <= 0) {
            throw new IllegalArgumentException("reconcileBatchSize must be positive");
        }
        this.fanoutBatchSize = fanoutBatchSize;
        this.reconcileBatchSize = reconcileBatchSize;
    }

    /// Test hook. Production leaves this false.
    public static void failTerminalForTest(final boolean fail) {
        FAIL_TERMINAL.set(fail);
    }

    @Override
    public ExpandAssessmentChangesRes execute(
            final ActivityContext ctx, final @Nullable ExpandAssessmentChangesArg argument)
            throws InterruptedException {
        if (Thread.interrupted()) {
            throw new InterruptedException("Interrupted before assessment expansion");
        }
        if (FAIL_TERMINAL.get()) {
            throw new TerminalApplicationFailureException("assessment expansion failed");
        }
        if (argument == null) {
            throw new TerminalApplicationFailureException("outbox_id must be positive");
        }
        ExpandAssessmentChangesWorkflow.requireArgument(argument);
        return inJdbiTransaction(handle -> expand(handle, argument));
    }

    private ExpandAssessmentChangesRes expand(final Handle handle, final ExpandAssessmentChangesArg argument) {
        final var outboxDao = new AssessmentSyncOutboxDao(handle);
        final OutboxEntry entry = outboxDao.lock(argument.getOutboxId());
        if (entry == null) {
            return ExpandAssessmentChangesRes.newBuilder()
                    .setHasMore(false)
                    .setTargetsRequested(0)
                    .setAlreadyCompleted(true)
                    .build();
        }
        if (entry.schemaVersion() != argument.getSchemaVersion()) {
            throw new TerminalApplicationFailureException("unsupported schema_version");
        }

        final var fanoutDao = new AssessmentSyncFanoutDao(handle);
        final int fetchLimit = fanoutBatchSize + 1;
        final List<UUID> fetched =
                switch (entry.change().scope()) {
                    case PROJECT -> fanoutDao.pageProjectTargets(entry.id(), fetchLimit);
                    case FINDING -> fanoutDao.pageFindingTargets(entry.id(), fetchLimit);
                };
        final boolean hasMore = fetched.size() > fanoutBatchSize;
        final List<UUID> page = hasMore ? fetched.subList(0, fanoutBatchSize) : fetched;
        final int targetsRequested = schedule(handle, fanoutDao, entry, page);
        if (hasMore) {
            outboxDao.updateFanoutCursor(entry.id(), page.getLast());
        } else {
            outboxDao.deleteFinished(entry.id());
        }
        return ExpandAssessmentChangesRes.newBuilder()
                .setHasMore(hasMore)
                .setTargetsRequested(targetsRequested)
                .setAlreadyCompleted(false)
                .build();
    }

    private int schedule(
            final Handle handle,
            final AssessmentSyncFanoutDao fanoutDao,
            final OutboxEntry entry,
            final List<UUID> page) {
        if (page.isEmpty()) {
            return 0;
        }
        final var workDao = new AssessmentSyncWorkDao(handle);
        if (entry.change().scope() == Scope.PROJECT) {
            for (final UUID targetUuid : page) {
                workDao.requestFull(targetUuid);
            }
            return page.size();
        }

        final var keysByTarget = new LinkedHashMap<UUID, List<FindingKey>>();
        for (final UUID targetUuid : page) {
            keysByTarget.put(targetUuid, new ArrayList<>());
        }
        for (final TargetFinding finding : fanoutDao.findingKeys(entry.id(), page, reconcileBatchSize + 1)) {
            final List<FindingKey> keys = keysByTarget.get(finding.targetUuid());
            if (keys != null) {
                keys.add(new FindingKey(finding.componentId(), finding.vulnerabilityId()));
            }
        }
        var requested = 0;
        for (final var target : keysByTarget.entrySet()) {
            final List<FindingKey> keys = target.getValue();
            if (keys.isEmpty()) {
                continue;
            }
            if (keys.size() > reconcileBatchSize) {
                workDao.requestFull(target.getKey());
            } else {
                workDao.requestFindings(target.getKey(), keys);
            }
            requested++;
        }
        return requested;
    }
}
