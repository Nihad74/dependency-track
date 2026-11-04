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
import org.dependencytrack.assessmentsync.AssessmentSyncOutboxDao;
import org.dependencytrack.assessmentsync.AssessmentSyncOutboxDao.OutboxEntry;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao;
import org.dependencytrack.dex.api.Activity;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.dex.api.ActivitySpec;
import org.dependencytrack.model.FindingKey;
import org.dependencytrack.proto.internal.workflow.v1.ExpandAssessmentChangesArg;
import org.dependencytrack.proto.internal.workflow.v1.ExpandAssessmentChangesRes;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;

/**
 * Schedules one page of target work and advances the outbox cursor in that same transaction.
 */
@ActivitySpec(name = "expand-assessment-changes", defaultTaskQueue = ExpandAssessmentChangesActivity.QUEUE_NAME)
public final class ExpandAssessmentChangesActivity
        implements Activity<ExpandAssessmentChangesArg, ExpandAssessmentChangesRes> {

    public static final String QUEUE_NAME = "assessment-sync";

    private final int fanoutBatchSize;
    private final int reconcileBatchSize;
    private final Runnable beforeExpand;

    public ExpandAssessmentChangesActivity(final int fanoutBatchSize, final int reconcileBatchSize) {
        this(fanoutBatchSize, reconcileBatchSize, () -> {});
    }

    /**
     * {@code beforeExpand} runs at the start of every call, so a test can make the activity fail.
     */
    public ExpandAssessmentChangesActivity(
            final int fanoutBatchSize, final int reconcileBatchSize, final Runnable beforeExpand) {
        if (fanoutBatchSize <= 0) {
            throw new IllegalArgumentException("fanoutBatchSize must be positive");
        }
        if (reconcileBatchSize <= 0) {
            throw new IllegalArgumentException("reconcileBatchSize must be positive");
        }
        this.fanoutBatchSize = fanoutBatchSize;
        this.reconcileBatchSize = reconcileBatchSize;
        this.beforeExpand = requireNonNull(beforeExpand, "beforeExpand must not be null");
    }

    @Override
    public ExpandAssessmentChangesRes execute(
            final ActivityContext ctx, final @Nullable ExpandAssessmentChangesArg argument)
            throws InterruptedException {
        if (Thread.interrupted()) {
            throw new InterruptedException("Interrupted before assessment expansion");
        }
        beforeExpand.run();
        final ExpandAssessmentChangesArg arg = AssessmentSyncArguments.require(argument);
        AssessmentSyncArguments.positive("outbox_id", arg.getOutboxId());
        return inJdbiTransaction(handle -> expand(handle, arg));
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

        final var fanoutDao = new AssessmentSyncFanoutDao(handle);
        final var workDao = new AssessmentSyncWorkDao(handle);
        final int fetchLimit = fanoutBatchSize + 1;
        final boolean hasMore;
        final UUID last;
        final int targetsRequested;
        if (entry.change().scope() == Scope.PROJECT) {
            final List<UUID> fetched = fanoutDao.pageProjectTargets(entry.id(), fetchLimit);
            hasMore = fetched.size() > fanoutBatchSize;
            final List<UUID> page = hasMore ? fetched.subList(0, fanoutBatchSize) : fetched;
            workDao.requestFull(page);
            last = page.isEmpty() ? null : page.getLast();
            targetsRequested = page.size();
        } else {
            final Map<UUID, List<FindingKey>> fetched =
                    fanoutDao.pageFindingTargets(entry.id(), fetchLimit, reconcileBatchSize + 1);
            hasMore = fetched.size() > fanoutBatchSize;
            final var full = new ArrayList<UUID>();
            final var findings = new LinkedHashMap<UUID, List<FindingKey>>();
            UUID lastOnPage = null;
            for (final var target : fetched.entrySet()) {
                if (full.size() + findings.size() == fanoutBatchSize) {
                    break;
                }
                // More keys than one reconcile batch: a full pass is cheaper than paging the keys.
                if (target.getValue().size() > reconcileBatchSize) {
                    full.add(target.getKey());
                } else {
                    findings.put(target.getKey(), target.getValue());
                }
                lastOnPage = target.getKey();
            }
            workDao.requestFull(full);
            workDao.requestFindings(findings);
            last = lastOnPage;
            targetsRequested = full.size() + findings.size();
        }
        if (hasMore) {
            outboxDao.updateFanoutCursor(entry.id(), requireNonNull(last));
        } else {
            outboxDao.deleteFinished(entry.id());
        }
        return ExpandAssessmentChangesRes.newBuilder()
                .setHasMore(hasMore)
                .setTargetsRequested(targetsRequested)
                .setAlreadyCompleted(false)
                .build();
    }
}
