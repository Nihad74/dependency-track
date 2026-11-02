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
package org.dependencytrack.assessmentsync;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao.Pass;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao.PendingFinding;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao.WorkRow;
import org.dependencytrack.model.FindingKey;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static java.util.Objects.requireNonNull;
import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class AssessmentSyncWorkDaoTest extends PersistenceCapableTest {

    @Test
    void shouldAllocateDistinctRevisionsAcrossOverlappingTransactions() throws Exception {
        final UUID targetUuid = UUID.fromString("40000000-0000-4000-8000-000000000001");
        final Handle first = openJdbiHandle();
        final Handle second = openJdbiHandle();
        final ExecutorService executor = Executors.newSingleThreadExecutor();
        final var entered = new CountDownLatch(1);
        try {
            first.begin();
            final long firstRevision = new AssessmentSyncWorkDao(first).requestFull(targetUuid);
            final Future<Long> secondRevision = executor.submit(() -> {
                second.begin();
                entered.countDown();
                try {
                    return new AssessmentSyncWorkDao(second)
                            .requestFindings(targetUuid, List.of(new FindingKey(11, 22)));
                } finally {
                    second.commit();
                }
            });

            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            TimeUnit.MILLISECONDS.sleep(300);
            assertThat(secondRevision.isDone()).isFalse();
            first.commit();

            assertThat(firstRevision).isEqualTo(1);
            assertThat(secondRevision.get(10, TimeUnit.SECONDS)).isEqualTo(2);
        } finally {
            if (first.isInTransaction()) {
                first.rollback();
            }
            executor.shutdown();
            assertThat(executor.awaitTermination(15, TimeUnit.SECONDS)).isTrue();
            if (second.isInTransaction()) {
                second.rollback();
            }
            first.close();
            second.close();
        }
    }

    @Test
    void shouldKeepPendingSinceUntilReconciliationAndRefreshBothCatchUp() {
        final UUID targetUuid = UUID.fromString("40000000-0000-4000-8000-000000000009");
        useJdbiTransaction(handle -> new AssessmentSyncWorkDao(handle).requestFull(targetUuid));
        final OffsetDateTime firstPending = pendingSince(targetUuid);
        assertThat(firstPending).isNotNull();

        useJdbiTransaction(handle -> {
            final var dao = new AssessmentSyncWorkDao(handle);
            dao.requestFindings(targetUuid, List.of(new FindingKey(11, 22)));
            final Pass pass = requireNonNull(dao.beginOrResumePass(targetUuid));
            dao.requestRefresh(targetUuid);
            assertThat(dao.completePass(targetUuid, pass.activeRevision())).isTrue();
        });
        assertThat(pendingSince(targetUuid))
                .as("reconciliation caught up, but the open refresh keeps the original start")
                .isEqualTo(firstPending);

        useJdbiTransaction(handle -> new AssessmentSyncWorkDao(handle).acknowledgeRefresh(targetUuid, 1));
        assertThat(pendingSince(targetUuid)).isNull();

        useJdbiTransaction(handle -> new AssessmentSyncWorkDao(handle).requestRefresh(targetUuid));
        assertThat(pendingSince(targetUuid)).isNotNull().isAfterOrEqualTo(firstPending);
    }

    @Test
    void finishingWithWorkStillPendingMakesTheTargetDueAgain() {
        final UUID targetUuid = UUID.fromString("40000000-0000-4000-8000-00000000000a");
        final Instant later = Instant.now().plus(Duration.ofHours(1));
        useJdbiTransaction(handle -> {
            final var dao = new AssessmentSyncWorkDao(handle);
            dao.requestFull(targetUuid);
            final Pass pass = requireNonNull(dao.beginOrResumePass(targetUuid));
            dao.requestFull(targetUuid);
            dao.requestRefresh(targetUuid);
            dao.recordDispatchAttempt(targetUuid, later);
            assertThat(dao.completePass(targetUuid, pass.activeRevision())).isTrue();
        });
        assertThat(nextDispatchAt(targetUuid)).isBeforeOrEqualTo(Instant.now());

        useJdbiTransaction(handle -> {
            final var dao = new AssessmentSyncWorkDao(handle);
            dao.recordDispatchAttempt(targetUuid, later);
            dao.acknowledgeRefresh(targetUuid, 0);
        });
        assertThat(nextDispatchAt(targetUuid)).isBeforeOrEqualTo(Instant.now());
    }

    private static Instant nextDispatchAt(final UUID targetUuid) {
        return requireNonNull(withJdbiHandle(handle -> new AssessmentSyncWorkDao(handle).find(targetUuid)))
                .nextDispatchAt();
    }

    @Test
    void shouldRequestManyTargetsInOneCallAtEachTargetsOwnRevision() {
        final UUID busy = UUID.fromString("40000000-0000-4000-8000-00000000000b");
        final UUID idle = UUID.fromString("40000000-0000-4000-8000-00000000000c");
        final UUID fresh = UUID.fromString("40000000-0000-4000-8000-00000000000d");
        useJdbiTransaction(handle -> {
            final var dao = new AssessmentSyncWorkDao(handle);
            dao.requestFull(busy);
            dao.requestFull(busy);
        });

        useJdbiTransaction(handle -> {
            final var dao = new AssessmentSyncWorkDao(handle);
            dao.requestFindings(Map.of(
                    busy, List.of(new FindingKey(1, 2)),
                    idle, List.of(new FindingKey(3, 4), new FindingKey(5, 6))));
            dao.requestFull(List.of(fresh, busy));
        });

        final List<PendingFinding> busyFindings =
                withJdbiHandle(handle -> new AssessmentSyncWorkDao(handle).pendingFindings(busy));
        assertThat(busyFindings).containsExactly(new PendingFinding(1, 2, 3));
        final List<PendingFinding> idleFindings =
                withJdbiHandle(handle -> new AssessmentSyncWorkDao(handle).pendingFindings(idle));
        assertThat(idleFindings).containsExactly(new PendingFinding(3, 4, 1), new PendingFinding(5, 6, 1));
        final WorkRow busyRow = requireNonNull(withJdbiHandle(handle -> new AssessmentSyncWorkDao(handle).find(busy)));
        assertThat(busyRow.requestedRevision()).isEqualTo(4);
        assertThat(busyRow.fullRevision()).isEqualTo(4);
        final WorkRow freshRow =
                requireNonNull(withJdbiHandle(handle -> new AssessmentSyncWorkDao(handle).find(fresh)));
        assertThat(freshRow.requestedRevision()).isEqualTo(1);
        assertThat(freshRow.fullRevision()).isEqualTo(1);
    }

    private static @Nullable OffsetDateTime pendingSince(final UUID targetUuid) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "PENDING_SINCE"
                          FROM "ASSESSMENT_SYNC_WORK"
                         WHERE "TARGET_UUID" = :targetUuid
                        """)
                .bind("targetUuid", targetUuid)
                .mapTo(OffsetDateTime.class)
                .one());
    }

    @Test
    void shouldDeleteOlderFindingsWhenFullPassCompletes() {
        final UUID targetUuid = UUID.fromString("40000000-0000-4000-8000-000000000002");
        useJdbiTransaction(handle -> {
            final var dao = new AssessmentSyncWorkDao(handle);
            assertThat(dao.requestFindings(targetUuid, List.of(new FindingKey(11, 22))))
                    .isEqualTo(1);
            assertThat(dao.requestFull(targetUuid)).isEqualTo(2);
            assertThat(dao.pendingFindings(targetUuid)).containsExactly(new PendingFinding(11, 22, 1));

            final Pass pass = dao.beginOrResumePass(targetUuid);
            assertThat(pass).isNotNull();
            assertThat(pass.activeRevision()).isEqualTo(2);
            assertThat(pass.full()).isTrue();
            assertThat(pass.resumed()).isFalse();
            assertThat(dao.completePass(targetUuid, 2)).isTrue();

            assertThat(dao.pendingFindings(targetUuid)).isEmpty();
            final WorkRow work = dao.find(targetUuid);
            assertThat(work.requestedRevision()).isEqualTo(2);
            assertThat(work.completedRevision()).isEqualTo(2);
            assertThat(work.fullRevision()).isEqualTo(2);
            assertThat(work.activeRevision()).isNull();
        });
    }

    @Test
    void shouldKeepFindingRevisionNewerThanAcknowledgedPass() {
        final UUID targetUuid = UUID.fromString("40000000-0000-4000-8000-000000000003");
        useJdbiTransaction(handle -> {
            final var dao = new AssessmentSyncWorkDao(handle);
            assertThat(dao.requestFindings(targetUuid, List.of(new FindingKey(11, 22))))
                    .isEqualTo(1);
            final Pass pass = dao.beginOrResumePass(targetUuid);
            assertThat(pass.activeRevision()).isEqualTo(1);
            assertThat(pass.full()).isFalse();

            assertThat(dao.requestFindings(targetUuid, List.of(new FindingKey(11, 22))))
                    .isEqualTo(2);
            assertThat(dao.completePass(targetUuid, 1)).isTrue();

            assertThat(dao.pendingFindings(targetUuid)).containsExactly(new PendingFinding(11, 22, 2));
            final WorkRow work = dao.find(targetUuid);
            assertThat(work.completedRevision()).isEqualTo(1);
            assertThat(work.requestedRevision()).isEqualTo(2);
            assertThat(dao.pollDue(10, true)).extracting(WorkRow::targetUuid).containsExactly(targetUuid);
        });
    }

    @Test
    void shouldLeaveWorkRequestedAfterAcknowledgementPending() {
        final UUID targetUuid = UUID.fromString("40000000-0000-4000-8000-000000000004");
        useJdbiTransaction(handle -> {
            final var dao = new AssessmentSyncWorkDao(handle);
            assertThat(dao.requestFull(targetUuid)).isEqualTo(1);
            assertThat(dao.beginOrResumePass(targetUuid).activeRevision()).isEqualTo(1);
            assertThat(dao.completePass(targetUuid, 1)).isTrue();
            assertThat(dao.pollDue(10, true)).isEmpty();

            assertThat(dao.requestFull(targetUuid)).isEqualTo(2);
            final WorkRow work = dao.find(targetUuid);
            assertThat(work.completedRevision()).isEqualTo(1);
            assertThat(work.requestedRevision()).isEqualTo(2);
            assertThat(work.fullRevision()).isEqualTo(2);
            assertThat(work.activeRevision()).isNull();
            assertThat(dao.pollDue(10, true)).extracting(WorkRow::targetUuid).containsExactly(targetUuid);

            final Pass next = dao.beginOrResumePass(targetUuid);
            assertThat(next.activeRevision()).isEqualTo(2);
            assertThat(next.full()).isTrue();
            assertThat(next.resumed()).isFalse();
        });
    }

    @Test
    void shouldResumeCursorAndAcknowledgeRefreshOnlyUpToCapturedValue() {
        final UUID targetUuid = UUID.fromString("40000000-0000-4000-8000-000000000005");
        useJdbiTransaction(handle -> {
            final var dao = new AssessmentSyncWorkDao(handle);
            assertThat(dao.requestFull(targetUuid)).isEqualTo(1);
            final Pass started = dao.beginOrResumePass(targetUuid);
            assertThat(started.cursor()).isNull();
            assertThat(dao.advancePass(targetUuid, 1, new FindingKey(40, 50))).isTrue();
            assertThat(dao.advancePass(targetUuid, 99, new FindingKey(1, 2))).isFalse();

            final Pass resumed = dao.beginOrResumePass(targetUuid);
            assertThat(resumed.resumed()).isTrue();
            assertThat(resumed.activeRevision()).isEqualTo(1);
            assertThat(resumed.cursor()).isEqualTo(new FindingKey(40, 50));

            assertThat(dao.requestRefresh(targetUuid)).isEqualTo(1);
            assertThat(dao.requestRefresh(targetUuid)).isEqualTo(2);
            assertThat(dao.acknowledgeRefresh(targetUuid, 1)).isEqualTo(1);
            assertThat(dao.find(targetUuid).refreshRequested()).isEqualTo(2);
            assertThat(dao.find(targetUuid).refreshCompleted()).isEqualTo(1);
            assertThat(dao.acknowledgeRefresh(targetUuid, 2)).isEqualTo(2);
            assertThat(dao.acknowledgeRefresh(targetUuid, 1)).isEqualTo(2);
        });
    }
}
