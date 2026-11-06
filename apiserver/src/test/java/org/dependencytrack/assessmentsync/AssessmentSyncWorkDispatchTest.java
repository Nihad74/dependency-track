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
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao.WorkRow;
import org.dependencytrack.model.FindingKey;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class AssessmentSyncWorkDispatchTest extends PersistenceCapableTest {

    @Test
    void advancingAnActivePassMakesRemainingWorkDueAndClearsBackoff() {
        final var target = UUID.randomUUID();
        useJdbiTransaction(h -> {
            final var dao = new AssessmentSyncWorkDao(h);
            dao.requestFull(target);
            final var pass = dao.beginOrResumePass(target);
            final var delayed = Instant.now().plusSeconds(3_600).truncatedTo(ChronoUnit.MILLIS);
            dao.recordDispatchAttempt(target, delayed);
            assertThat(dao.advancePass(target, pass.activeRevision() + 1, new FindingKey(1, 1)))
                    .isFalse();
            assertThat(dao.find(target).dispatchAttempts()).isEqualTo(1);
            assertThat(dao.find(target).nextDispatchAt()).isEqualTo(delayed);
            assertThat(dao.advancePass(target, pass.activeRevision(), new FindingKey(1, 2)))
                    .isTrue();
            final var row = dao.find(target);
            assertThat(row.dispatchAttempts()).isZero();
            assertThat(row.nextDispatchAt()).isBeforeOrEqualTo(Instant.now());
            assertThat(dao.pollDue(1, true))
                    .extracting(AssessmentSyncWorkDao.WorkRow::targetUuid)
                    .containsExactly(target);
        });
    }

    @Test
    void invalidDispatchBatchIsRejectedBeforeChangingAnyTarget() {
        final var target = UUID.randomUUID();
        useJdbiTransaction(h -> {
            final var dao = new AssessmentSyncWorkDao(h);
            dao.requestFull(target);
            final var invalid = new LinkedHashMap<UUID, Instant>();
            invalid.put(target, Instant.now().plusSeconds(60));
            invalid.put(null, Instant.now().plusSeconds(60));
            assertThatThrownBy(() -> dao.recordDispatchAttempts(invalid))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessage("targetUuid must not be null");
            assertThat(dao.find(target).dispatchAttempts()).isZero();
        });
    }

    @Test
    void pollingHonorsBothKindsOfPendingWorkModeAndFutureDeferrals() {
        final var reconciliation = uuid(1);
        final var refresh = uuid(2);
        final var both = uuid(3);
        final var finished = uuid(4);
        final var active = uuid(5);
        final var deferred = uuid(6);
        final var future = Instant.now().plusSeconds(3_600).truncatedTo(ChronoUnit.MILLIS);
        useJdbiTransaction(h -> {
            final var dao = new AssessmentSyncWorkDao(h);
            dao.requestFull(reconciliation);
            dao.requestRefresh(refresh);
            dao.requestFull(both);
            dao.requestRefresh(both);
            dao.requestFull(finished);
            dao.requestRefresh(finished);
            dao.acknowledgeCancellation(finished);
            dao.requestFull(active);
            final var pass = dao.beginOrResumePass(active);
            dao.advancePass(active, pass.activeRevision(), new FindingKey(10, 20));
            dao.requestFull(deferred);
            dao.requestRefresh(deferred);
            for (final var target : List.of(reconciliation, refresh, both, finished, active)) {
                dao.scheduleDispatch(target, Instant.parse("2000-01-01T00:00:00Z"));
            }
            dao.scheduleDispatch(deferred, future);
            final var before = dao.find(active);
            assertThat(dao.pollDue(10, true))
                    .extracting(WorkRow::targetUuid)
                    .containsExactly(reconciliation, refresh, both, active);
            assertThat(dao.pollDue(10, false)).extracting(WorkRow::targetUuid).containsExactly(refresh, both);
            assertThat(dao.find(active)).isEqualTo(before);
            assertThat(dao.find(active).cursor()).isEqualTo(new FindingKey(10, 20));
            assertThat(dao.find(finished).completedRevision()).isEqualTo(1);
            assertThat(dao.find(deferred).nextDispatchAt()).isEqualTo(future);
        });
    }

    @Test
    void pollingSkipsRowsLockedByAnotherConsumerAndRollbackReleasesThem() {
        useJdbiTransaction(h -> {
            final var dao = new AssessmentSyncWorkDao(h);
            dao.requestFull(List.of(uuid(1), uuid(2), uuid(3)));
            for (final var target : List.of(uuid(1), uuid(2), uuid(3))) {
                dao.scheduleDispatch(target, Instant.parse("2000-01-01T00:00:00Z"));
            }
        });
        try (final var holder = openJdbiHandle();
                final var other = openJdbiHandle()) {
            holder.begin();
            other.begin();
            try {
                other.execute("SET LOCAL lock_timeout = '1s'");
                assertThat(new AssessmentSyncWorkDao(holder).pollDue(1, true))
                        .extracting(WorkRow::targetUuid)
                        .containsExactly(uuid(1));
                assertThat(new AssessmentSyncWorkDao(other).pollDue(2, true))
                        .extracting(WorkRow::targetUuid)
                        .containsExactly(uuid(2), uuid(3));
            } finally {
                other.rollback();
                holder.rollback();
            }
        }
        useJdbiTransaction(h -> assertThat(new AssessmentSyncWorkDao(h).pollDue(3, true))
                .extracting(WorkRow::targetUuid)
                .containsExactly(uuid(1), uuid(2), uuid(3)));
    }

    @Test
    void pollingPrioritizesDueTimeThenUuidAndCountsOnlyClaimedRows() {
        final var first = uuid(1);
        final var second = uuid(2);
        final var earlier = uuid(3);
        final var due = Instant.parse("2000-01-01T00:00:00Z");
        final var later = Instant.now().plusSeconds(3_600).truncatedTo(ChronoUnit.MILLIS);
        useJdbiTransaction(h -> {
            final var dao = new AssessmentSyncWorkDao(h);
            dao.requestFull(List.of(first, second, earlier));
            dao.scheduleDispatch(first, due);
            dao.scheduleDispatch(second, due);
            dao.scheduleDispatch(earlier, due.minusSeconds(60));
            assertThat(dao.pollDue(2, true)).extracting(WorkRow::targetUuid).containsExactly(earlier, first);
            final var times = new LinkedHashMap<UUID, Instant>();
            times.put(earlier, later);
            times.put(first, later.plusSeconds(1));
            assertThat(dao.recordDispatchAttempts(times)).isEqualTo(2);
            assertThat(dao.pollDue(2, true)).extracting(WorkRow::targetUuid).containsExactly(second);
            assertThat(dao.find(earlier).dispatchAttempts()).isEqualTo(1);
            assertThat(dao.find(first).nextDispatchAt()).isEqualTo(later.plusSeconds(1));
            assertThat(dao.find(second).dispatchAttempts()).isZero();
        });
    }

    @Test
    void dispatchBatchCorrelatesTimesCountsMissingRowsAndPreservesWorkState() {
        final var first = uuid(1);
        final var second = uuid(2);
        final var missing = uuid(3);
        final var time = Instant.now().plusSeconds(60).truncatedTo(ChronoUnit.MILLIS);
        useJdbiTransaction(h -> {
            final var dao = new AssessmentSyncWorkDao(h);
            dao.requestFindings(first, List.of(new FindingKey(1, 2)));
            dao.requestFull(second);
            final var original = dao.find(first);
            final var times = new LinkedHashMap<UUID, Instant>();
            times.put(second, time.plusSeconds(1));
            times.put(missing, time);
            times.put(first, time);
            assertThat(dao.recordDispatchAttempts(times)).isEqualTo(2);
            assertThat(dao.recordDispatchAttempts(Map.of())).isZero();
            assertThat(dao.find(first).nextDispatchAt()).isEqualTo(time);
            assertThat(dao.find(second).nextDispatchAt()).isEqualTo(time.plusSeconds(1));
            assertThat(dao.find(first).requestedRevision()).isEqualTo(original.requestedRevision());
            assertThat(dao.find(first).completedRevision()).isEqualTo(original.completedRevision());
            assertThat(dao.pendingFindings(first)).hasSize(1);
            assertThat(dao.recordDispatchAttempt(first, time.plusSeconds(2))).isTrue();
            assertThat(dao.find(first).dispatchAttempts()).isEqualTo(2);
            assertThat(dao.recordDispatchAttempt(missing, time)).isFalse();
            assertThat(dao.find(missing)).isNull();
            final var before = dao.find(first);
            assertThat(dao.scheduleDispatch(first, time.plusSeconds(3))).isTrue();
            assertThat(dao.find(first).dispatchAttempts()).isEqualTo(before.dispatchAttempts());
            assertThat(dao.find(first).requestedRevision()).isEqualTo(before.requestedRevision());
            assertThat(dao.find(first).nextDispatchAt()).isEqualTo(time.plusSeconds(3));
            assertThat(dao.scheduleDispatch(missing, time)).isFalse();
        });
    }

    @Test
    void rolledBackSchedulingAndBookkeepingLeaveTheOriginalStateIntact() {
        final var target = UUID.randomUUID();
        final var time = Instant.now().plusSeconds(60);
        useJdbiTransaction(h -> new AssessmentSyncWorkDao(h).requestFull(target));
        final WorkRow before = withJdbiHandle(h -> new AssessmentSyncWorkDao(h).find(target));
        assertThatThrownBy(() -> useJdbiTransaction(h -> {
                    final var dao = new AssessmentSyncWorkDao(h);
                    dao.scheduleDispatch(target, time);
                    dao.recordDispatchAttempt(target, time.plusSeconds(1));
                    throw new IllegalStateException("rollback");
                }))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("rollback");
        final WorkRow after = withJdbiHandle(h -> new AssessmentSyncWorkDao(h).find(target));
        assertThat(after).isEqualTo(before);
    }

    @Test
    void dispatchOperationsRequireATransactionAndValidateTheirInputs() {
        final var target = UUID.randomUUID();
        final var time = Instant.now();
        try (final var h = openJdbiHandle()) {
            final var dao = new AssessmentSyncWorkDao(h);
            assertThatThrownBy(() -> dao.pollDue(1, true)).isInstanceOf(IllegalStateException.class);
            assertThatThrownBy(() -> dao.recordDispatchAttempts(Map.of(target, time)))
                    .isInstanceOf(IllegalStateException.class);
            assertThatThrownBy(() -> dao.scheduleDispatch(target, time)).isInstanceOf(IllegalStateException.class);
            h.begin();
            for (final int invalid : new int[] {0, -1}) {
                assertThatThrownBy(() -> dao.pollDue(invalid, true))
                        .isInstanceOf(IllegalArgumentException.class)
                        .hasMessage("limit must be positive");
            }
            assertThatThrownBy(() -> dao.recordDispatchAttempts(null)).isInstanceOf(NullPointerException.class);
            final var nullTime = new LinkedHashMap<UUID, Instant>();
            nullTime.put(target, null);
            assertThatThrownBy(() -> dao.recordDispatchAttempts(nullTime)).isInstanceOf(NullPointerException.class);
            assertThatThrownBy(() -> dao.scheduleDispatch(null, time)).isInstanceOf(NullPointerException.class);
            assertThatThrownBy(() -> dao.scheduleDispatch(target, null)).isInstanceOf(NullPointerException.class);
            h.rollback();
        }
    }

    private static UUID uuid(final int value) {
        return new UUID(0, value);
    }
}
