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
import org.dependencytrack.assessmentsync.AssessmentChange.LookupKey;
import org.dependencytrack.assessmentsync.AssessmentChange.Reason;
import org.dependencytrack.assessmentsync.AssessmentChange.Scope;
import org.dependencytrack.assessmentsync.AssessmentSyncOutboxDao.OutboxEntry;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.jdbi.v3.core.Handle;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

class AssessmentSyncOutboxDaoTest extends PersistenceCapableTest {

    @Test
    void shouldMergeLookupKeysInOneTransactionAndKeepSeparateRowsAcrossTransactions() {
        final UUID projectUuid = UUID.fromString("10000000-0000-4000-8000-000000000001");
        final UUID componentUuid = UUID.fromString("20000000-0000-4000-8000-000000000002");
        final UUID vulnerabilityUuid = UUID.fromString("30000000-0000-4000-8000-000000000003");

        final long mergedId = inJdbiTransaction(handle -> {
            final var dao = new AssessmentSyncOutboxDao(handle);
            final long first = record(
                    dao,
                    finding(
                            projectUuid,
                            componentUuid,
                            vulnerabilityUuid,
                            Reason.BOM_IMPORT,
                            new LookupKey("before", "1")));
            final long second = record(
                    dao,
                    finding(
                            projectUuid,
                            componentUuid,
                            vulnerabilityUuid,
                            Reason.PROJECT_UPDATED,
                            new LookupKey("after", "2")));
            assertThat(second).isEqualTo(first);
            final List<Long> batched = dao.recordAll(List.of(
                    finding(
                            projectUuid,
                            componentUuid,
                            vulnerabilityUuid,
                            Reason.COMPONENT_CHANGED,
                            new LookupKey("extra", "4")),
                    finding(
                            projectUuid,
                            componentUuid,
                            vulnerabilityUuid,
                            Reason.ATTRIBUTION,
                            new LookupKey("before", "1"))));
            assertThat(batched).containsExactly(first);
            return first;
        });

        useJdbiTransaction(handle -> record(
                new AssessmentSyncOutboxDao(handle),
                finding(projectUuid, componentUuid, vulnerabilityUuid, Reason.POLICY, new LookupKey("later", "3"))));

        final List<OutboxEntry> rows = inJdbiTransaction(handle -> new AssessmentSyncOutboxDao(handle).pollDue(10));
        assertThat(rows).hasSize(2);
        final OutboxEntry merged =
                rows.stream().filter(row -> row.id() == mergedId).findFirst().orElseThrow();
        assertThat(merged.schemaVersion()).isEqualTo(1);
        assertThat(merged.change().reason()).isEqualTo(Reason.BOM_IMPORT);
        assertThat(merged.change().scope()).isEqualTo(Scope.FINDING);
        assertThat(merged.change().lookupKeys())
                .containsExactlyInAnyOrder(
                        new LookupKey("before", "1"), new LookupKey("after", "2"), new LookupKey("extra", "4"));
        assertThat(merged.dispatchAttempts()).isZero();
        assertThat(merged.lastErrorCode()).isNull();

        final OutboxEntry separate =
                rows.stream().filter(row -> row.id() != mergedId).findFirst().orElseThrow();
        assertThat(separate.change().reason()).isEqualTo(Reason.POLICY);
        assertThat(separate.change().lookupKeys()).containsExactly(new LookupKey("later", "3"));
    }

    @Test
    void shouldLeaveNoOutboxRowWhenBusinessTransactionRollsBack() {
        final Handle handle = openJdbiHandle();
        try {
            handle.begin();
            record(
                    new AssessmentSyncOutboxDao(handle),
                    finding(
                            UUID.fromString("10000000-0000-4000-8000-000000000011"),
                            UUID.fromString("20000000-0000-4000-8000-000000000012"),
                            UUID.fromString("30000000-0000-4000-8000-000000000013"),
                            Reason.BOM_IMPORT,
                            new LookupKey("cmx500", "1.0.0")));
            handle.rollback();
        } finally {
            if (handle.isInTransaction()) {
                handle.rollback();
            }
            handle.close();
        }

        assertThat(outboxCount()).isZero();
    }

    @Test
    void shouldPollLowerIdCommittedAfterHigherId() {
        final Handle slow = openJdbiHandle();
        final Handle fast = openJdbiHandle();
        try {
            slow.begin();
            final long lowerId = record(
                    new AssessmentSyncOutboxDao(slow),
                    finding(
                            UUID.fromString("10000000-0000-4000-8000-000000000021"),
                            UUID.fromString("20000000-0000-4000-8000-000000000022"),
                            UUID.fromString("30000000-0000-4000-8000-000000000023"),
                            Reason.AUTHORED,
                            new LookupKey("slow", "1")));
            fast.begin();
            final long higherId = record(
                    new AssessmentSyncOutboxDao(fast),
                    finding(
                            UUID.fromString("10000000-0000-4000-8000-000000000031"),
                            UUID.fromString("20000000-0000-4000-8000-000000000032"),
                            UUID.fromString("30000000-0000-4000-8000-000000000033"),
                            Reason.AUTHORED,
                            new LookupKey("fast", "1")));
            fast.commit();

            final List<Long> afterHigherCommit = inJdbiTransaction(handle -> new AssessmentSyncOutboxDao(handle)
                    .pollDue(10).stream().map(OutboxEntry::id).toList());
            assertThat(afterHigherCommit).containsExactly(higherId);

            slow.commit();

            final List<Long> afterLowerCommit = inJdbiTransaction(handle -> new AssessmentSyncOutboxDao(handle)
                    .pollDue(10).stream().map(OutboxEntry::id).toList());
            assertThat(lowerId).isLessThan(higherId);
            assertThat(afterLowerCommit).containsExactly(lowerId, higherId);
        } finally {
            if (slow.isInTransaction()) {
                slow.rollback();
            }
            if (fast.isInTransaction()) {
                fast.rollback();
            }
            slow.close();
            fast.close();
        }
    }

    @Test
    void shouldKeepOutboxRowWhenReferencedProjectIsDeleted() {
        final Project project = new Project();
        project.setName("cmx500");
        project.setVersion("1.0.0");
        final Project persisted = qm.persist(project);

        final long id = inJdbiTransaction(handle -> record(
                new AssessmentSyncOutboxDao(handle),
                new AssessmentChange(
                        Scope.PROJECT,
                        persisted.getUuid(),
                        null,
                        null,
                        Reason.PROJECT_DELETED,
                        List.of(new LookupKey("cmx500", "1.0.0")))));
        useJdbiTransaction(handle -> handle.attach(ProjectDao.class).deleteProject(persisted.getUuid()));

        final OutboxEntry entry = inJdbiTransaction(handle -> new AssessmentSyncOutboxDao(handle).lock(id));
        assertThat(projectCount(persisted.getUuid())).isZero();
        assertThat(entry).isNotNull();
        assertThat(entry.change().projectUuid()).isEqualTo(persisted.getUuid());
        assertThat(entry.change().scope()).isEqualTo(Scope.PROJECT);
        assertThat(entry.change().lookupKeys()).containsExactly(new LookupKey("cmx500", "1.0.0"));
    }

    @Test
    void shouldUpdateDispatchLockCursorAndDeleteOnlyAfterExpansionFinishes() {
        final UUID cursor = UUID.fromString("00000000-0000-4000-8000-00000000007b");
        final Instant nextDispatchAt = Instant.parse("2030-01-01T00:00:00Z");
        final long id = inJdbiTransaction(handle -> record(
                new AssessmentSyncOutboxDao(handle),
                finding(
                        UUID.fromString("10000000-0000-4000-8000-000000000041"),
                        UUID.fromString("20000000-0000-4000-8000-000000000042"),
                        UUID.fromString("30000000-0000-4000-8000-000000000043"),
                        Reason.BOM_IMPORT,
                        new LookupKey("cmx500", "1.0.0"))));

        useJdbiTransaction(handle -> {
            final var dao = new AssessmentSyncOutboxDao(handle);
            final OutboxEntry locked = dao.lock(id);
            assertThat(locked).isNotNull();
            assertThat(locked.fanoutCursor()).isNull();
            assertThat(dao.updateFanoutCursor(id, cursor)).isTrue();
            assertThat(dao.recordDispatchAttempt(id, nextDispatchAt, "EXPAND_FAILED"))
                    .isTrue();
            assertThat(dao.recordDispatchAttempt(id, nextDispatchAt, "EXPAND_FAILED"))
                    .isTrue();
        });

        final OutboxEntry updated = inJdbiTransaction(handle -> new AssessmentSyncOutboxDao(handle).lock(id));
        assertThat(updated.fanoutCursor()).isEqualTo(cursor);
        assertThat(updated.dispatchAttempts()).isEqualTo(2);
        assertThat(updated.lastErrorCode()).isEqualTo("EXPAND_FAILED");
        assertThat(updated.nextDispatchAt()).isEqualTo(nextDispatchAt);
        final List<OutboxEntry> due = inJdbiTransaction(handle -> new AssessmentSyncOutboxDao(handle).pollDue(10));
        assertThat(due).isEmpty();

        useJdbiTransaction(handle -> {
            final var dao = new AssessmentSyncOutboxDao(handle);
            assertThat(dao.deleteFinished(id)).isTrue();
            assertThat(dao.lock(id)).isNull();
            assertThat(dao.deleteFinished(id)).isFalse();
            assertThat(dao.recordDispatchAttempt(id, nextDispatchAt, "EXPAND_FAILED"))
                    .isFalse();
        });
        assertThat(outboxCount()).isZero();
    }

    private static AssessmentChange finding(
            final UUID projectUuid,
            final UUID componentUuid,
            final UUID vulnerabilityUuid,
            final Reason reason,
            final LookupKey lookupKey) {
        return new AssessmentChange(
                Scope.FINDING, projectUuid, componentUuid, vulnerabilityUuid, reason, List.of(lookupKey));
    }

    private static long record(final AssessmentSyncOutboxDao dao, final AssessmentChange change) {
        return dao.recordAll(List.of(change)).getFirst();
    }

    private static int outboxCount() {
        return inJdbiTransaction(
                handle -> handle.createQuery("""
                        SELECT COUNT(*)
                          FROM "ASSESSMENT_SYNC_OUTBOX"
                        """).mapTo(int.class).one());
    }

    private static int projectCount(final UUID projectUuid) {
        return inJdbiTransaction(handle -> handle.createQuery("""
                        SELECT COUNT(*)
                          FROM "PROJECT"
                         WHERE "UUID" = :projectUuid
                        """)
                .bind("projectUuid", projectUuid)
                .mapTo(int.class)
                .one());
    }
}
