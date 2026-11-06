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
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao.PendingFinding;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao.WorkRow;
import org.dependencytrack.model.FindingKey;
import org.jdbi.v3.core.statement.SqlLogger;
import org.jdbi.v3.core.statement.SqlStatements;
import org.jdbi.v3.core.statement.StatementContext;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class AssessmentSyncWorkRequestTest extends PersistenceCapableTest {

    @Test
    void allRequestFormsRequireTheCallersTransaction() {
        final var target = UUID.randomUUID();
        try (final var h = openJdbiHandle()) {
            final var dao = new AssessmentSyncWorkDao(h);
            assertThatThrownBy(() -> dao.requestFull(target)).isInstanceOf(IllegalStateException.class);
            assertThatThrownBy(() -> dao.requestFull(List.of(target))).isInstanceOf(IllegalStateException.class);
            assertThatThrownBy(() -> dao.requestFindings(target, List.of(new FindingKey(1, 2))))
                    .isInstanceOf(IllegalStateException.class);
            assertThatThrownBy(() -> dao.requestFindings(Map.of(target, List.of(new FindingKey(1, 2)))))
                    .isInstanceOf(IllegalStateException.class);
            assertThatThrownBy(() -> dao.requestWork(List.of(target), Map.of()))
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void mixedBatchUsesOneStatementAndOneRevisionPerTargetWhilePreservingAnActivePass() {
        final var busy = UUID.randomUUID();
        final var keysOnly = UUID.randomUUID();
        final var fresh = UUID.randomUUID();
        useJdbiTransaction(h -> {
            final var dao = new AssessmentSyncWorkDao(h);
            dao.requestFindings(busy, List.of(new FindingKey(1, 2)));
            dao.requestFull(busy);
            final var active = dao.beginOrResumePass(busy);
            assertThat(active.activeRevision()).isEqualTo(2);
            dao.advancePass(busy, 2, new FindingKey(20, 30));
            final var count = new AtomicInteger();
            final var previous = h.getConfig(SqlStatements.class).getSqlLogger();
            h.getConfig(SqlStatements.class).setSqlLogger(new SqlLogger() {
                @Override
                public void logAfterExecution(final StatementContext ctx) {
                    count.incrementAndGet();
                }
            });
            try {
                dao.requestWork(
                        List.of(fresh, busy, busy),
                        Map.of(
                                busy, List.of(new FindingKey(99, 100)),
                                keysOnly, List.of(new FindingKey(5, 6), new FindingKey(5, 6))));
            } finally {
                h.getConfig(SqlStatements.class).setSqlLogger(previous);
            }
            assertThat(count).hasValue(1);
            final var row = dao.find(busy);
            assertThat(row.requestedRevision()).isEqualTo(3);
            assertThat(row.fullRevision()).isEqualTo(3);
            assertThat(row.activeRevision()).isEqualTo(2);
            assertThat(row.cursor()).isEqualTo(new FindingKey(20, 30));
            assertThat(dao.pendingFindings(busy)).containsExactly(new PendingFinding(1, 2, 1));
            assertThat(dao.find(keysOnly).requestedRevision()).isEqualTo(1);
            assertThat(dao.find(keysOnly).fullRevision()).isZero();
            assertThat(dao.pendingFindings(keysOnly)).containsExactly(new PendingFinding(5, 6, 1));
            assertThat(dao.find(fresh).requestedRevision()).isEqualTo(1);
            assertThat(dao.find(fresh).fullRevision()).isEqualTo(1);
        });
    }

    @Test
    void rollbackRestoresBothExistingAndNewRequestsAndTheirKeys() {
        final var existing = UUID.randomUUID();
        final var fresh = UUID.randomUUID();
        useJdbiTransaction(h -> new AssessmentSyncWorkDao(h).requestFindings(existing, List.of(new FindingKey(1, 2))));
        assertThatThrownBy(() -> useJdbiTransaction(h -> {
                    new AssessmentSyncWorkDao(h)
                            .requestWork(List.of(existing), Map.of(fresh, List.of(new FindingKey(3, 4))));
                    throw new IllegalStateException("rollback");
                }))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("rollback");
        withJdbiHandle(h -> {
            final var dao = new AssessmentSyncWorkDao(h);
            assertThat(dao.find(existing).requestedRevision()).isEqualTo(1);
            assertThat(dao.find(existing).fullRevision()).isZero();
            assertThat(dao.pendingFindings(existing)).containsExactly(new PendingFinding(1, 2, 1));
            assertThat(dao.find(fresh)).isNull();
            return null;
        });
    }

    @Test
    void emptyBatchesExecuteNoSqlAndEmptyTargetKeysStillAllocateARevision() {
        final var target = UUID.randomUUID();
        useJdbiTransaction(h -> {
            final var dao = new AssessmentSyncWorkDao(h);
            final var count = new AtomicInteger();
            h.getConfig(SqlStatements.class).setSqlLogger(new SqlLogger() {
                @Override
                public void logAfterExecution(final StatementContext ctx) {
                    count.incrementAndGet();
                }
            });
            dao.requestWork(List.of(), Map.of());
            dao.requestFull(List.of());
            dao.requestFindings(Map.of());
            assertThat(count).hasValue(0);
            dao.requestFindings(Map.of(target, List.of()));
            assertThat(count).hasValue(1);
            count.set(0);
            assertThat(dao.requestFindings(target, List.of())).isEqualTo(2);
            assertThat(count).hasValue(1);
            assertThat(dao.find(target).requestedRevision()).isEqualTo(2);
            assertThat(dao.find(target).fullRevision()).isZero();
            assertThat(dao.pendingFindings(target)).isEmpty();
        });
    }

    @Test
    void invalidBatchInputsCannotMutateAnyTargetEvenWhenCaught() {
        final var target = UUID.randomUUID();
        useJdbiTransaction(h -> {
            final var dao = new AssessmentSyncWorkDao(h);
            final var nullTarget = new LinkedHashMap<UUID, Collection<FindingKey>>();
            nullTarget.put(null, List.of(new FindingKey(1, 2)));
            final var nullKeys = new LinkedHashMap<UUID, Collection<FindingKey>>();
            nullKeys.put(target, null);
            assertThatThrownBy(() -> dao.requestWork(null, Map.of())).isInstanceOf(NullPointerException.class);
            assertThatThrownBy(() -> dao.requestWork(List.of(), null)).isInstanceOf(NullPointerException.class);
            assertThatThrownBy(() -> dao.requestWork(Arrays.asList((UUID) null), Map.of()))
                    .isInstanceOf(NullPointerException.class);
            assertThatThrownBy(() -> dao.requestWork(List.of(target), nullTarget))
                    .isInstanceOf(NullPointerException.class);
            assertThatThrownBy(() -> dao.requestWork(List.of(target), nullKeys))
                    .isInstanceOf(NullPointerException.class);
            assertThatThrownBy(() -> dao.requestWork(List.of(target), Map.of(target, Arrays.asList((FindingKey) null))))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessage("finding key must not be null");
        });
        final WorkRow row = withJdbiHandle(h -> new AssessmentSyncWorkDao(h).find(target));
        assertThat(row).isNull();
    }

    @Test
    void aNewBatchRevisionSurvivesAcknowledgementOfAnOlderPass() {
        final var target = UUID.randomUUID();
        useJdbiTransaction(h -> {
            final var dao = new AssessmentSyncWorkDao(h);
            dao.requestFindings(target, List.of(new FindingKey(1, 2)));
            final var pass = dao.beginOrResumePass(target);
            dao.requestFindings(Map.of(target, List.of(new FindingKey(1, 2), new FindingKey(3, 4))));
            assertThat(dao.completePass(target, pass.activeRevision())).isTrue();
            assertThat(dao.pendingFindings(target))
                    .containsExactly(new PendingFinding(1, 2, 2), new PendingFinding(3, 4, 2));
            assertThat(dao.find(target).requestedRevision()).isEqualTo(2);
            assertThat(dao.find(target).completedRevision()).isEqualTo(1);
        });
    }
}
