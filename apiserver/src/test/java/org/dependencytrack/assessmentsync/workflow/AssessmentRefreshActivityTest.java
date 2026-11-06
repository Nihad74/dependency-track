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

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.dex.api.ActivityContext;
import org.dependencytrack.model.FindingKey;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.proto.internal.workflow.v1.AssessmentSyncPendingRes;
import org.dependencytrack.proto.internal.workflow.v1.RefreshSynchronizedAssessmentsArg;
import org.dependencytrack.proto.internal.workflow.v1.SynchronizeProjectAssessmentsArg;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class AssessmentRefreshActivityTest extends PersistenceCapableTest {
    private static final ActivityContext CONTEXT = () -> UUID.randomUUID();

    @AfterEach
    void clearMode() {
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
    }

    @ParameterizedTest
    @ValueSource(strings = {"OFF", "CAPTURE", "ACTIVE", "WITHDRAW"})
    void pendingFlagsRespectModeAndReadingNeverAcknowledgesWork(final String mode) throws Exception {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, mode);
        final UUID target = project();
        useJdbiTransaction(h -> {
            final var dao = new AssessmentSyncWorkDao(h);
            dao.requestFull(target);
            dao.requestRefresh(target);
        });
        final var before = ReconcileFixture.work(target);
        final AssessmentSyncPendingRes pending = read(target);
        assertThat(pending.getReconciliationPending()).isEqualTo("ACTIVE".equals(mode));
        assertThat(pending.getRefreshPending()).isTrue();
        assertThat(pending.getRefreshRequested()).isEqualTo(1);
        assertThat(pending.getTargetDeleted()).isFalse();
        assertThat(ReconcileFixture.work(target)).isEqualTo(before);
        useJdbiTransaction(h -> {
            final var dao = new AssessmentSyncWorkDao(h);
            final var pass = dao.beginOrResumePass(target);
            assertThat(dao.completePass(target, pass.activeRevision())).isTrue();
            dao.acknowledgeRefresh(target, 1);
        });
        assertThat(read(target))
                .isEqualTo(AssessmentSyncPendingRes.newBuilder()
                        .setRefreshRequested(1)
                        .build());
    }

    @Test
    void absentWorkAndDeletedProjectsReturnTheDocumentedPendingResults() throws Exception {
        final UUID target = project();
        assertThat(read(target)).isEqualTo(AssessmentSyncPendingRes.getDefaultInstance());
        useJdbiTransaction(h -> h.attach(ProjectDao.class).deleteProject(target));
        assertThat(read(target))
                .isEqualTo(AssessmentSyncPendingRes.newBuilder()
                        .setTargetDeleted(true)
                        .build());
        // Deleted target and absent work are an idempotent completion, not a missing-work error.
        new CompleteAssessmentRefreshActivity().execute(CONTEXT, refresh(target, 1));
        assertThat(ReconcileFixture.work(target)).isNull();
    }

    @Test
    void missingWorkForAnExistingTargetIsReportedWithoutCreatingOrAcknowledgingAnything() {
        final UUID target = project();
        assertThatThrownBy(() -> new CompleteAssessmentRefreshActivity().execute(CONTEXT, refresh(target, 1)))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("No assessment sync work for " + target);
        assertThat(ReconcileFixture.work(target)).isNull();
    }

    @Test
    void capturedAcknowledgmentsAreMonotonicClampedAndPreserveActiveReconciliation() {
        final UUID target = project();
        final var key = new FindingKey(11, 22);
        useJdbiTransaction(h -> {
            final var dao = new AssessmentSyncWorkDao(h);
            dao.requestFindings(target, List.of(key));
            final var pass = dao.beginOrResumePass(target);
            dao.advancePass(target, pass.activeRevision(), key);
            dao.requestRefresh(target);
            dao.requestRefresh(target);
            dao.recordDispatchAttempt(target, Instant.now().plusSeconds(3600));
            final var before = dao.find(target);
            assertThat(dao.acknowledgeRefresh(target, 0)).isZero();
            assertThat(dao.acknowledgeRefresh(target, 1)).isEqualTo(1);
            assertThat(dao.acknowledgeRefresh(target, 0)).isEqualTo(1);
            final var partial = dao.find(target);
            assertThat(partial.refreshRequested()).isEqualTo(2);
            assertThat(partial.completedRevision()).isEqualTo(before.completedRevision());
            assertThat(partial.activeRevision()).isEqualTo(before.activeRevision());
            assertThat(partial.cursor()).isEqualTo(key);
            assertThat(partial.dispatchAttempts()).isZero();
            assertThat(partial.nextDispatchAt()).isBeforeOrEqualTo(Instant.now());
            assertThat(dao.pendingFindings(target)).hasSize(1);
            assertThat(dao.acknowledgeRefresh(target, Long.MAX_VALUE)).isEqualTo(2);
            assertThat(dao.find(target).refreshRequested()).isEqualTo(2);
            assertThat(dao.find(target).activeRevision()).isEqualTo(before.activeRevision());
        });
    }

    @Test
    void refreshRequestsAndAcknowledgmentsRollBackWithTheirTransaction() {
        final UUID target = project();
        useJdbiTransaction(h -> new AssessmentSyncWorkDao(h).requestRefresh(target));
        final var before = ReconcileFixture.work(target);
        assertThatThrownBy(() -> useJdbiTransaction(h -> {
                    final var dao = new AssessmentSyncWorkDao(h);
                    dao.requestRefresh(target);
                    dao.acknowledgeRefresh(target, 2);
                    throw new IllegalStateException("rollback refresh");
                }))
                .hasMessage("rollback refresh");
        assertThat(ReconcileFixture.work(target)).isEqualTo(before);
    }

    @Test
    void refreshDaoRequiresATransactionAndRejectsInvalidOrMissingWork() {
        final UUID missing = UUID.randomUUID();
        withJdbiHandle(h -> {
            final var dao = new AssessmentSyncWorkDao(h);
            assertThatThrownBy(() -> dao.requestRefresh(missing))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("transaction");
            assertThatThrownBy(() -> dao.acknowledgeRefresh(missing, 1))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("transaction");
            return null;
        });
        useJdbiTransaction(h -> {
            final var dao = new AssessmentSyncWorkDao(h);
            assertThatThrownBy(() -> dao.acknowledgeRefresh(missing, -1))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessage("capturedRefresh must not be negative");
            assertThatThrownBy(() -> dao.acknowledgeRefresh(missing, 1))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("No assessment sync work");
        });
    }

    private UUID project() {
        final var project = new Project();
        project.setName("refresh-activities-" + UUID.randomUUID());
        project.setVersion("1");
        return qm.persist(project).getUuid();
    }

    private static AssessmentSyncPendingRes read(final UUID target) throws Exception {
        return new ReadAssessmentSyncPendingActivity()
                .execute(
                        CONTEXT,
                        SynchronizeProjectAssessmentsArg.newBuilder()
                                .setProjectUuid(target.toString())
                                .build());
    }

    private static RefreshSynchronizedAssessmentsArg refresh(final UUID target, final long revision) {
        return RefreshSynchronizedAssessmentsArg.newBuilder()
                .setProjectUuid(target.toString())
                .setRefreshRevision(revision)
                .build();
    }
}
