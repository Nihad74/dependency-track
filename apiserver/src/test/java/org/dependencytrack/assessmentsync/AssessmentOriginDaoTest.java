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
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class AssessmentOriginDaoTest extends PersistenceCapableTest {

    @Test
    void concurrentFirstWritersBothCommitAndAdvanceTheVersion() throws Exception {
        final var finding = finding();
        try (final var first = openJdbiHandle();
                final var second = openJdbiHandle();
                final var executor = Executors.newSingleThreadExecutor()) {
            first.begin();
            try {
                new AssessmentOriginDao(first).upsertOrigin(finding.id(), AssessmentOwnership.LOCAL, true);
                final int backend = second.createQuery("SELECT pg_backend_pid()")
                        .mapTo(int.class)
                        .one();
                final var competing = executor.submit(() -> {
                    second.begin();
                    try {
                        second.execute("SET LOCAL statement_timeout = '10s'");
                        new AssessmentOriginDao(second).upsertOrigin(finding.id(), AssessmentOwnership.POLICY, true);
                        second.commit();
                    } finally {
                        if (second.isInTransaction()) {
                            second.rollback();
                        }
                    }
                });
                // Observe the database lock wait, rather than relying on thread scheduling or sleeps.
                await().atMost(5, TimeUnit.SECONDS)
                        .until(() -> withJdbiHandle(handle -> handle.createQuery(
                                        "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE pid = :pid AND wait_event_type = 'Lock')")
                                .bind("pid", backend)
                                .mapTo(boolean.class)
                                .one()));
                first.commit();
                competing.get(10, TimeUnit.SECONDS);
            } finally {
                if (first.isInTransaction()) {
                    first.rollback();
                }
            }
        }
        final var origin = origin(finding.id());
        assertThat(origin.owner()).isEqualTo(AssessmentOwnership.POLICY);
        assertThat(origin.decisionVersion()).isEqualTo(2);
    }

    @ParameterizedTest
    @EnumSource(AssessmentOwnership.class)
    void versionsTrackValuesAndOwnershipAndClearTheWorkerReason(final AssessmentOwnership owner) {
        final var finding = finding();
        useJdbiTransaction(handle -> new AssessmentOriginDao(handle).upsertOrigin(finding.id(), owner, false));
        assertThat(origin(finding.id()).decisionVersion()).isZero();
        useJdbiTransaction(handle -> handle.createUpdate(
                        "UPDATE \"ASSESSMENT_ORIGIN\" SET \"LAST_REASON\" = 'TARGET_LOCAL' WHERE \"ANALYSIS_ID\" = :id")
                .bind("id", finding.id())
                .execute());
        useJdbiTransaction(handle -> new AssessmentOriginDao(handle).upsertOrigin(finding.id(), owner, false));
        assertThat(origin(finding.id()).decisionVersion()).isZero();
        assertThat(origin(finding.id()).lastReason()).isNull();
        useJdbiTransaction(handle -> new AssessmentOriginDao(handle).upsertOrigin(finding.id(), owner, true));
        assertThat(origin(finding.id()).decisionVersion()).isEqualTo(1);
        final var different =
                owner == AssessmentOwnership.LOCAL ? AssessmentOwnership.NEUTRAL : AssessmentOwnership.LOCAL;
        useJdbiTransaction(handle -> new AssessmentOriginDao(handle).upsertOrigin(finding.id(), different, false));
        assertThat(origin(finding.id()).decisionVersion()).isEqualTo(2);
        assertThat(origin(finding.id()).owner()).isEqualTo(different);
        useJdbiTransaction(handle -> new AssessmentOriginDao(handle).upsertOrigin(finding.id(), owner, true));
        assertThat(origin(finding.id()).decisionVersion()).isEqualTo(3);
    }

    @Test
    void mixedBatchInsertsUpdatesAndSkipsDeletedAnalyses() {
        final var existing = finding();
        final var fresh = finding();
        final var deleted = finding();
        useJdbiTransaction(handle -> {
            final var dao = new AssessmentOriginDao(handle);
            dao.upsertOrigin(existing.id(), AssessmentOwnership.LOCAL, true);
            handle.createUpdate("DELETE FROM \"ANALYSIS\" WHERE \"ID\" = :id")
                    .bind("id", deleted.id())
                    .execute();
            dao.upsertOrigins(List.of(
                    new AssessmentOriginDao.OriginUpdate(existing.id(), AssessmentOwnership.POLICY, false),
                    new AssessmentOriginDao.OriginUpdate(fresh.id(), AssessmentOwnership.LOCAL, true),
                    new AssessmentOriginDao.OriginUpdate(deleted.id(), AssessmentOwnership.LOCAL, true)));
            assertThat(dao.findOrigin(deleted.id())).isNull();
            assertThat(dao.findOriginOfFinding(fresh.componentId(), fresh.vulnerabilityId()))
                    .isEqualTo(dao.findOrigin(fresh.id()));
            assertThat(dao.findOriginOfFinding(deleted.componentId(), deleted.vulnerabilityId()))
                    .isNull();
        });
        assertThat(origin(existing.id()).decisionVersion()).isEqualTo(2);
        assertThat(origin(fresh.id()).decisionVersion()).isEqualTo(1);
    }

    @Test
    void rejectsDuplicateUpdatesBeforeChangingAnyOrigin() {
        final var finding = finding();
        useJdbiTransaction(handle -> {
            final var dao = new AssessmentOriginDao(handle);
            assertThatThrownBy(() -> dao.upsertOrigins(List.of(
                            new AssessmentOriginDao.OriginUpdate(finding.id(), AssessmentOwnership.LOCAL, true),
                            new AssessmentOriginDao.OriginUpdate(finding.id(), AssessmentOwnership.POLICY, true))))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThat(dao.findOrigin(finding.id())).isNull();
            dao.upsertOrigins(List.of());
        });
    }

    @Test
    void originWritesRollBackWithTheBusinessTransaction() {
        final var finding = finding();
        assertThatThrownBy(() -> useJdbiTransaction(handle -> {
                    new AssessmentOriginDao(handle).upsertOrigin(finding.id(), AssessmentOwnership.LOCAL, true);
                    throw new IllegalStateException("rollback");
                }))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("rollback");
        assertThat(origin(finding.id())).isNull();
    }

    @Test
    void deletingCopiedTrailsPreservesLocalCommentsAndOtherFindings() {
        final var first = finding();
        final var second = finding();
        final var third = finding();
        useJdbiTransaction(handle -> {
            for (final var finding : List.of(first, second, third)) {
                handle.createUpdate("""
                        INSERT INTO "ASSESSMENT_SOURCE_CONTRIBUTION"
                          ("TARGET_ANALYSIS_ID", "SOURCE_PROJECT_UUID", "SOURCE_COMPONENT_UUID", "SOURCE_VULNERABILITY_UUID", "SOURCE_ANALYSIS_ID")
                        VALUES (:id, :project, :component, :vulnerability, 42)
                        """)
                        .bind("id", finding.id())
                        .bind("project", finding.projectUuid())
                        .bind("component", UUID.randomUUID())
                        .bind("vulnerability", UUID.randomUUID())
                        .execute();
                handle.createUpdate("""
                        INSERT INTO "ASSESSMENT_SOURCE_COMMENT"
                          ("TARGET_ANALYSIS_ID", "SOURCE_PROJECT_UUID", "SOURCE_ANALYSIS_ID", "SOURCE_COMMENT_ID", "COMMENT", "ORIGINAL_TIMESTAMP")
                        VALUES (:id, :project, 42, 43, 'copied', now())
                        """)
                        .bind("id", finding.id())
                        .bind("project", finding.projectUuid())
                        .execute();
            }
            final var dao = new AssessmentOriginDao(handle);
            dao.deleteCopiedContributions(List.of());
            dao.deleteCopiedContributions(List.of(first.id(), second.id()));
            assertThat(handle.createQuery("SELECT \"TARGET_ANALYSIS_ID\" FROM \"ASSESSMENT_SOURCE_CONTRIBUTION\"")
                            .mapTo(long.class)
                            .list())
                    .containsExactly(third.id());
            assertThat(handle.createQuery("SELECT \"TARGET_ANALYSIS_ID\" FROM \"ASSESSMENT_SOURCE_COMMENT\"")
                            .mapTo(long.class)
                            .list())
                    .containsExactly(third.id());
            assertThat(handle.createQuery("SELECT \"COMMENT\" FROM \"ANALYSISCOMMENT\"")
                            .mapTo(String.class)
                            .list())
                    .containsExactlyInAnyOrder("local", "local", "local");
            dao.deleteCopiedContributions(third.id());
        });
    }

    @Test
    void writesRequireATransaction() {
        try (final var handle = openJdbiHandle()) {
            final var dao = new AssessmentOriginDao(handle);
            assertThatThrownBy(() -> dao.upsertOrigins(List.of())).isInstanceOf(IllegalStateException.class);
            assertThatThrownBy(() -> dao.deleteCopiedContributions(List.of()))
                    .isInstanceOf(IllegalStateException.class);
            assertThatThrownBy(() -> dao.backfillProjectOrigins(UUID.randomUUID()))
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void projectionReadKeepsAnUnlabeledLegacyAnalysisWithoutInventingAnOwner() {
        final var finding = finding();
        final var projection = withJdbiHandle(handle -> new AssessmentProjectionDao(handle).load(finding.id()));
        assertThat(projection).isNotNull();
        assertThat(projection.origin()).isNull();
        assertThat(projection.decision().state()).isEqualTo(AnalysisState.NOT_SET);
    }

    @Test
    void rejectsInvalidOriginIdsOwnersAndHandles() {
        assertThatThrownBy(() -> new AssessmentOriginDao(null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new AssessmentOriginDao.OriginUpdate(0, AssessmentOwnership.LOCAL, false))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AssessmentOriginDao.OriginUpdate(-1, AssessmentOwnership.LOCAL, false))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AssessmentOriginDao.OriginUpdate(1, null, false))
                .isInstanceOf(NullPointerException.class);
    }

    private Finding finding() {
        final var project = new Project();
        project.setName("origin-" + UUID.randomUUID());
        project.setVersion("1");
        final var p = qm.persist(project);
        final var component = new Component();
        component.setProject(p);
        component.setName("component");
        final var c = qm.persist(component);
        final var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-" + UUID.randomUUID());
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        final var v = qm.persist(vulnerability);
        final long id = qm.makeAnalysis(new MakeAnalysisCommand(c, v)
                .withComment("local")
                .withOptions(Set.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        useJdbiTransaction(
                handle -> handle.createUpdate("DELETE FROM \"ASSESSMENT_ORIGIN\" WHERE \"ANALYSIS_ID\" = :id")
                        .bind("id", id)
                        .execute());
        return new Finding(id, p.getUuid(), c.getId(), v.getId());
    }

    private static AssessmentOriginDao.Origin origin(final long id) {
        return withJdbiHandle(handle -> new AssessmentOriginDao(handle).findOrigin(id));
    }

    private record Finding(long id, UUID projectUuid, long componentId, long vulnerabilityId) {}
}
