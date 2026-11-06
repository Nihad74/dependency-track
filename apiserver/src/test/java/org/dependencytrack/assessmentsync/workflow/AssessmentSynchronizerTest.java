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
import org.dependencytrack.assessmentsync.AssessmentMutationGuard;
import org.dependencytrack.assessmentsync.AssessmentReason;
import org.dependencytrack.assessmentsync.AssessmentSynchronizer;
import org.dependencytrack.assessmentsync.AssessmentSynchronizer.BatchResult;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.FindingKey;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class AssessmentSynchronizerTest extends PersistenceCapableTest {

    @ParameterizedTest
    @ValueSource(strings = {"commenter", "comment_id", "details", "missing_contribution", "missing_comment"})
    void repairsCopiedTrailDriftWithoutChangingTheDecisionOrRequestingRefresh(final String kind) {
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 1);
        final var keys = List.of(new FindingKey(fixture.library().getId(), fixture.vulnerability.getId()));
        assertThat(reconcile(fixture, keys).applied()).isEqualTo(1);
        final long beforeVersion = version(fixture);
        useJdbiTransaction(h -> {
            final String sql =
                    switch (kind) {
                        case "commenter" ->
                            "UPDATE \"ASSESSMENT_SOURCE_COMMENT\" SET \"COMMENTER\" = 'incorrect' WHERE \"SOURCE_ANALYSIS_ID\" = :id";
                        case "comment_id" ->
                            "UPDATE \"ASSESSMENT_SOURCE_COMMENT\" SET \"SOURCE_COMMENT_ID\" = \"SOURCE_COMMENT_ID\" + 100000000 WHERE \"SOURCE_ANALYSIS_ID\" = :id";
                        case "details" ->
                            "UPDATE \"ASSESSMENT_SOURCE_CONTRIBUTION\" SET \"SOURCE_DETAILS\" = 'incorrect' WHERE \"SOURCE_ANALYSIS_ID\" = :id";
                        case "missing_contribution" ->
                            "DELETE FROM \"ASSESSMENT_SOURCE_CONTRIBUTION\" WHERE \"SOURCE_ANALYSIS_ID\" = :id";
                        default -> "DELETE FROM \"ASSESSMENT_SOURCE_COMMENT\" WHERE \"SOURCE_ANALYSIS_ID\" = :id";
                    };
            h.createUpdate(sql).bind("id", fixture.alpineAnalysisId).execute();
        });
        final int beforeDrift =
                inJdbiTransaction(h -> new AssessmentSynchronizer().countDrift(h, fixture.target.getUuid(), keys));
        assertThat(beforeDrift).isEqualTo(1);
        assertThat(reconcile(fixture, keys)).isEqualTo(new BatchResult(1, 0, 0, 0, false));
        assertThat(version(fixture)).isEqualTo(beforeVersion);
        final int afterDrift =
                inJdbiTransaction(h -> new AssessmentSynchronizer().countDrift(h, fixture.target.getUuid(), keys));
        assertThat(afterDrift).isZero();
        assertThat(reconcile(fixture, keys)).isEqualTo(new BatchResult(0, 0, 1, 0, false));
    }

    @Test
    void requiresATransactionAndHandlesEmptyOrMissingTargetsWithoutWriting() {
        final var synchronizer = new AssessmentSynchronizer();
        withJdbiHandle(h -> {
            assertThatThrownBy(() -> synchronizer.reconcileBatch(h, UUID.randomUUID(), List.of()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("active transaction");
            assertThatThrownBy(() -> synchronizer.countDrift(h, UUID.randomUUID(), List.of()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("active transaction");
            return null;
        });
        useJdbiTransaction(h -> {
            final UUID missing = UUID.randomUUID();
            assertThat(synchronizer.reconcileBatch(h, missing, List.of()))
                    .isEqualTo(new BatchResult(0, 0, 0, 0, false));
            assertThat(synchronizer.countDrift(h, missing, List.of())).isZero();
            final var keys = List.of(new FindingKey(1, 2));
            assertThat(synchronizer.reconcileBatch(h, missing, keys)).isEqualTo(new BatchResult(0, 0, 1, 0, false));
            assertThat(synchronizer.countDrift(h, missing, keys)).isZero();
        });
    }

    @Test
    void deduplicatesFindingsAndIgnoresForeignOrMissingInventory() {
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 2);
        final var first = new FindingKey(fixture.libraries.getFirst().getId(), fixture.vulnerability.getId());
        final var second = new FindingKey(fixture.libraries.getLast().getId(), fixture.vulnerability.getId());
        final var foreign = new FindingKey(
                withJdbiHandle(h -> h.createQuery("SELECT \"COMPONENT_ID\" FROM \"ANALYSIS\" WHERE \"ID\" = :id")
                        .bind("id", fixture.alpineAnalysisId)
                        .mapTo(long.class)
                        .one()),
                fixture.vulnerability.getId());
        final var keys =
                List.of(second, first, second, foreign, new FindingKey(Long.MAX_VALUE, fixture.vulnerability.getId()));
        assertThat(reconcile(fixture, keys)).isEqualTo(new BatchResult(2, 0, 2, 0, true));
        assertThat(reconcile(fixture, keys)).isEqualTo(new BatchResult(0, 0, 4, 0, false));
        final int drift =
                inJdbiTransaction(h -> new AssessmentSynchronizer().countDrift(h, fixture.target.getUuid(), keys));
        assertThat(drift).isZero();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void anAmbiguousOrConflictingSourceBlocksAnotherAgreeingSource(final boolean conflict) {
        final ReconcileFixture fixture = ReconcileFixture.twoSources(qm);
        final var keys = List.of(new FindingKey(fixture.library().getId(), fixture.vulnerability.getId()));
        assertThat(reconcile(fixture, keys).applied()).isEqualTo(1);
        if (conflict) {
            useJdbiTransaction(h -> {
                h.createUpdate("UPDATE \"COMPONENT\" SET \"SHA_256\" = :hash WHERE \"PROJECT_ID\" = :id")
                        .bind("hash", "ab".repeat(32))
                        .bind("id", fixture.alpine.getId())
                        .execute();
                h.createUpdate("UPDATE \"COMPONENT\" SET \"SHA_256\" = :hash WHERE \"ID\" = :id")
                        .bind("hash", "cd".repeat(32))
                        .bind("id", fixture.library().getId())
                        .execute();
            });
        } else {
            final var duplicate = new Component();
            duplicate.setProject(fixture.alpine);
            duplicate.setName("duplicate");
            duplicate.setVersion("1.2.3");
            duplicate.setClassifier(Classifier.LIBRARY);
            duplicate.setPurl(ReconcileFixture.FOO_PURL);
            qm.persist(duplicate);
        }
        assertThat(reconcile(fixture, keys)).isEqualTo(new BatchResult(0, 1, 0, 0, true));
        assertThat(reason(fixture))
                .isEqualTo(
                        conflict
                                ? AssessmentReason.IDENTITY_CONFLICT.name()
                                : AssessmentReason.AMBIGUOUS_COMPONENT.name());
        assertThat(ReconcileFixture.contributionCount(fixture.library().getId(), fixture.vulnerability.getId()))
                .isZero();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void inactiveSourceOrTargetAttributionWithdrawsAnExistingCopy(final boolean target) {
        final ReconcileFixture fixture = ReconcileFixture.oneSource(qm, 1);
        final var keys = List.of(new FindingKey(fixture.library().getId(), fixture.vulnerability.getId()));
        assertThat(reconcile(fixture, keys).applied()).isEqualTo(1);
        useJdbiTransaction(h -> h.createUpdate("""
                UPDATE "FINDINGATTRIBUTION" AS fa SET "DELETED_AT" = now()
                  FROM "COMPONENT" AS c WHERE c."ID" = fa."COMPONENT_ID" AND c."PROJECT_ID" = :id
                """)
                .bind("id", target ? fixture.target.getId() : fixture.alpine.getId())
                .execute());
        assertThat(reconcile(fixture, keys)).isEqualTo(new BatchResult(0, 1, 0, 0, true));
        assertThat(reason(fixture))
                .isEqualTo(
                        target ? AssessmentReason.FINDING_INACTIVE.name() : AssessmentReason.NO_AUTHORED_SOURCE.name());
    }

    private static BatchResult reconcile(final ReconcileFixture fixture, final List<FindingKey> keys) {
        return inJdbiTransaction(h -> {
            AssessmentMutationGuard.lockProject(h, fixture.target.getUuid());
            return new AssessmentSynchronizer().reconcileBatch(h, fixture.target.getUuid(), keys);
        });
    }

    private static long version(final ReconcileFixture fixture) {
        return withJdbiHandle(h -> h.createQuery("""
                SELECT o."DECISION_VERSION" FROM "ASSESSMENT_ORIGIN" AS o
                JOIN "ANALYSIS" AS a ON a."ID" = o."ANALYSIS_ID"
                WHERE a."COMPONENT_ID" = :id AND a."VULNERABILITY_ID" = :vulnerability
                """)
                .bind("id", fixture.library().getId())
                .bind("vulnerability", fixture.vulnerability.getId())
                .mapTo(long.class)
                .one());
    }

    private static String reason(final ReconcileFixture fixture) {
        return withJdbiHandle(h -> h.createQuery("""
                SELECT o."LAST_REASON" FROM "ASSESSMENT_ORIGIN" AS o
                JOIN "ANALYSIS" AS a ON a."ID" = o."ANALYSIS_ID"
                WHERE a."COMPONENT_ID" = :id AND a."VULNERABILITY_ID" = :vulnerability
                """)
                .bind("id", fixture.library().getId())
                .bind("vulnerability", fixture.vulnerability.getId())
                .mapTo(String.class)
                .one());
    }
}
