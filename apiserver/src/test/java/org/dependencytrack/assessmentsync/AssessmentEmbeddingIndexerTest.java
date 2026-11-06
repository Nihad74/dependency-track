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
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.statement.SqlLogger;
import org.jdbi.v3.core.statement.StatementContext;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class AssessmentEmbeddingIndexerTest extends PersistenceCapableTest {

    @ParameterizedTest
    @EnumSource(Classifier.class)
    void onlyReachableAssembledUnitsBecomeMarkers(final Classifier classifier) {
        final Project target = project("target");
        final Component root = component(target, "root", classifier);
        final Component child = component(target, "child", Classifier.LIBRARY);
        component(target, "unreachable", Classifier.APPLICATION);
        final Project foreign = project("foreign");
        final Component foreignChild = component(foreign, "foreign-child", Classifier.APPLICATION);
        final boolean marker = List.of(
                        Classifier.APPLICATION,
                        Classifier.CONTAINER,
                        Classifier.DEVICE,
                        Classifier.FIRMWARE,
                        Classifier.OPERATING_SYSTEM,
                        Classifier.PLATFORM)
                .contains(classifier);
        useJdbiTransaction(h -> {
            dependencies(h, "PROJECT", target.getId(), json(root.getUuid()));
            dependencies(
                    h, "COMPONENT", root.getId(), json(child.getUuid(), foreignChild.getUuid(), UUID.randomUUID()));
            dependencies(h, "COMPONENT", child.getId(), json(root.getUuid()));
            new AssessmentEmbeddingIndexer(h).rebuild(target.getUuid());
            final var dao = new AssessmentEmbeddingDao(h);
            assertThat(dao.findByMarkerNameAndVersion("root", "1")).hasSize(marker ? 1 : 0);
            assertThat(dao.findByMarkerNameAndVersion("unreachable", "1")).isEmpty();
            assertThat(dao.findByMarkerNameAndVersion("foreign-child", "1")).isEmpty();
            assertThat(dao.findMembership(target.getId(), child.getId())).hasSize(marker ? 1 : 0);
            assertThat(dao.findMembership(target.getId(), root.getId())).isEmpty();
        });
    }

    @ParameterizedTest
    @ValueSource(strings = {"null-classifier", "blank-name", "null-version", "blank-version"})
    void incompleteReachableComponentsCannotBecomeMarkers(final String invalid) {
        final Project target = project("target");
        final Component marker = component(target, "source", Classifier.APPLICATION);
        useJdbiTransaction(h -> {
            dependencies(h, "PROJECT", target.getId(), json(marker.getUuid()));
            final String update =
                    switch (invalid) {
                        case "null-classifier" -> "UPDATE \"COMPONENT\" SET \"CLASSIFIER\" = NULL WHERE \"ID\" = :id";
                        case "blank-name" -> "UPDATE \"COMPONENT\" SET \"NAME\" = ' ' WHERE \"ID\" = :id";
                        case "null-version" -> "UPDATE \"COMPONENT\" SET \"VERSION\" = NULL WHERE \"ID\" = :id";
                        default -> "UPDATE \"COMPONENT\" SET \"VERSION\" = ' ' WHERE \"ID\" = :id";
                    };
            h.createUpdate(update).bind("id", marker.getId()).execute();
            new AssessmentEmbeddingIndexer(h).rebuild(target.getUuid());
            final int markers = h.createQuery(
                            "SELECT count(*) FROM \"ASSESSMENT_EMBEDDING\" WHERE \"TARGET_PROJECT_ID\" = :id")
                    .bind("id", target.getId())
                    .mapTo(int.class)
                    .one();
            assertThat(markers).isZero();
        });
    }

    @Test
    void repairsMissingMarkersWithoutRewritingAnUnchangedIndexAndClearsRemovedGraph() {
        final Project target = project("target");
        final Project source = project("source");
        final Component marker = component(target, "source", Classifier.APPLICATION);
        final Component child = component(target, "child", Classifier.LIBRARY);
        useJdbiTransaction(h -> {
            dependencies(h, "PROJECT", target.getId(), json(marker.getUuid()));
            dependencies(h, "COMPONENT", marker.getId(), json(child.getUuid()));
            final var indexer = new AssessmentEmbeddingIndexer(h);
            indexer.ensureMarkersPresent(target.getUuid());
            final var dao = new AssessmentEmbeddingDao(h);
            assertThat(dao.findBySourceProject(source.getUuid())).hasSize(1);
            final var writes = countWrites(h);
            indexer.ensureMarkersPresent(target.getUuid());
            indexer.rebuild(target.getUuid());
            assertThat(writes.get())
                    .as("unchanged rebuild must issue no writes")
                    .isZero();
            h.createUpdate("DELETE FROM \"ASSESSMENT_EMBEDDING\" WHERE \"TARGET_PROJECT_ID\" = :id")
                    .bind("id", target.getId())
                    .execute();
            indexer.ensureMarkersPresent(target.getUuid());
            assertThat(dao.findMembership(target.getId(), child.getId())).hasSize(1);
            dependencies(h, "PROJECT", target.getId(), "[]");
            indexer.rebuild(target.getUuid());
            assertThat(dao.findBySourceProject(source.getUuid())).isEmpty();
            assertThat(dao.findMembership(target.getId(), child.getId())).isEmpty();
            indexer.ensureMarkersPresent(target.getUuid());
            indexer.rebuild(UUID.randomUUID());
            indexer.ensureMarkersPresent(UUID.randomUUID());
        });
    }

    @Test
    void ignoresAbsentNonArrayAndIncompleteDependencyDocuments() {
        final Project target = project("target");
        final Component marker = component(target, "source", Classifier.APPLICATION);
        useJdbiTransaction(h -> {
            final var indexer = new AssessmentEmbeddingIndexer(h);
            indexer.rebuild(target.getUuid());
            for (final String document : List.of("{}", "null", "[null,{}, {\"uuid\":1},{\"uuid\":\"\"}]")) {
                dependencies(h, "PROJECT", target.getId(), document);
                indexer.rebuild(target.getUuid());
                assertThat(new AssessmentEmbeddingDao(h).findByMarkerNameAndVersion("source", "1"))
                        .isEmpty();
            }
            dependencies(h, "PROJECT", target.getId(), json(marker.getUuid()));
            dependencies(h, "COMPONENT", marker.getId(), "[{\"uuid\":\"invalid\"}]");
            assertThatThrownBy(() -> indexer.rebuild(target.getUuid()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("dependency uuid");
        });
    }

    @Test
    void indexerRequiresATransaction() {
        withJdbiHandle(h -> {
            assertThatThrownBy(() -> new AssessmentEmbeddingIndexer(h).rebuild(UUID.randomUUID()))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("active transaction");
            return null;
        });
    }

    private static AtomicInteger countWrites(final Handle handle) {
        final var writes = new AtomicInteger();
        handle.setSqlLogger(new SqlLogger() {
            @Override
            public void logAfterExecution(final StatementContext context) {
                final String sql = context.getRenderedSql().stripLeading();
                if (List.of("INSERT", "UPDATE", "DELETE").stream().anyMatch(sql::startsWith)) {
                    writes.incrementAndGet();
                }
            }
        });
        return writes;
    }

    private static void dependencies(final Handle h, final String table, final long id, final String json) {
        final String sql = "PROJECT".equals(table)
                ? "UPDATE \"PROJECT\" SET \"DIRECT_DEPENDENCIES\" = CAST(:json AS jsonb) WHERE \"ID\" = :id"
                : "UPDATE \"COMPONENT\" SET \"DIRECT_DEPENDENCIES\" = CAST(:json AS jsonb) WHERE \"ID\" = :id";
        h.createUpdate(sql).bind("id", id).bind("json", json).execute();
    }

    private static String json(final UUID... ids) {
        return java.util.Arrays.stream(ids)
                .map(id -> "{\"uuid\":\"" + id + "\"}")
                .collect(java.util.stream.Collectors.joining(",", "[", "]"));
    }

    private Project project(final String name) {
        final var project = new Project();
        project.setName(name);
        project.setVersion("1");
        return qm.persist(project);
    }

    private Component component(final Project project, final String name, final Classifier classifier) {
        final var component = new Component();
        component.setProject(project);
        component.setName(name);
        component.setVersion("1");
        component.setClassifier(classifier);
        return qm.persist(component);
    }
}
