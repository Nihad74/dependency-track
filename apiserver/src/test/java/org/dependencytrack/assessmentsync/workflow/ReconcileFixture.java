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

import org.dependencytrack.assessmentsync.AssessmentEmbeddingIndexer;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao;
import org.dependencytrack.assessmentsync.AssessmentSyncWorkDao.WorkRow;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.jspecify.annotations.Nullable;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/// Two authored sources and one target whose marker graph names those sources.
final class ReconcileFixture {

    static final String FOO_PURL = "pkg:maven/org.example/libfoo@1.2.3";
    static final String BAR_PURL = "pkg:maven/org.example/libbar@4.5.6";
    static final String ALPINE_DETAILS = "from-alpine";
    static final String DEBIAN_DETAILS = "from-debian";
    static final String ALPINE_NOTE = "alpine-note";
    static final Instant ALPINE_NOTE_AT = Instant.parse("2024-01-02T03:04:05Z");

    private static final AtomicInteger SEQUENCE = new AtomicInteger();

    final Project target;
    final Project alpine;
    final @Nullable Project debian;
    final @Nullable Component debianLibrary;
    final List<Component> libraries;
    final Vulnerability vulnerability;
    final long alpineAnalysisId;
    final long debianAnalysisId;

    private ReconcileFixture(
            final Project target,
            final Project alpine,
            final @Nullable Project debian,
            final @Nullable Component debianLibrary,
            final List<Component> libraries,
            final Vulnerability vulnerability,
            final long alpineAnalysisId,
            final long debianAnalysisId) {
        this.target = target;
        this.alpine = alpine;
        this.debian = debian;
        this.debianLibrary = debianLibrary;
        this.libraries = libraries;
        this.vulnerability = vulnerability;
        this.alpineAnalysisId = alpineAnalysisId;
        this.debianAnalysisId = debianAnalysisId;
    }

    static ReconcileFixture twoSources(final QueryManager qm) {
        return create(qm, 1, true);
    }

    static ReconcileFixture oneSource(final QueryManager qm, final int libraries) {
        return create(qm, libraries, false);
    }

    Component library() {
        return libraries.getFirst();
    }

    private static ReconcileFixture create(final QueryManager qm, final int libraryCount, final boolean twoSources) {
        if (libraryCount <= 0) {
            throw new IllegalArgumentException("libraryCount must be positive");
        }
        final int sequence = SEQUENCE.incrementAndGet();
        final var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-" + UUID.randomUUID());
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        final Vulnerability persistedVulnerability = qm.persist(vulnerability);

        final Project alpine = project(qm, "alpine-" + sequence, "3.20." + sequence);
        final Project debian = twoSources ? project(qm, "debian-" + sequence, "12." + sequence) : null;
        final Project target = project(qm, "product-" + sequence, "1.0." + sequence);

        final var libraries = new ArrayList<Component>(libraryCount);
        long alpineAnalysisId = 0;
        for (int i = 0; i < libraryCount; i++) {
            final String name = i == 0 ? "libfoo" : "libbar-" + i;
            final String version = i == 0 ? "1.2.3" : "4.5.6";
            final String purl = i == 0 ? FOO_PURL : BAR_PURL + i;
            final Component sourceComponent = component(qm, alpine, name, version, Classifier.LIBRARY, purl);
            qm.addVulnerability(persistedVulnerability, sourceComponent, "internal");
            final long analysisId = qm.makeAnalysis(new MakeAnalysisCommand(sourceComponent, persistedVulnerability)
                    .withState(org.dependencytrack.model.AnalysisState.EXPLOITABLE)
                    .withDetails(ALPINE_DETAILS)
                    .withOptions(Set.of(
                            MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL,
                            MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
            if (i == 0) {
                alpineAnalysisId = analysisId;
                comment(analysisId, ALPINE_NOTE, "alice", ALPINE_NOTE_AT);
            }
            libraries.add(component(qm, target, name, version, Classifier.LIBRARY, purl));
        }

        long debianAnalysisId = 0;
        Component debianLibrary = null;
        if (debian != null) {
            debianLibrary = component(qm, debian, "libfoo", "1.2.3", Classifier.LIBRARY, FOO_PURL);
            qm.addVulnerability(persistedVulnerability, debianLibrary, "internal");
            debianAnalysisId = qm.makeAnalysis(new MakeAnalysisCommand(debianLibrary, persistedVulnerability)
                    .withState(org.dependencytrack.model.AnalysisState.EXPLOITABLE)
                    .withDetails(DEBIAN_DETAILS)
                    .withOptions(Set.of(
                            MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL,
                            MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        }

        final Component alpineMarker =
                component(qm, target, alpine.getName(), alpine.getVersion(), Classifier.OPERATING_SYSTEM, null);
        final Component debianMarker = debian == null
                ? null
                : component(qm, target, debian.getName(), debian.getVersion(), Classifier.OPERATING_SYSTEM, null);

        final var roots = new ArrayList<UUID>();
        roots.add(alpineMarker.getUuid());
        if (debianMarker != null) {
            roots.add(debianMarker.getUuid());
        }
        directDependencies("PROJECT", target.getId(), roots);
        final var alpineChildren = new ArrayList<UUID>();
        for (final Component library : libraries) {
            alpineChildren.add(library.getUuid());
            qm.addVulnerability(persistedVulnerability, library, "internal");
        }
        directDependencies("COMPONENT", alpineMarker.getId(), alpineChildren);
        if (debianMarker != null) {
            directDependencies(
                    "COMPONENT",
                    debianMarker.getId(),
                    List.of(libraries.getFirst().getUuid()));
        }
        useJdbiTransaction(handle -> new AssessmentEmbeddingIndexer(handle).rebuild(target.getUuid()));
        return new ReconcileFixture(
                target,
                alpine,
                debian,
                debianLibrary,
                libraries,
                persistedVulnerability,
                alpineAnalysisId,
                debianAnalysisId);
    }

    private static Project project(final QueryManager qm, final String name, final String version) {
        final var project = new Project();
        project.setName(name);
        project.setVersion(version);
        return qm.persist(project);
    }

    private static Component component(
            final QueryManager qm,
            final Project project,
            final String name,
            final String version,
            final Classifier classifier,
            final @Nullable String purl) {
        final var component = new Component();
        component.setProject(project);
        component.setName(name);
        component.setVersion(version);
        component.setClassifier(classifier);
        if (purl != null) {
            component.setPurl(purl);
        }
        return qm.persist(component);
    }

    private static void directDependencies(final String table, final long id, final List<UUID> children) {
        final var json = new StringBuilder("[");
        for (int i = 0; i < children.size(); i++) {
            if (i > 0) {
                json.append(',');
            }
            json.append("{\"uuid\":\"").append(children.get(i)).append("\"}");
        }
        json.append(']');
        final String sql = "PROJECT".equals(table) ? """
                UPDATE "PROJECT"
                   SET "DIRECT_DEPENDENCIES" = CAST(:json AS jsonb)
                 WHERE "ID" = :id
                """ : """
                UPDATE "COMPONENT"
                   SET "DIRECT_DEPENDENCIES" = CAST(:json AS jsonb)
                 WHERE "ID" = :id
                """;
        useJdbiTransaction(handle -> handle.createUpdate(sql)
                .bind("json", json.toString())
                .bind("id", id)
                .execute());
    }

    private static void comment(
            final long analysisId, final String comment, final String commenter, final Instant timestamp) {
        useJdbiTransaction(handle -> handle.createUpdate("""
                        INSERT INTO "ANALYSISCOMMENT" ("ANALYSIS_ID", "COMMENT", "COMMENTER", "TIMESTAMP")
                        VALUES (:analysisId, :comment, :commenter, :timestamp)
                        """)
                .bind("analysisId", analysisId)
                .bind("comment", comment)
                .bind("commenter", commenter)
                .bind("timestamp", OffsetDateTime.ofInstant(timestamp, java.time.ZoneOffset.UTC))
                .execute());
    }

    static long requestFull(final UUID targetUuid) {
        return inJdbiTransaction(handle -> new AssessmentSyncWorkDao(handle).requestFull(targetUuid));
    }

    static long requestFindings(final UUID targetUuid, final List<org.dependencytrack.model.FindingKey> keys) {
        return inJdbiTransaction(handle -> new AssessmentSyncWorkDao(handle).requestFindings(targetUuid, keys));
    }

    static @Nullable WorkRow work(final UUID targetUuid) {
        return withJdbiHandle(handle -> new AssessmentSyncWorkDao(handle).find(targetUuid));
    }

    static @Nullable String state(final long componentId, final long vulnerabilityId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT a."STATE"
                          FROM "ANALYSIS" AS a
                         WHERE a."COMPONENT_ID" = :componentId
                           AND a."VULNERABILITY_ID" = :vulnerabilityId
                        """)
                .bind("componentId", componentId)
                .bind("vulnerabilityId", vulnerabilityId)
                .mapTo(String.class)
                .findOne()
                .orElse(null));
    }

    static @Nullable String owner(final long componentId, final long vulnerabilityId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT o."OWNER"
                          FROM "ANALYSIS" AS a
                          LEFT JOIN "ASSESSMENT_ORIGIN" AS o
                            ON o."ANALYSIS_ID" = a."ID"
                         WHERE a."COMPONENT_ID" = :componentId
                           AND a."VULNERABILITY_ID" = :vulnerabilityId
                        """)
                .bind("componentId", componentId)
                .bind("vulnerabilityId", vulnerabilityId)
                .mapTo(String.class)
                .findOne()
                .orElse(null));
    }

    static @Nullable String details(final long componentId, final long vulnerabilityId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT a."DETAILS"
                          FROM "ANALYSIS" AS a
                         WHERE a."COMPONENT_ID" = :componentId
                           AND a."VULNERABILITY_ID" = :vulnerabilityId
                        """)
                .bind("componentId", componentId)
                .bind("vulnerabilityId", vulnerabilityId)
                .mapTo(String.class)
                .findOne()
                .orElse(null));
    }

    static List<String> contributionDetails(final long componentId, final long vulnerabilityId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT c."SOURCE_DETAILS"
                          FROM "ASSESSMENT_SOURCE_CONTRIBUTION" AS c
                         INNER JOIN "ANALYSIS" AS a
                            ON a."ID" = c."TARGET_ANALYSIS_ID"
                         WHERE a."COMPONENT_ID" = :componentId
                           AND a."VULNERABILITY_ID" = :vulnerabilityId
                         ORDER BY c."SOURCE_DETAILS"
                        """)
                .bind("componentId", componentId)
                .bind("vulnerabilityId", vulnerabilityId)
                .mapTo(String.class)
                .list());
    }

    static int contributionCount(final long componentId, final long vulnerabilityId) {
        return contributionDetails(componentId, vulnerabilityId).size();
    }

    static List<String> localComments(final long componentId, final long vulnerabilityId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT ac."COMMENT"
                          FROM "ANALYSISCOMMENT" AS ac
                         INNER JOIN "ANALYSIS" AS a
                            ON a."ID" = ac."ANALYSIS_ID"
                         WHERE a."COMPONENT_ID" = :componentId
                           AND a."VULNERABILITY_ID" = :vulnerabilityId
                         ORDER BY ac."ID"
                        """)
                .bind("componentId", componentId)
                .bind("vulnerabilityId", vulnerabilityId)
                .mapTo(String.class)
                .list());
    }

    static @Nullable Instant copiedCommentTimestamp(final long componentId, final long vulnerabilityId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT m."ORIGINAL_TIMESTAMP"
                          FROM "ASSESSMENT_SOURCE_COMMENT" AS m
                         INNER JOIN "ANALYSIS" AS a
                            ON a."ID" = m."TARGET_ANALYSIS_ID"
                         WHERE a."COMPONENT_ID" = :componentId
                           AND a."VULNERABILITY_ID" = :vulnerabilityId
                           AND m."COMMENT" = :comment
                        """)
                .bind("componentId", componentId)
                .bind("vulnerabilityId", vulnerabilityId)
                .bind("comment", ALPINE_NOTE)
                .map((rs, ctx) ->
                        rs.getObject("ORIGINAL_TIMESTAMP", OffsetDateTime.class).toInstant())
                .findOne()
                .orElse(null));
    }
}
