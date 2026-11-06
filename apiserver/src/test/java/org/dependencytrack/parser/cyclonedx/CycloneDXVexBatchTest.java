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
package org.dependencytrack.parser.cyclonedx;

import org.cyclonedx.model.Bom;
import org.cyclonedx.parsers.BomParserFactory;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.analysis.AnalysisMutationPlanner;
import org.dependencytrack.analysis.AnalysisWriter;
import org.dependencytrack.assessmentsync.AssessmentOriginDao;
import org.dependencytrack.assessmentsync.AssessmentOwnership;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.jdbi.v3.core.statement.SqlLogger;
import org.jdbi.v3.core.statement.SqlStatements;
import org.jdbi.v3.core.statement.StatementContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.assessmentsync.AssessmentSyncTestSupport.recordedChanges;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.createJdbi;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class CycloneDXVexBatchTest extends PersistenceCapableTest {

    @AfterEach
    void resetMode() {
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
    }

    @Test
    void writingMoreDistinctFindingsUsesTheSameNumberOfJdbiStatements() throws Exception {
        final var small = fixture(2, "[{\"ref\":\"project\"}]");
        final var large = fixture(4, "[{\"ref\":\"project\"}]");
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        final int smallCount = applyCountingStatements(small);
        final int largeCount = applyCountingStatements(large);
        assertThat(smallCount).isPositive();
        assertThat(largeCount).isEqualTo(smallCount);
        assertThat(recordedChanges(small.project().getUuid())).hasSize(2);
        assertThat(recordedChanges(large.project().getUuid())).hasSize(4);
        for (final var component : large.components()) {
            final var analysis = qm.getAnalysis(component, large.vulnerability());
            assertThat(analysis.isSuppressed()).isTrue();
            final var origin = withJdbiHandle(handle -> new AssessmentOriginDao(handle).findOrigin(analysis.getId()));
            assertThat(origin.owner()).isEqualTo(AssessmentOwnership.LOCAL);
            assertThat(origin.decisionVersion()).isEqualTo(1);
            assertThat(analysis.getAnalysisComments()).hasSize(2);
        }
    }

    @Test
    void overlappingAffectsAreAppliedOnlyOncePerVexEntry() throws Exception {
        final var single = fixture(2, "[{\"ref\":\"project\"}]");
        final var duplicate = fixture(2, "[{\"ref\":\"project\"},{\"ref\":\"project\"}]");
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        assertThat(applyCountingStatements(duplicate)).isEqualTo(applyCountingStatements(single));
        assertThat(recordedChanges(duplicate.project().getUuid())).hasSize(2);
    }

    @Test
    void batchBoundaryKeepsEveryFinding() throws Exception {
        final var data = fixture(251, "[{\"ref\":\"project\"}]");
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        new CycloneDXVexImporter().applyVex(qm, data.bom(), data.project());
        assertThat(recordedChanges(data.project().getUuid())).hasSize(251);
        for (final var component :
                List.of(data.components().getFirst(), data.components().getLast())) {
            assertThat(qm.getAnalysis(component, data.vulnerability()).isSuppressed())
                    .isTrue();
        }
    }

    @Test
    void callerRollbackRemovesEveryBatchEffect() throws Exception {
        final var data = fixture(3, "[{\"ref\":\"project\"}]");
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        assertThatThrownBy(() -> qm.runInTransaction(() -> {
                    new CycloneDXVexImporter().applyVex(qm, data.bom(), data.project());
                    throw new IllegalStateException("rollback");
                }))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("rollback");
        assertThat(recordedChanges(data.project().getUuid())).isEmpty();
        for (final var component : data.components()) {
            assertThat(qm.getAnalysis(component, data.vulnerability())).isNull();
        }
    }

    @Test
    void componentScopedVexCannotCreateAnAnalysisForAnUnattributedFinding() throws Exception {
        final var data = fixture(1, "[{\"ref\":\"component\"}]");
        final var other = new Component();
        other.setName("unaffected");
        other.setVersion("1");
        other.setProject(data.project());
        final var unassigned = qm.createComponent(other, false);
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        new CycloneDXVexImporter().applyVex(qm, data.bom(), data.project());
        assertThat(qm.getAnalysis(unassigned, data.vulnerability())).isNull();
        assertThat(recordedChanges(data.project().getUuid())).isEmpty();
    }

    @Test
    void batchWriterIgnoresEmptyInputAndRejectsRepeatedFindingsBeforeAnySql() throws Exception {
        final var data = fixture(1, "[{\"ref\":\"project\"}]");
        final var component = data.components().getFirst();
        final var finding = new AnalysisWriter.Finding(
                data.project().getId(),
                data.project().getUuid(),
                data.project().getName(),
                data.project().getVersion(),
                component.getId(),
                component.getUuid(),
                data.vulnerability().getId(),
                data.vulnerability().getUuid());
        final var request = new AnalysisMutationPlanner.Request(
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                Set.of(),
                MakeAnalysisCommand.DecisionAction.AUTO,
                null);
        final var entry = new AnalysisWriter.Entry(request, finding, "test");
        try (final var handle = openJdbiHandle()) {
            assertThat(AnalysisWriter.writeAll(handle, List.of())).isEmpty();
            // No transaction is open: duplicate validation must fail before attempting to lock or write.
            assertThatThrownBy(() -> AnalysisWriter.writeAll(handle, List.of(entry, entry)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("each finding only once");
        }
        assertThat(qm.getAnalysis(component, data.vulnerability())).isNull();
        assertThat(recordedChanges(data.project().getUuid())).isEmpty();
    }

    @Test
    void repeatedDecisionsForOneFindingKeepTheirOrderVersionsAndAuditTrail() throws Exception {
        final var data = fixture(1, "[{\"ref\":\"project\"}]");
        final var bytes = ("""
                {"bomFormat":"CycloneDX","specVersion":"1.4","version":1,
                 "metadata":{"component":{"type":"application","bom-ref":"project","name":"app"}},
                 "vulnerabilities":[
                  {"id":"%1$s","source":{"name":"INTERNAL"},"analysis":{"state":"not_affected"},"affects":[{"ref":"project"}]},
                  {"id":"%1$s","source":{"name":"INTERNAL"},"analysis":{"state":"exploitable"},"affects":[{"ref":"project"}]}]}
                """).formatted(data.vulnerability().getVulnId()).getBytes(StandardCharsets.UTF_8);
        final var bom = BomParserFactory.createParser(bytes).parse(bytes);
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        new CycloneDXVexImporter().applyVex(qm, bom, data.project());
        final var analysis = qm.getAnalysis(data.components().getFirst(), data.vulnerability());
        assertThat(analysis.getAnalysisState()).isEqualTo(AnalysisState.EXPLOITABLE);
        assertThat(analysis.isSuppressed()).isFalse();
        assertThat(analysis.getAnalysisComments())
                .extracting(AnalysisComment::getComment)
                .containsExactly(
                        "Analysis: NOT_SET → NOT_AFFECTED",
                        "Suppressed",
                        "Analysis: NOT_AFFECTED → EXPLOITABLE",
                        "Unsuppressed");
        assertThat(withJdbiHandle(handle -> new AssessmentOriginDao(handle).findOrigin(analysis.getId()))
                        .decisionVersion())
                .isEqualTo(2);
        assertThat(recordedChanges(data.project().getUuid())).hasSize(1);
    }

    private int applyCountingStatements(final Fixture data) {
        final var count = new AtomicInteger();
        final var jdbi = createJdbi();
        final var previous = jdbi.getConfig(SqlStatements.class).getSqlLogger();
        jdbi.setSqlLogger(new SqlLogger() {
            @Override
            public void logAfterExecution(final StatementContext context) {
                count.incrementAndGet();
            }
        });
        try {
            new CycloneDXVexImporter().applyVex(qm, data.bom(), data.project());
        } finally {
            jdbi.setSqlLogger(previous);
        }
        return count.get();
    }

    private Fixture fixture(final int count, final String affects) throws Exception {
        final var project = new Project();
        project.setName("batch-" + UUID.randomUUID());
        project.setVersion("1");
        final var persisted = qm.persist(project);
        final var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-" + UUID.randomUUID());
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        final var vuln = qm.persist(vulnerability);
        final var components = new ArrayList<Component>();
        for (int i = 0; i < count; i++) {
            final var component = new Component();
            component.setName("component-" + i);
            component.setVersion("1");
            component.setProject(persisted);
            final var c = qm.createComponent(component, false);
            qm.addVulnerability(vuln, c, "none");
            components.add(c);
        }
        final var bytes = ("""
                {"bomFormat":"CycloneDX","specVersion":"1.4","version":1,
                 "metadata":{"component":{"type":"application","bom-ref":"project","name":"app","version":"1"}},
                 "components":[{"type":"library","bom-ref":"component","name":"unaffected","version":"1"}],
                 "vulnerabilities":[{"id":"%s","source":{"name":"INTERNAL"},
                 "analysis":{"state":"not_affected"},"affects":%s}]}
                """).formatted(vuln.getVulnId(), affects).getBytes(StandardCharsets.UTF_8);
        return new Fixture(
                persisted,
                vuln,
                components,
                BomParserFactory.createParser(bytes).parse(bytes));
    }

    private record Fixture(Project project, Vulnerability vulnerability, List<Component> components, Bom bom) {}
}
