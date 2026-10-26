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
package org.dependencytrack.persistence;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.assessmentsync.AssessmentSyncMode;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class AnalysisAuthorshipTest extends PersistenceCapableTest {

    @AfterEach
    void clearMode() {
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
    }

    @Test
    void rollbackLeavesNoAnalysisOriginCommentOrOutbox() {
        final Finding finding = finding();
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");

        assertThatThrownBy(() -> qm.callInTransaction(() -> {
                    qm.makeAnalysis(new MakeAnalysisCommand(finding.component(), finding.vulnerability())
                            .withState(AnalysisState.NOT_AFFECTED)
                            .withComment("should roll back")
                            .withCommenter("Jane")
                            .withOptions(EnumSet.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
                    throw new IllegalStateException("force rollback");
                }))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("force rollback");

        assertThat(analysisCount(finding.componentId())).isZero();
        assertThat(originCount(finding.componentId())).isZero();
        assertThat(commentCount(finding.componentId())).isZero();
        assertThat(outboxCount(finding.projectUuid())).isZero();
    }

    @Test
    void modeOffWritesAnalysisWithoutOutbox() {
        final Finding finding = finding();

        qm.makeAnalysis(new MakeAnalysisCommand(finding.component(), finding.vulnerability())
                .withState(AnalysisState.NOT_AFFECTED)
                .withOptions(EnumSet.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));

        assertThat(qm.getAnalysis(finding.component(), finding.vulnerability()).getAnalysisState())
                .isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(outboxCount(finding.projectUuid())).isZero();
    }

    @Test
    void withdrawWritesAnalysisWithoutOutbox() {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "WITHDRAW");
        final Finding finding = finding();

        qm.makeAnalysis(new MakeAnalysisCommand(finding.component(), finding.vulnerability())
                .withState(AnalysisState.NOT_AFFECTED)
                .withOptions(EnumSet.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));

        assertThat(qm.getAnalysis(finding.component(), finding.vulnerability()).getAnalysisState())
                .isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(outboxCount(finding.projectUuid())).isZero();
    }

    @Test
    void equalValueVexStillRecordsOneOutboxRow() {
        final Finding finding = finding();
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        final MakeAnalysisCommand command = new MakeAnalysisCommand(finding.component(), finding.vulnerability())
                .withState(AnalysisState.NOT_AFFECTED)
                .withDecisionAction(MakeAnalysisCommand.DecisionAction.VEX)
                .withOptions(EnumSet.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION));

        qm.makeAnalysis(command);
        qm.makeAnalysis(command);

        assertThat(owner(finding.componentId())).isEqualTo("LOCAL");
        assertThat(outboxCount(finding.projectUuid())).isEqualTo(2);
    }

    @Test
    void unknownModeIsRejected() {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "NOPE");

        assertThatThrownBy(AssessmentSyncMode::current)
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("dt.assessment-sync.mode")
                .hasMessageContaining("NOPE");
    }

    private Finding finding() {
        final Project project = qm.createProject("Acme Example", null, "1.0", null, null, null, null, false);
        var component = new Component();
        component.setProject(project);
        component.setName("Acme Component");
        component.setVersion("1.0");
        component = qm.createComponent(component, false);
        var vulnerability = new Vulnerability();
        vulnerability.setVulnId("INT-AUTHOR");
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        vulnerability = qm.createVulnerability(vulnerability);
        return new Finding(project.getUuid(), component, component.getId(), vulnerability);
    }

    private static int analysisCount(final long componentId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT COUNT(*)::int
                          FROM "ANALYSIS"
                         WHERE "COMPONENT_ID" = :componentId
                        """)
                .bind("componentId", componentId)
                .mapTo(int.class)
                .one());
    }

    private static int originCount(final long componentId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT COUNT(*)::int
                          FROM "ASSESSMENT_ORIGIN" AS origin
                         INNER JOIN "ANALYSIS" AS analysis
                            ON analysis."ID" = origin."ANALYSIS_ID"
                         WHERE analysis."COMPONENT_ID" = :componentId
                        """)
                .bind("componentId", componentId)
                .mapTo(int.class)
                .one());
    }

    private static int commentCount(final long componentId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT COUNT(*)::int
                          FROM "ANALYSISCOMMENT" AS comment
                         INNER JOIN "ANALYSIS" AS analysis
                            ON analysis."ID" = comment."ANALYSIS_ID"
                         WHERE analysis."COMPONENT_ID" = :componentId
                        """)
                .bind("componentId", componentId)
                .mapTo(int.class)
                .one());
    }

    private static int outboxCount(final UUID projectUuid) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT COUNT(*)::int
                          FROM "ASSESSMENT_SYNC_OUTBOX"
                         WHERE "PROJECT_UUID" = :projectUuid
                        """)
                .bind("projectUuid", projectUuid)
                .mapTo(int.class)
                .one());
    }

    private static String owner(final long componentId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT origin."OWNER"
                          FROM "ASSESSMENT_ORIGIN" AS origin
                         INNER JOIN "ANALYSIS" AS analysis
                            ON analysis."ID" = origin."ANALYSIS_ID"
                         WHERE analysis."COMPONENT_ID" = :componentId
                        """)
                .bind("componentId", componentId)
                .mapTo(String.class)
                .one());
    }

    private record Finding(UUID projectUuid, Component component, long componentId, Vulnerability vulnerability) {}
}
