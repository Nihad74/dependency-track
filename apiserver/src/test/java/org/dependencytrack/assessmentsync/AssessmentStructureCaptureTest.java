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
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.jdbi.v3.core.statement.SqlLogger;
import org.jdbi.v3.core.statement.StatementContext;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.assessmentsync.AssessmentSyncTestSupport.embeddings;
import static org.dependencytrack.assessmentsync.AssessmentSyncTestSupport.recordedChanges;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

class AssessmentStructureCaptureTest extends PersistenceCapableTest {

    @AfterEach
    void resetMode() {
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
    }

    @Test
    void lookupKeysAreCompleteDistinctOrderedAndImmutable() {
        assertThat(AssessmentStructureCapture.keys("old", "1", "new", "2"))
                .containsExactly(new LookupKey("old", "1"), new LookupKey("new", "2"));
        assertThat(AssessmentStructureCapture.keys("same", "1", "same", "1"))
                .containsExactly(new LookupKey("same", "1"));
        assertThat(AssessmentStructureCapture.keys(null, "1", "new", null)).isEmpty();
        assertThatThrownBy(() ->
                        AssessmentStructureCapture.keys("old", "1", "new", "2").clear())
                .isInstanceOf(UnsupportedOperationException.class);
    }

    @ParameterizedTest
    @ValueSource(strings = {"OFF", "WITHDRAW"})
    void disabledModesSkipAllStructuralQueries(final String mode) {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, mode);
        useJdbiTransaction(handle -> {
            final var statements = new AtomicInteger();
            handle.setSqlLogger(new SqlLogger() {
                @Override
                public void logAfterExecution(final StatementContext context) {
                    statements.incrementAndGet();
                }
            });
            final UUID project = UUID.randomUUID();
            AssessmentStructureCapture.rebuildAndRecord(handle, project, Reason.BOM_IMPORT, List.of());
            AssessmentStructureCapture.recordProject(handle, project, Reason.PROJECT_UPDATED, List.of());
            AssessmentStructureCapture.recordAttributionChanges(
                    handle, project, List.of(new AssessmentStructureCapture.FindingRef(1, 2)));
            AssessmentStructureCapture.recordAccessChange(handle, List.of(project));
            AssessmentStructureCapture.recordTeamAccessRemoved(handle, 1);
            AssessmentStructureCapture.recordAccessControlToggled(handle);
            assertThat(statements.get()).isZero();
        });
        assertThat(recordedChanges()).isEmpty();
    }

    @Test
    void attributionsDeduplicateAndIgnoreOtherProjectsOrMissingRows() {
        final var project = project("one", null);
        final var other = project("other", null);
        final var component = component(project, "library", Classifier.LIBRARY);
        final var foreign = component(other, "foreign", Classifier.LIBRARY);
        final var vuln = new Vulnerability();
        vuln.setVulnId("INT-CAPTURE");
        vuln.setSource(Vulnerability.Source.INTERNAL);
        final var vulnerability = qm.persist(vuln);
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        useJdbiTransaction(handle -> {
            final var valid = new AssessmentStructureCapture.FindingRef(component.getId(), vulnerability.getId());
            AssessmentStructureCapture.recordAttributionChanges(
                    handle,
                    project.getUuid(),
                    List.of(
                            valid,
                            valid,
                            new AssessmentStructureCapture.FindingRef(foreign.getId(), vulnerability.getId()),
                            new AssessmentStructureCapture.FindingRef(component.getId(), Long.MAX_VALUE)));
            AssessmentStructureCapture.recordAttributionChanges(handle, project.getUuid(), List.of());
        });
        assertThat(recordedChanges()).singleElement().satisfies(change -> {
            assertThat(change.componentUuid()).isEqualTo(component.getUuid());
            assertThat(change.vulnerabilityUuid()).isEqualTo(vulnerability.getUuid());
            assertThat(change.reason()).isEqualTo(Reason.ATTRIBUTION);
            assertThat(change.lookupKeys()).containsExactly(new LookupKey("one", "1"));
        });
    }

    @Test
    void accessChangeIncludesRootsAndAllDescendantsOnlyOnce() {
        final var root = project("root", null);
        final var child = project("child", root);
        final var grandchild = project("grandchild", child);
        project("unrelated", null);
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "ACTIVE");
        useJdbiTransaction(handle -> {
            AssessmentStructureCapture.recordAccessChange(
                    handle, List.of(root.getUuid(), child.getUuid(), UUID.randomUUID()));
            AssessmentStructureCapture.recordAccessChange(handle, List.of());
        });
        assertThat(recordedChanges())
                .extracting(AssessmentChange::projectUuid)
                .containsExactlyInAnyOrder(root.getUuid(), child.getUuid(), grandchild.getUuid());
        assertThat(recordedChanges())
                .allSatisfy(change -> assertThat(change.reason()).isEqualTo(Reason.ACCESS_CHANGED));
    }

    @Test
    void aclToggleRecordsEveryMarkerTargetAndNoUnrelatedProjects() {
        final var target = project("target", null);
        project("unrelated", null);
        final var marker = component(target, "embedded", Classifier.OPERATING_SYSTEM);
        target.setDirectDependencies("[{\"uuid\":\"" + marker.getUuid() + "\"}]");
        qm.persist(target);
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        useJdbiTransaction(handle -> {
            new AssessmentEmbeddingIndexer(handle).rebuild(target.getUuid());
            AssessmentStructureCapture.recordAccessControlToggled(handle);
        });
        assertThat(recordedChanges()).singleElement().satisfies(change -> {
            assertThat(change.projectUuid()).isEqualTo(target.getUuid());
            assertThat(change.reason()).isEqualTo(Reason.ACCESS_CHANGED);
        });
    }

    @Test
    void embeddingReplacementAndCaptureRollBackTogether() {
        final var target = project("target", null);
        final var marker = component(target, "embedded", Classifier.OPERATING_SYSTEM);
        target.setDirectDependencies("[{\"uuid\":\"" + marker.getUuid() + "\"}]");
        qm.persist(target);
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "ACTIVE");
        assertThatThrownBy(() -> useJdbiTransaction(handle -> {
                    AssessmentStructureCapture.rebuildAndRecord(
                            handle,
                            target.getUuid(),
                            Reason.COMPONENT_CHANGED,
                            LookupKey.listOf(target.getName(), target.getVersion()));
                    assertThat(new AssessmentEmbeddingDao(handle).findByMarkerNameAndVersion("embedded", "1"))
                            .hasSize(1);
                    throw new IllegalStateException("rollback");
                }))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("rollback");
        assertThat(recordedChanges()).isEmpty();
        assertThat(embeddings(target.getUuid(), "embedded", "1")).isEmpty();
    }

    private Project project(final String name, final Project parent) {
        final var project = new Project();
        project.setName(name);
        project.setVersion("1");
        project.setParent(parent);
        return qm.persist(project);
    }

    private Component component(final Project project, final String name, final Classifier classifier) {
        final var component = new Component();
        component.setProject(project);
        component.setName(name);
        component.setVersion("1");
        component.setClassifier(classifier);
        return qm.createComponent(component, false);
    }
}
