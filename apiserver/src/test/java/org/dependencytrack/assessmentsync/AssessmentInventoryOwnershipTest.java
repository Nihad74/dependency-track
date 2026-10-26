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
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisComment;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.FindingAttribution;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.junit.jupiter.api.Test;

import java.util.EnumSet;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Characterizes today's inventory. Synchronization is not implemented here.
 * The product and the source share a package URL and a vulnerability, and they
 * remain separate projects, components, and analysis rows.
 */
class AssessmentInventoryOwnershipTest extends PersistenceCapableTest {

    private static final String SHARED_PACKAGE_PURL = "pkg:deb/debian/libc6@2.36";
    private static final String MARKER_CPE = "cpe:2.3:o:linux:linux_kernel:5.14.121:*:*:*:*:*:*:*";
    private static final String SOURCE_COMMENT = "Kernel package is not affected in this build";

    @Test
    void shouldCharacterizeSeparateInventoryAndAnalysisOwnership() {
        final Project organizationalParent = persistProject("mrt.base.linux", "scarthgap", null);
        final Project sourceVersion = persistProject("mrt.base.linux", "5.14.121", organizationalParent);
        final Project secondSource = persistProject("mrt.other.firmware", "1.4.0", null);
        final Project productFamily = persistProject("cmx-family", "portfolio", null);
        final Project targetProduct = persistProject("cmx500", "1.0.0", productFamily);
        final Project secondTarget = persistProject("cmx900", "2.0.0", null);

        final Component sourcePackage = persistPackage(sourceVersion, "libc6", "2.36", SHARED_PACKAGE_PURL);
        final Component secondSourcePackage =
                persistPackage(secondSource, "busybox", "1.36.1", "pkg:generic/busybox@1.36.1");

        final Component marker = new Component();
        marker.setProject(targetProduct);
        marker.setName("mrt.base.linux");
        marker.setVersion("5.14.121");
        marker.setClassifier(Classifier.OPERATING_SYSTEM);
        marker.setCpe(MARKER_CPE);
        final Component persistedMarker = qm.persist(marker);

        final Component targetPackage = persistPackage(targetProduct, "libc6", "2.36", SHARED_PACKAGE_PURL);
        final Component neutralPackage =
                persistPackage(targetProduct, "libssl", "3.0.11", "pkg:deb/debian/libssl@3.0.11");

        sourceVersion.setDirectDependencies(dependencyEdge(sourcePackage.getUuid()));
        persistedMarker.setDirectDependencies(dependencyEdge(targetPackage.getUuid(), neutralPackage.getUuid()));
        targetProduct.setDirectDependencies(dependencyEdge(persistedMarker.getUuid()));
        qm.persist(sourceVersion);
        qm.persist(persistedMarker);
        qm.persist(targetProduct);

        final Vulnerability sharedVulnerability = persistVulnerability("CVE-2099-1210");
        final Vulnerability secondSourceVulnerability = persistVulnerability("CVE-2099-4401");
        qm.addVulnerability(sharedVulnerability, sourcePackage, "internal");
        qm.addVulnerability(sharedVulnerability, targetPackage, "internal");
        qm.addVulnerability(sharedVulnerability, neutralPackage, "internal");
        qm.addVulnerability(secondSourceVulnerability, secondSourcePackage, "internal");

        qm.makeAnalysis(new MakeAnalysisCommand(sourcePackage, sharedVulnerability)
                .withState(AnalysisState.NOT_AFFECTED)
                .withCommenter("source-maintainer")
                .withComment(SOURCE_COMMENT)
                .withOptions(EnumSet.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        qm.makeAnalysis(new MakeAnalysisCommand(targetPackage, sharedVulnerability)
                .withState(AnalysisState.EXPLOITABLE)
                .withCommenter("product-owner")
                .withComment("Local product override")
                .withOptions(EnumSet.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        qm.makeAnalysis(new MakeAnalysisCommand(neutralPackage, sharedVulnerability)
                .withState(AnalysisState.NOT_SET)
                .withCommenter("product-owner")
                .withComment("Recorded without a decision")
                .withOptions(EnumSet.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        qm.makeAnalysis(new MakeAnalysisCommand(secondSourcePackage, secondSourceVulnerability)
                .withState(AnalysisState.IN_TRIAGE)
                .withCommenter("other-source-maintainer")
                .withComment("Firmware is still in triage")
                .withOptions(EnumSet.of(MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));

        qm.getPersistenceManager().refresh(organizationalParent);
        qm.getPersistenceManager().refresh(sourceVersion);
        qm.getPersistenceManager().refresh(secondSource);
        qm.getPersistenceManager().refresh(targetProduct);
        qm.getPersistenceManager().refresh(secondTarget);
        qm.getPersistenceManager().refresh(persistedMarker);
        qm.getPersistenceManager().refresh(sourcePackage);
        qm.getPersistenceManager().refresh(targetPackage);

        final Analysis sourceAnalysis = qm.getAnalysis(sourcePackage, sharedVulnerability);
        final Analysis targetOverride = qm.getAnalysis(targetPackage, sharedVulnerability);
        final Analysis neutralAnalysis = qm.getAnalysis(neutralPackage, sharedVulnerability);
        final Analysis secondSourceAnalysis = qm.getAnalysis(secondSourcePackage, secondSourceVulnerability);

        assertThat(sourcePackage.getUuid()).isNotEqualTo(targetPackage.getUuid());
        assertThat(sourcePackage.getPurlAsString())
                .isEqualTo(SHARED_PACKAGE_PURL)
                .isEqualTo(targetPackage.getPurlAsString());
        assertThat(sourcePackage.getProject().getUuid())
                .isNotEqualTo(targetPackage.getProject().getUuid());
        assertThat(sourcePackage.getProject().getUuid()).isEqualTo(sourceVersion.getUuid());
        assertThat(targetPackage.getProject().getUuid()).isEqualTo(targetProduct.getUuid());

        assertThat(targetProduct.getParent()).isNotNull();
        assertThat(targetProduct.getParent().getUuid())
                .isNotEqualTo(organizationalParent.getUuid())
                .isNotEqualTo(sourceVersion.getUuid());
        assertThat(targetProduct.getParent().getName()).isEqualTo("cmx-family");
        assertThat(targetProduct.getParent().getVersion()).isEqualTo("portfolio");
        assertThat(sourceVersion.getParent()).isNotNull();
        assertThat(sourceVersion.getParent().getUuid()).isEqualTo(organizationalParent.getUuid());
        assertThat(sourceVersion.getParent().getName()).isEqualTo("mrt.base.linux");
        assertThat(sourceVersion.getParent().getVersion()).isEqualTo("scarthgap");
        assertThat(secondSource.getParent()).isNull();
        assertThat(secondTarget.getParent()).isNull();

        assertThat(persistedMarker.getClassifier()).isEqualTo(Classifier.OPERATING_SYSTEM);
        assertThat(persistedMarker.getName()).isEqualTo(sourceVersion.getName()).isEqualTo("mrt.base.linux");
        assertThat(persistedMarker.getVersion())
                .isEqualTo(sourceVersion.getVersion())
                .isEqualTo("5.14.121");
        assertThat(persistedMarker.getCpe()).isEqualTo(MARKER_CPE);
        assertThat(persistedMarker.getPurl()).isNull();
        assertThat(persistedMarker.getPurlAsString()).isNull();
        assertThat(persistedMarker.getParent()).isNull();
        assertThat(targetPackage.getParent()).isNull();

        assertThat(sourceAnalysis).isNotNull();
        assertThat(targetOverride).isNotNull();
        assertThat(sourceAnalysis.getId()).isPositive().isNotEqualTo(targetOverride.getId());
        assertThat(sourceAnalysis.getComponent().getId())
                .isEqualTo(sourcePackage.getId())
                .isNotEqualTo(targetOverride.getComponent().getId());
        assertThat(targetOverride.getComponent().getId()).isEqualTo(targetPackage.getId());
        assertThat(sourceAnalysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(targetOverride.getAnalysisState()).isEqualTo(AnalysisState.EXPLOITABLE);
        assertThat(sourceAnalysis.getAnalysisComments())
                .extracting(AnalysisComment::getComment)
                .contains(SOURCE_COMMENT);

        final long sourceAnalysisId = sourceAnalysis.getId();
        final long targetOverrideId = targetOverride.getId();
        final AnalysisState sourceStateBeforeRead = sourceAnalysis.getAnalysisState();
        final AnalysisState targetStateBeforeRead = targetOverride.getAnalysisState();
        qm.getPersistenceManager().evict(sourceAnalysis);
        qm.getPersistenceManager().evict(targetOverride);

        final Analysis rereadSource = qm.getAnalysis(sourcePackage, sharedVulnerability);
        assertThat(rereadSource.getId()).isEqualTo(sourceAnalysisId);
        assertThat(rereadSource.getAnalysisState()).isEqualTo(sourceStateBeforeRead);
        assertThat(rereadSource.getAnalysisComments())
                .extracting(AnalysisComment::getComment)
                .contains(SOURCE_COMMENT);

        final Analysis rereadOverride = qm.getAnalysis(targetPackage, sharedVulnerability);
        assertThat(rereadOverride.getId()).isEqualTo(targetOverrideId);
        assertThat(rereadOverride.getAnalysisState()).isEqualTo(targetStateBeforeRead);
        assertThat(rereadOverride.getComponent().getId()).isEqualTo(targetPackage.getId());
        assertThat(rereadSource.getComponent().getId())
                .isEqualTo(sourcePackage.getId())
                .isNotEqualTo(rereadOverride.getComponent().getId());

        assertThat(neutralAnalysis).isNotNull();
        assertThat(neutralAnalysis.getId()).isPositive();
        assertThat(neutralAnalysis.getAnalysisState()).isEqualTo(AnalysisState.NOT_SET);
        assertThat(neutralAnalysis.getComponent().getId()).isEqualTo(neutralPackage.getId());
        assertThat(neutralAnalysis.getVulnerability().getUuid()).isEqualTo(sharedVulnerability.getUuid());

        assertThat(secondSource.getUuid())
                .isNotEqualTo(sourceVersion.getUuid())
                .isNotEqualTo(targetProduct.getUuid())
                .isNotEqualTo(secondTarget.getUuid());
        assertThat(secondTarget.getUuid())
                .isNotEqualTo(targetProduct.getUuid())
                .isNotEqualTo(sourceVersion.getUuid())
                .isNotEqualTo(organizationalParent.getUuid());
        assertThat(secondSource.getName()).isEqualTo("mrt.other.firmware");
        assertThat(secondSource.getVersion()).isEqualTo("1.4.0");
        assertThat(secondTarget.getName()).isEqualTo("cmx900");
        assertThat(secondTarget.getVersion()).isEqualTo("2.0.0");
        assertThat(secondSourcePackage.getUuid())
                .isNotEqualTo(sourcePackage.getUuid())
                .isNotEqualTo(targetPackage.getUuid());
        assertThat(secondSourceAnalysis).isNotNull();
        assertThat(secondSourceAnalysis.getId()).isPositive();
        assertThat(secondSourceAnalysis.getAnalysisState()).isEqualTo(AnalysisState.IN_TRIAGE);
        assertThat(sourceVersion.getParent().getUuid()).isNotEqualTo(secondSource.getUuid());

        assertThat(persistedMarker.getName()).isEqualTo(sourceVersion.getName());
        assertThat(persistedMarker.getVersion()).isEqualTo(sourceVersion.getVersion());
        assertThat(persistedMarker.getUuid()).isNotEqualTo(sourceVersion.getUuid());
        assertThat(targetProduct.getParent().getId()).isNotEqualTo(sourceVersion.getId());
        assertThat(targetProduct.getParent().getId()).isNotEqualTo(organizationalParent.getId());
        assertThat(sourceVersion.getParent().getId()).isEqualTo(organizationalParent.getId());
        assertThat(targetProduct.getDirectDependencies())
                .contains(persistedMarker.getUuid().toString());
        assertThat(targetProduct.getDirectDependencies())
                .doesNotContain(sourceVersion.getUuid().toString());
        assertThat(targetProduct.getDirectDependencies())
                .doesNotContain(sourcePackage.getUuid().toString());
        assertThat(persistedMarker.getDirectDependencies())
                .contains(targetPackage.getUuid().toString());
        assertThat(persistedMarker.getDirectDependencies())
                .contains(neutralPackage.getUuid().toString());
        assertThat(persistedMarker.getDirectDependencies())
                .doesNotContain(sourcePackage.getUuid().toString());

        assertActiveFinding(sharedVulnerability, sourcePackage);
        assertActiveFinding(sharedVulnerability, targetPackage);
        assertActiveFinding(sharedVulnerability, neutralPackage);
        assertActiveFinding(secondSourceVulnerability, secondSourcePackage);
    }

    private void assertActiveFinding(final Vulnerability vulnerability, final Component component) {
        assertThat(qm.getFindingAttributions(vulnerability, component))
                .isNotEmpty()
                .extracting(FindingAttribution::getDeletedAt)
                .containsOnlyNulls();
    }

    private Project persistProject(final String name, final String version, final Project parent) {
        final var project = new Project();
        project.setName(name);
        project.setVersion(version);
        project.setParent(parent);
        return qm.persist(project);
    }

    private Component persistPackage(
            final Project project, final String name, final String version, final String purl) {
        final var component = new Component();
        component.setProject(project);
        component.setName(name);
        component.setVersion(version);
        component.setClassifier(Classifier.LIBRARY);
        component.setPurl(purl);
        return qm.persist(component);
    }

    private Vulnerability persistVulnerability(final String vulnId) {
        final var vulnerability = new Vulnerability();
        vulnerability.setVulnId(vulnId);
        vulnerability.setSource(Vulnerability.Source.NVD);
        vulnerability.setSeverity(Severity.HIGH);
        return qm.persist(vulnerability);
    }

    private static String dependencyEdge(final UUID... dependencyUuids) {
        final var edges = new StringBuilder("[");
        for (int i = 0; i < dependencyUuids.length; i++) {
            if (i > 0) {
                edges.append(',');
            }
            edges.append("{\"uuid\":\"").append(dependencyUuids[i]).append("\"}");
        }
        edges.append(']');
        return edges.toString();
    }
}
