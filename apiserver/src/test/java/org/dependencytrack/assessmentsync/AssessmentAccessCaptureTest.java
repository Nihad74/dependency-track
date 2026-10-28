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
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.model.Project;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

/// Access changes decide source eligibility (ADR 044), so they must reach every project whose access changed.
class AssessmentAccessCaptureTest extends PersistenceCapableTest {

    @BeforeEach
    void captureMode() {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
    }

    @AfterEach
    void clearMode() {
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
    }

    @Test
    void accessChangeReachesTheProjectAndEveryDescendant() {
        final Project root = persistProject("platform", "all", null);
        final Project child = persistProject("mrt.base.linux", "scarthgap", root);
        final Project grandchild = persistProject("mrt.base.linux", "5.14.121", child);
        final Project unrelated = persistProject("cmx500", "1.0.0", null);

        useJdbiTransaction(handle -> AssessmentStructureCapture.recordAccessChange(handle, List.of(root.getUuid())));

        assertThat(accessChangedProjects())
                .containsExactlyInAnyOrder(root.getUuid(), child.getUuid(), grandchild.getUuid())
                .doesNotContain(unrelated.getUuid());
    }

    @Test
    void parentChangeRecordsTheMovedSubtree() {
        final Project oldParent = persistProject("family-a", "all", null);
        final Project newParent = persistProject("family-b", "all", null);
        final Project moved = persistProject("mrt.base.linux", "scarthgap", oldParent);
        final Project movedChild = persistProject("mrt.base.linux", "5.14.121", moved);

        final var transientProject = new Project();
        transientProject.setUuid(moved.getUuid());
        transientProject.setName(moved.getName());
        transientProject.setVersion(moved.getVersion());
        transientProject.setActive(true);
        transientProject.setParent(newParent);
        qm.updateProject(transientProject, false);

        assertThat(accessChangedProjects()).containsExactlyInAnyOrder(moved.getUuid(), movedChild.getUuid());
    }

    @Test
    void unchangedParentRecordsNoAccessChange() {
        final Project parent = persistProject("family-a", "all", null);
        final Project project = persistProject("mrt.base.linux", "scarthgap", parent);

        final var transientProject = new Project();
        transientProject.setUuid(project.getUuid());
        transientProject.setName(project.getName());
        transientProject.setVersion(project.getVersion());
        transientProject.setActive(true);
        transientProject.setParent(parent);
        transientProject.setDescription("only the description changed");
        qm.updateProject(transientProject, false);

        assertThat(accessChangedProjects()).isEmpty();
    }

    private Project persistProject(final String name, final String version, final Project parent) {
        final var project = new Project();
        project.setName(name);
        project.setVersion(version);
        project.setParent(parent);
        return qm.persist(project);
    }

    private static List<UUID> accessChangedProjects() {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "PROJECT_UUID"
                          FROM "ASSESSMENT_SYNC_OUTBOX"
                         WHERE "REASON" = :reason
                        """)
                .bind("reason", AssessmentStructureCapture.ACCESS_CHANGED)
                .mapTo(UUID.class)
                .list());
    }
}
