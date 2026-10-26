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
package org.dependencytrack.tasks.maintenance;

import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.common.pagination.Page;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.persistence.jdbi.ProjectDao.ListProjectsRow;
import org.dependencytrack.persistence.jdbi.query.ListProjectsQuery;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.dependencytrack.util.DateUtil;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_PROJECTS_RETENTION_DAYS;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_PROJECTS_RETENTION_TYPE;
import static org.dependencytrack.model.ConfigPropertyConstants.MAINTENANCE_PROJECTS_RETENTION_VERSIONS;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class ProjectMaintenanceTaskTest extends PersistenceCapableTest {

    @Test
    void testWithRetentionTypeAge() {
        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyName(),
                "AGE",
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getDescription());

        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_DAYS.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_DAYS.getPropertyName(),
                MAINTENANCE_PROJECTS_RETENTION_DAYS.getDefaultPropertyValue(),
                MAINTENANCE_PROJECTS_RETENTION_DAYS.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_DAYS.getDescription());

        final var projectA = new Project();
        projectA.setName("acme-app-A");
        projectA.setInactiveSince(Date.from(Instant.now().minus(Duration.ofDays(40))));

        final var projectB = new Project();
        projectB.setName("acme-app-B");
        projectB.setInactiveSince(new Date());
        qm.persist(projectA, projectB);

        // Delete projects older than default 30 days
        final var task = new ProjectMaintenanceTask();
        assertThatNoException().isThrownBy(task::run);

        final Page<ListProjectsRow> projectsPage =
                withJdbiHandle(handle -> handle.attach(ProjectDao.class).getProjects(new ListProjectsQuery()));

        assertThat(projectsPage.items())
                .satisfiesExactly(
                        retainedProject -> assertThat(retainedProject.name()).isEqualTo("acme-app-B"));
    }

    @Test
    void testWithRetentionTypeVersionsForSameProject() {
        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyName(),
                "VERSIONS",
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getDescription());

        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_VERSIONS.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_VERSIONS.getPropertyName(),
                "2",
                MAINTENANCE_PROJECTS_RETENTION_VERSIONS.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_VERSIONS.getDescription());

        var project = new Project();
        project.setName("acme-app-A");
        project.setVersion("1.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20250105"));
        qm.persist(project);

        project = new Project();
        project.setName("acme-app-A");
        project.setVersion("2.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20250106"));
        qm.persist(project);

        project = new Project();
        project.setName("acme-app-A");
        project.setVersion("3.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20250107"));
        qm.persist(project);

        project = new Project();
        project.setName("acme-app-A");
        project.setVersion("4.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20250108"));
        qm.persist(project);

        project = new Project();
        project.setName("acme-app-A");
        project.setVersion("5.0.0");
        qm.persist(project);

        // Retain all active and last 2 inactive versions of a project and delete rest
        final var task = new ProjectMaintenanceTask();
        assertThatNoException().isThrownBy(task::run);
        final Page<ListProjectsRow> projectsPage =
                withJdbiHandle(handle -> handle.attach(ProjectDao.class).getProjects(new ListProjectsQuery()));
        assertThat(projectsPage.items())
                .satisfiesExactly(
                        retainedProject -> assertThat(retainedProject.version()).isEqualTo("3.0.0"),
                        retainedProject -> assertThat(retainedProject.version()).isEqualTo("4.0.0"),
                        retainedProject -> assertThat(retainedProject.version()).isEqualTo("5.0.0"));
    }

    @Test
    void testWithRetentionTypeVersionsForDifferentProjects() {
        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyName(),
                "VERSIONS",
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getDescription());

        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_VERSIONS.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_VERSIONS.getPropertyName(),
                "1",
                MAINTENANCE_PROJECTS_RETENTION_VERSIONS.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_VERSIONS.getDescription());

        var project = new Project();
        project.setName("acme-app-A");
        project.setVersion("1.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20250105"));
        qm.persist(project);

        project = new Project();
        project.setName("acme-app-A");
        project.setVersion("2.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20250107"));
        qm.persist(project);

        project = new Project();
        project.setName("acme-app-B");
        project.setVersion("1.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20250108"));
        qm.persist(project);

        project = new Project();
        project.setName("acme-app-B");
        project.setVersion("2.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20250109"));
        qm.persist(project);

        project = new Project();
        project.setName("acme-app-B");
        project.setVersion("3.0.0");
        qm.persist(project);

        // Retain all active and last 2 inactive versions of all projects and delete rest
        final var task = new ProjectMaintenanceTask();
        assertThatNoException().isThrownBy(task::run);
        final Page<ListProjectsRow> projectsPage =
                withJdbiHandle(handle -> handle.attach(ProjectDao.class).getProjects(new ListProjectsQuery()));
        assertThat(projectsPage.items())
                .satisfiesExactlyInAnyOrder(
                        retainedProject -> {
                            assertThat(retainedProject.name()).isEqualTo("acme-app-A");
                            assertThat(retainedProject.version()).isEqualTo("2.0.0");
                        },
                        retainedProject -> {
                            assertThat(retainedProject.name()).isEqualTo("acme-app-B");
                            assertThat(retainedProject.version()).isEqualTo("2.0.0");
                        },
                        retainedProject -> {
                            assertThat(retainedProject.name()).isEqualTo("acme-app-B");
                            assertThat(retainedProject.version()).isEqualTo("3.0.0");
                        });
    }

    @Test
    void testWithProjectRetentionDisabled() {
        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyName(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getDefaultPropertyValue(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getDescription());

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20100109"));
        qm.persist(project);

        final var task = new ProjectMaintenanceTask();
        assertThatNoException().isThrownBy(task::run);
        final Page<ListProjectsRow> projectsPage =
                withJdbiHandle(handle -> handle.attach(ProjectDao.class).getProjects(new ListProjectsQuery()));
        assertThat(projectsPage.items()).isNotEmpty();
    }

    @Test
    void testWithProjectRetentionDisabledWithEmptyValue() {
        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyName(),
                "",
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getDescription());

        var project = new Project();
        project.setName("acme-app");
        project.setVersion("1.0.0");
        project.setInactiveSince(DateUtil.parseShortDate("20100109"));
        qm.persist(project);

        final var task = new ProjectMaintenanceTask();
        assertThatNoException().isThrownBy(task::run);
        final Page<ListProjectsRow> projectsPage =
                withJdbiHandle(handle -> handle.attach(ProjectDao.class).getProjects(new ListProjectsQuery()));
        assertThat(projectsPage.items()).isNotEmpty();
    }

    @Test
    void retentionDeleteRecordsDescendant() {
        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyName(),
                "AGE",
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_TYPE.getDescription());
        qm.createConfigProperty(
                MAINTENANCE_PROJECTS_RETENTION_DAYS.getGroupName(),
                MAINTENANCE_PROJECTS_RETENTION_DAYS.getPropertyName(),
                MAINTENANCE_PROJECTS_RETENTION_DAYS.getDefaultPropertyValue(),
                MAINTENANCE_PROJECTS_RETENTION_DAYS.getPropertyType(),
                MAINTENANCE_PROJECTS_RETENTION_DAYS.getDescription());

        final var parent = new Project();
        parent.setName("retained-parent");
        parent.setVersion("1.0.0");
        parent.setInactiveSince(Date.from(Instant.now().minus(Duration.ofDays(40))));
        qm.persist(parent);

        final var child = new Project();
        child.setParent(parent);
        child.setName("retained-child");
        child.setVersion("2.0.0");
        qm.persist(child);

        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        try {
            assertThatNoException().isThrownBy(new ProjectMaintenanceTask()::run);
            final Long parentId =
                    withJdbiHandle(handle -> handle.attach(ProjectDao.class).getProjectId(parent.getUuid()));
            final Long childId =
                    withJdbiHandle(handle -> handle.attach(ProjectDao.class).getProjectId(child.getUuid()));
            assertThat(parentId).isNull();
            assertThat(childId).isNull();
            final List<String> lookupKeys = lookupKeys(parent.getUuid(), child.getUuid());
            assertThat(lookupKeys).hasSize(2);
            assertThat(String.join("\n", lookupKeys)).contains("retained-parent", "1.0.0", "retained-child", "2.0.0");
        } finally {
            MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
        }
    }

    private static List<String> lookupKeys(final UUID parentUuid, final UUID childUuid) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "LOOKUP_KEYS"::text
                          FROM "ASSESSMENT_SYNC_OUTBOX"
                         WHERE "PROJECT_UUID" IN (:parentUuid, :childUuid)
                        """)
                .bind("parentUuid", parentUuid)
                .bind("childUuid", childUuid)
                .mapTo(String.class)
                .list());
    }
}
