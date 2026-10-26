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
import org.dependencytrack.assessmentsync.AssessmentEmbeddingDao.Embedding;
import org.dependencytrack.assessmentsync.AssessmentEmbeddingDao.MarkerMembership;
import org.dependencytrack.assessmentsync.AssessmentEmbeddingDao.Membership;
import org.dependencytrack.model.Classifier;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

class AssessmentEmbeddingDaoTest extends PersistenceCapableTest {

    @Test
    void shouldReplaceMembershipKeepUnresolvedMarkersAndReadByIdentity() {
        final Project target = persistProject("cmx500", "1.0.0");
        final Project source = persistProject("mrt.base.linux", "5.14.121");
        final Component marker = persistComponent(target, "mrt.base.linux", "5.14.121");
        final Component otherMarker = persistComponent(target, "mrt.other.firmware", "1.4.0");
        final Component member = persistComponent(target, "libc6", "2.36");
        final Component otherMember = persistComponent(target, "busybox", "1.36.1");

        useJdbiTransaction(handle -> new AssessmentEmbeddingDao(handle)
                .replaceMembership(
                        target.getId(),
                        List.of(
                                new MarkerMembership(
                                        marker.getId(),
                                        "mrt.base.linux",
                                        "5.14.121",
                                        null,
                                        List.of(member.getId(), member.getId())),
                                new MarkerMembership(
                                        otherMarker.getId(),
                                        "mrt.other.firmware",
                                        "1.4.0",
                                        source.getUuid(),
                                        List.of(otherMember.getId())))));

        final List<Embedding> byName = inJdbiTransaction(
                handle -> new AssessmentEmbeddingDao(handle).findByMarkerNameAndVersion("mrt.base.linux", "5.14.121"));
        assertThat(byName)
                .containsExactly(new Embedding(target.getId(), marker.getId(), "mrt.base.linux", "5.14.121", null));
        final List<Embedding> missingMarker = inJdbiTransaction(
                handle -> new AssessmentEmbeddingDao(handle).findByMarkerNameAndVersion("mrt.base.linux", "9.9.9"));
        assertThat(missingMarker).isEmpty();

        final List<Embedding> bySource =
                inJdbiTransaction(handle -> new AssessmentEmbeddingDao(handle).findBySourceProject(source.getUuid()));
        assertThat(bySource)
                .containsExactly(new Embedding(
                        target.getId(), otherMarker.getId(), "mrt.other.firmware", "1.4.0", source.getUuid()));

        final List<Membership> membership = inJdbiTransaction(
                handle -> new AssessmentEmbeddingDao(handle).findMembership(target.getId(), member.getId()));
        assertThat(membership).containsExactly(new Membership(target.getId(), marker.getId(), member.getId()));

        useJdbiTransaction(handle -> handle.attach(ProjectDao.class).deleteProject(source.getUuid()));

        final List<Embedding> afterSourceDelete =
                inJdbiTransaction(handle -> new AssessmentEmbeddingDao(handle).findBySourceProject(source.getUuid()));
        assertThat(afterSourceDelete)
                .containsExactly(new Embedding(
                        target.getId(), otherMarker.getId(), "mrt.other.firmware", "1.4.0", source.getUuid()));

        useJdbiTransaction(handle -> new AssessmentEmbeddingDao(handle)
                .replaceMembership(
                        target.getId(),
                        List.of(new MarkerMembership(
                                marker.getId(), "mrt.base.linux", "5.14.121", null, List.of(member.getId())))));
        final List<Embedding> afterReplace =
                inJdbiTransaction(handle -> new AssessmentEmbeddingDao(handle).findBySourceProject(source.getUuid()));
        assertThat(afterReplace).isEmpty();
        final List<Embedding> unresolved = inJdbiTransaction(
                handle -> new AssessmentEmbeddingDao(handle).findByMarkerNameAndVersion("mrt.base.linux", "5.14.121"));
        assertThat(unresolved)
                .containsExactly(new Embedding(target.getId(), marker.getId(), "mrt.base.linux", "5.14.121", null));

        useJdbiTransaction(handle -> handle.attach(ProjectDao.class).deleteProject(target.getUuid()));
        final int embeddingCount = inJdbiTransaction(
                handle -> handle.createQuery("""
                        SELECT COUNT(*)
                          FROM "ASSESSMENT_EMBEDDING"
                        """).mapTo(int.class).one());
        assertThat(embeddingCount).isZero();
    }

    private Project persistProject(final String name, final String version) {
        final var project = new Project();
        project.setName(name);
        project.setVersion(version);
        return qm.persist(project);
    }

    private Component persistComponent(final Project project, final String name, final String version) {
        final var component = new Component();
        component.setProject(project);
        component.setName(name);
        component.setVersion(version);
        component.setClassifier(Classifier.LIBRARY);
        return qm.persist(component);
    }
}
