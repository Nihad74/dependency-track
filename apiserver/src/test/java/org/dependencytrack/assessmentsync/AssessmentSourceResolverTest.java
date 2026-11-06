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

import alpine.model.Team;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.assessmentsync.AssessmentSourceResolver.Identity;
import org.dependencytrack.model.ConfigPropertyConstants;
import org.dependencytrack.model.Project;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.ConfigPropertyTestUtil.createConfigProperty;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

class AssessmentSourceResolverTest extends PersistenceCapableTest {

    @Test
    void resolvesOnlyUniqueActiveNonCollectionProjectsOtherThanTheTarget() {
        final Project target = project("target", "1");
        final Project source = project("source", "1");
        final Project inactive = project("inactive", "1");
        final Project collection = project("collection", "1");
        useJdbiTransaction(h -> {
            h.createUpdate("UPDATE \"PROJECT\" SET \"INACTIVE_SINCE\" = now() WHERE \"ID\" = :id")
                    .bind("id", inactive.getId())
                    .execute();
            h.createUpdate(
                            "UPDATE \"PROJECT\" SET \"COLLECTION_LOGIC\" = 'AGGREGATE_DIRECT_CHILDREN' WHERE \"ID\" = :id")
                    .bind("id", collection.getId())
                    .execute();
            final var marker = new Identity("source", "1");
            assertThat(AssessmentSourceResolver.resolve(
                            h,
                            target.getUuid(),
                            List.of(
                                    marker,
                                    marker,
                                    new Identity("target", "1"),
                                    new Identity("Source", "1"),
                                    new Identity("source", "2"),
                                    new Identity("inactive", "1"),
                                    new Identity("collection", "1"),
                                    new Identity("missing", "1"))))
                    .containsExactlyEntriesOf(Map.of(marker, source.getUuid()));
            assertThat(AssessmentSourceResolver.resolve(h, target.getUuid(), List.of()))
                    .isEmpty();
        });
    }

    @Test
    void everyDirectOrInheritedTargetTeamMustHaveSourceAccess() {
        createConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED, "true");
        final Team direct = qm.createTeam("direct");
        final Team inherited = qm.createTeam("inherited");
        final Project targetParent = project("target-parent", "1");
        targetParent.addAccessTeam(inherited);
        qm.persist(targetParent);
        final Project target = project("target", "1");
        target.setParent(targetParent);
        target.addAccessTeam(direct);
        qm.persist(target);
        final Project sourceParent = project("source-parent", "1");
        sourceParent.addAccessTeam(direct);
        qm.persist(sourceParent);
        final Project source = project("source", "1");
        source.setParent(sourceParent);
        qm.persist(source);
        final var identity = new Identity("source", "1");
        assertThat(resolve(target, identity)).isEmpty();
        sourceParent.addAccessTeam(inherited);
        qm.persist(sourceParent);
        assertThat(resolve(target, identity)).containsExactlyEntriesOf(Map.of(identity, source.getUuid()));
    }

    @Test
    void aclDisabledAndTargetsWithoutTeamsFollowTheDocumentedSubsetRule() {
        final Project target = project("target", "1");
        final Project source = project("source", "1");
        final var identity = new Identity("source", "1");
        createConfigProperty(ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED, "true");
        assertThat(resolve(target, identity)).containsExactlyEntriesOf(Map.of(identity, source.getUuid()));
        target.addAccessTeam(qm.createTeam("product"));
        qm.persist(target);
        assertThat(resolve(target, identity)).isEmpty();
        useJdbiTransaction(h -> h.createUpdate("""
                UPDATE "CONFIGPROPERTY" SET "PROPERTYVALUE" = 'false'
                 WHERE "GROUPNAME" = :group AND "PROPERTYNAME" = :name
                """)
                .bind("group", ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getGroupName())
                .bind("name", ConfigPropertyConstants.ACCESS_MANAGEMENT_ACL_ENABLED.getPropertyName())
                .execute());
        assertThat(resolve(target, identity)).containsExactlyEntriesOf(Map.of(identity, source.getUuid()));
    }

    private static Map<Identity, UUID> resolve(final Project target, final Identity identity) {
        return inJdbiTransaction(h -> AssessmentSourceResolver.resolve(h, target.getUuid(), List.of(identity)));
    }

    private Project project(final String name, final String version) {
        final var project = new Project();
        project.setName(name);
        project.setVersion(version);
        return qm.persist(project);
    }
}
