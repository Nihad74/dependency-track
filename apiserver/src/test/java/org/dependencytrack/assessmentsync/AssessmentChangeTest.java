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

import org.dependencytrack.assessmentsync.AssessmentChange.LookupKey;
import org.dependencytrack.assessmentsync.AssessmentChange.Scope;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AssessmentChangeTest {

    private static final UUID PROJECT = UUID.fromString("11111111-1111-1111-1111-111111111111");
    private static final UUID COMPONENT = UUID.fromString("22222222-2222-2222-2222-222222222222");
    private static final UUID VULNERABILITY = UUID.fromString("33333333-3333-3333-3333-333333333333");

    @Test
    void shouldBuildFindingAndProjectScopeKeys() {
        final AssessmentChange finding = new AssessmentChange(
                Scope.FINDING,
                PROJECT,
                COMPONENT,
                VULNERABILITY,
                "component-added",
                List.of(
                        new LookupKey("mrt.base.linux", "5.14.121"),
                        new LookupKey("mrt.base.linux", "5.14.121"),
                        new LookupKey("cmx500", "1.0.0")));

        assertThat(finding.scopeKey())
                .isEqualTo(
                        "finding:11111111-1111-1111-1111-111111111111:22222222-2222-2222-2222-222222222222:33333333-3333-3333-3333-333333333333");
        assertThat(finding.lookupKeys())
                .containsExactly(new LookupKey("mrt.base.linux", "5.14.121"), new LookupKey("cmx500", "1.0.0"));

        final AssessmentChange project =
                new AssessmentChange(Scope.PROJECT, PROJECT, null, null, "graph-changed", List.of());

        assertThat(project.scopeKey()).isEqualTo("project:11111111-1111-1111-1111-111111111111");
        assertThat(project.componentUuid()).isNull();
        assertThat(project.vulnerabilityUuid()).isNull();
    }

    @Test
    void shouldRejectInvalidEnvelopes() {
        assertThatThrownBy(
                        () -> new AssessmentChange(Scope.PROJECT, PROJECT, COMPONENT, null, "graph-changed", List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AssessmentChange(Scope.FINDING, PROJECT, null, null, "component-added", List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AssessmentChange(Scope.FINDING, PROJECT, COMPONENT, VULNERABILITY, " ", List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
