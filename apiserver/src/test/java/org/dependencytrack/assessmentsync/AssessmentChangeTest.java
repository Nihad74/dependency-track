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
import org.dependencytrack.assessmentsync.AssessmentChange.Reason;
import org.dependencytrack.assessmentsync.AssessmentChange.Scope;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.Arrays;
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
                Reason.COMPONENT_CHANGED,
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
                new AssessmentChange(Scope.PROJECT, PROJECT, null, null, Reason.BOM_IMPORT, List.of());

        assertThat(project.scopeKey()).isEqualTo("project:11111111-1111-1111-1111-111111111111");
        assertThat(project.componentUuid()).isNull();
        assertThat(project.vulnerabilityUuid()).isNull();
    }

    @Test
    void shouldRejectInvalidEnvelopes() {
        assertThatThrownBy(() ->
                        new AssessmentChange(Scope.PROJECT, PROJECT, COMPONENT, null, Reason.BOM_IMPORT, List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() ->
                        new AssessmentChange(Scope.FINDING, PROJECT, null, null, Reason.COMPONENT_CHANGED, List.of()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void changeSnapshotsTheLookupKeysAndPreservesTheirOrder() {
        final var first = new LookupKey("before", "1");
        final var second = new LookupKey("after", "2");
        final var mutable = new ArrayList<>(List.of(first, first, second));
        final var change = new AssessmentChange(Scope.PROJECT, PROJECT, null, null, Reason.PROJECT_UPDATED, mutable);
        mutable.clear();
        assertThat(change.lookupKeys()).containsExactly(first, second);
        assertThatThrownBy(() -> change.lookupKeys().clear()).isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void factoriesKeepConcreteLookupKeysAndOmitIncompleteOrBlankKeys() {
        assertThat(AssessmentChange.finding(PROJECT, COMPONENT, VULNERABILITY, Reason.AUTHORED, "Project", "1")
                        .lookupKeys())
                .containsExactly(new LookupKey("Project", "1"));
        assertThat(AssessmentChange.project(PROJECT, Reason.PROJECT_UPDATED, "Project", "1")
                        .lookupKeys())
                .containsExactly(new LookupKey("Project", "1"));
        for (final String missing : new String[] {null, "", " "}) {
            assertThat(LookupKey.listOf(missing, "1")).isEmpty();
            assertThat(LookupKey.listOf("Project", missing)).isEmpty();
        }
    }

    @Test
    void rejectsEveryInvalidScopeShapeAndRequiredNull() {
        assertThatThrownBy(() ->
                        new AssessmentChange(Scope.PROJECT, PROJECT, null, VULNERABILITY, Reason.BOM_IMPORT, List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(
                        () -> new AssessmentChange(Scope.FINDING, PROJECT, COMPONENT, null, Reason.AUTHORED, List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() ->
                        new AssessmentChange(Scope.FINDING, PROJECT, null, VULNERABILITY, Reason.AUTHORED, List.of()))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new AssessmentChange(null, PROJECT, null, null, Reason.BOM_IMPORT, List.of()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new AssessmentChange(Scope.PROJECT, null, null, null, Reason.BOM_IMPORT, List.of()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new AssessmentChange(Scope.PROJECT, PROJECT, null, null, null, List.of()))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new AssessmentChange(Scope.PROJECT, PROJECT, null, null, Reason.BOM_IMPORT, null))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new AssessmentChange(
                        Scope.PROJECT, PROJECT, null, null, Reason.BOM_IMPORT, Arrays.asList((LookupKey) null)))
                .isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new LookupKey(null, "1")).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new LookupKey("Project", null)).isInstanceOf(NullPointerException.class);
        assertThatThrownBy(() -> new LookupKey(" ", "1")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new LookupKey("Project", " ")).isInstanceOf(IllegalArgumentException.class);
    }
}
