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
package org.dependencytrack.pkghealth;

import com.github.packageurl.PackageURL;
import org.dependencytrack.model.PackageHealthMetadata;
import org.dependencytrack.model.PackageHealthMetadataStatus;
import org.dependencytrack.model.PackageHealthScorecardCheck;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class PackageHealthPolicyDeltaTest {

    private static final Instant FETCHED_AT = Instant.parse("2026-09-29T10:00:00Z");

    @Test
    void shouldIgnoreFirstWriteWhenNoPolicyFieldIsPresent() throws Exception {
        assertThat(PackageHealthPolicyDelta.changed(null, metadata(null, null, List.of())))
                .isFalse();
    }

    @Test
    void shouldDetectFirstWriteWhenAPolicyFieldIsPresent() throws Exception {
        assertThat(PackageHealthPolicyDelta.changed(null, metadata(10L, null, List.of())))
                .isTrue();
    }

    @Test
    void shouldDetectFirstWriteWhenAScorecardCheckIsPresent() throws Exception {
        assertThat(PackageHealthPolicyDelta.changed(
                        null, metadata(null, null, List.of(check("Maintained", 3.0f, "ok")))))
                .isTrue();
    }

    @Test
    void shouldIgnoreRefreshWhenPolicyFieldsAndCheckScoresAreUnchanged() throws Exception {
        final var previous = metadata(10L, 4.0f, List.of(check("Maintained", 3.0f, "old reason")));
        final var next = metadata(10L, 4.0f, List.of(check("Maintained", 3.0f, "new reason")));

        assertThat(PackageHealthPolicyDelta.changed(previous, next)).isFalse();
    }

    @Test
    void shouldDetectChangedScorecardCheckScore() throws Exception {
        final var previous = metadata(10L, 4.0f, List.of(check("Maintained", 3.0f, "ok")));
        final var next = metadata(10L, 4.0f, List.of(check("Maintained", 2.0f, "ok")));

        assertThat(PackageHealthPolicyDelta.changed(previous, next)).isTrue();
    }

    @Test
    void shouldIgnoreCheckOrder() throws Exception {
        final var previous =
                metadata(10L, 4.0f, List.of(check("Maintained", 3.0f, "ok"), check("Code-Review", 8.0f, "ok")));
        final var next =
                metadata(10L, 4.0f, List.of(check("Code-Review", 8.0f, "ok"), check("Maintained", 3.0f, "ok")));

        assertThat(PackageHealthPolicyDelta.changed(previous, next)).isFalse();
    }

    private static PackageHealthMetadata metadata(
            final Long stars, final Float scorecardScore, final List<PackageHealthScorecardCheck> checks)
            throws Exception {
        final var purl = new PackageURL("pkg:npm/react");
        return new PackageHealthMetadata(
                purl,
                stars,
                null,
                99L,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                scorecardScore,
                null,
                null,
                null,
                FETCHED_AT,
                PackageHealthMetadataStatus.PROCESSED,
                checks);
    }

    private static PackageHealthScorecardCheck check(final String name, final Float score, final String reason)
            throws Exception {
        return new PackageHealthScorecardCheck(
                new PackageURL("pkg:npm/react"), name, null, score, reason, List.of(), null);
    }
}
