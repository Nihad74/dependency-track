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

import org.dependencytrack.assessmentsync.AssessmentMatcher.ComponentIdentity;
import org.dependencytrack.assessmentsync.AssessmentMatcher.HashAlgorithm;
import org.dependencytrack.assessmentsync.AssessmentMatcher.MatchResult;
import org.dependencytrack.assessmentsync.AssessmentMatcher.SourceCandidate;
import org.dependencytrack.assessmentsync.AssessmentMatcher.VulnerabilityIdentity;
import org.dependencytrack.assessmentsync.AssessmentMatcher.VulnerabilityMatch;
import org.dependencytrack.model.Classifier;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

class AssessmentMatcherTest {

    private static final UUID TARGET_ID = UUID.fromString("10000000-0000-0000-0000-000000000001");
    private static final UUID SOURCE_ID = UUID.fromString("20000000-0000-0000-0000-000000000002");
    private static final UUID OTHER_ID = UUID.fromString("30000000-0000-0000-0000-000000000003");

    private static final String FULL_PURL = "pkg:deb/debian/libc6@2.36?arch=amd64&distro=bookworm#usr/lib";
    private static final String FULL_PURL_REORDERED = "pkg:deb/debian/libc6@2.36?distro=bookworm&arch=amd64#usr/lib";
    private static final String COORDINATES_PURL = "pkg:deb/debian/libc6@2.36";
    private static final String VERSIONLESS_PURL = "pkg:deb/debian/libc6";
    private static final String CONCRETE_CPE = "cpe:2.3:o:linux:linux_kernel:5.14.121:*:*:*:*:*:*:*";
    private static final String WILDCARD_CPE = "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*";
    private static final String UNSPECIFIED_CPE = "cpe:2.3:a:vendor:product:-:*:*:*:*:*:*:*";
    private static final String PARTIAL_WILDCARD_CPE = "cpe:2.3:a:vendor:product:5.*:*:*:*:*:*:*:*";
    private static final String INVALID_CPE = "cpe:2.3:a:vendor";
    private static final String PACKAGE_CPE = "cpe:2.3:a:debian:libc6:2.36:*:*:*:*:*:*:*";

    @Test
    void shouldMatchCanonicalPurlWithNamespaceVersionQualifiersAndSubpath() {
        assertThat(FULL_PURL).isNotEqualTo(FULL_PURL_REORDERED);
        final ComponentIdentity target = component(TARGET_ID, "libc6", "2.36", FULL_PURL, null);
        final SourceCandidate source =
                candidate(SOURCE_ID, "libc6", "2.36", FULL_PURL_REORDERED, null, AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(target, List.of(source));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Matched.class,
                        matched -> assertThat(matched.candidate().component().uuid())
                                .isEqualTo(SOURCE_ID));
    }

    @Test
    void shouldMatchIdenticalVersionedPurlWithoutQualifiers() {
        final ComponentIdentity target = component(TARGET_ID, "libc6", "2.36", COORDINATES_PURL, null);
        final SourceCandidate source =
                candidate(SOURCE_ID, "libc6", "2.36", COORDINATES_PURL, null, AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(target, List.of(source));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Matched.class,
                        matched -> assertThat(matched.candidate().component().uuid())
                                .isEqualTo(SOURCE_ID));
    }

    @Test
    void shouldNotMatchCoordinatesOnlyPurl() {
        final ComponentIdentity target = component(TARGET_ID, "libc6", "2.36", FULL_PURL, null);
        final SourceCandidate coordinates =
                candidate(SOURCE_ID, "libc6", "2.36", COORDINATES_PURL, null, AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(target, List.of(coordinates));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.IDENTITY_MISSING));
    }

    @Test
    void shouldNotMatchNameAndVersionAlone() {
        final ComponentIdentity target = component(TARGET_ID, "libc6", "2.36", FULL_PURL, null);
        final SourceCandidate named = candidate(SOURCE_ID, "libc6", "2.36", null, null, AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(target, List.of(named));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.IDENTITY_MISSING));
    }

    @Test
    void shouldNotMatchVersionlessPurl() {
        final ComponentIdentity target = component(TARGET_ID, "libc6", null, VERSIONLESS_PURL, null);
        final SourceCandidate source =
                candidate(SOURCE_ID, "libc6", null, VERSIONLESS_PURL, null, AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(target, List.of(source));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.IDENTITY_MISSING));
    }

    @Test
    void shouldMatchConcreteVersionSpecificCpeWhenPurlIsAbsent() {
        final ComponentIdentity target =
                component(TARGET_ID, "linux_kernel", "5.14.121", null, CONCRETE_CPE, Classifier.OPERATING_SYSTEM);
        final SourceCandidate source = candidate(
                SOURCE_ID,
                "linux_kernel",
                "5.14.121",
                null,
                CONCRETE_CPE,
                Classifier.OPERATING_SYSTEM,
                AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(target, List.of(source));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Matched.class,
                        matched -> assertThat(matched.candidate().component().uuid())
                                .isEqualTo(SOURCE_ID));
    }

    @Test
    void shouldRejectWildcardCpe() {
        final ComponentIdentity target = component(TARGET_ID, "product", null, null, WILDCARD_CPE);
        final SourceCandidate source =
                candidate(SOURCE_ID, "product", null, null, WILDCARD_CPE, AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(target, List.of(source));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.IDENTITY_MISSING));
    }

    @Test
    void shouldRejectPartialWildcardCpeVersion() {
        final ComponentIdentity target = component(TARGET_ID, "product", null, null, PARTIAL_WILDCARD_CPE);
        final SourceCandidate source =
                candidate(SOURCE_ID, "product", null, null, PARTIAL_WILDCARD_CPE, AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(target, List.of(source));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.IDENTITY_MISSING));
    }

    @Test
    void shouldRejectUnspecifiedCpeVersion() {
        final ComponentIdentity target = component(TARGET_ID, "product", null, null, UNSPECIFIED_CPE);
        final SourceCandidate source =
                candidate(SOURCE_ID, "product", null, null, UNSPECIFIED_CPE, AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(target, List.of(source));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.IDENTITY_MISSING));
    }

    @Test
    void shouldRejectInvalidCpe() {
        final ComponentIdentity target = component(TARGET_ID, "product", null, null, INVALID_CPE);
        final SourceCandidate source =
                candidate(SOURCE_ID, "product", null, null, INVALID_CPE, AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(target, List.of(source));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.IDENTITY_MISSING));
    }

    @Test
    void shouldConflictWhenCandidatePurlContradictsCpe() {
        final ComponentIdentity target = component(TARGET_ID, "linux_kernel", "5.14.121", null, CONCRETE_CPE);
        final SourceCandidate source =
                candidate(SOURCE_ID, "linux_kernel", "5.14.121", FULL_PURL, CONCRETE_CPE, AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(target, List.of(source));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.IDENTITY_CONFLICT));
    }

    @Test
    void shouldConflictWhenSharedHashDiffers() {
        final ComponentIdentity target = component(
                TARGET_ID, "libc6", "2.36", FULL_PURL, null, Map.of(HashAlgorithm.SHA256, "aaaaaaaaaaaaaaaa"));
        final SourceCandidate source = candidate(
                SOURCE_ID,
                "libc6",
                "2.36",
                FULL_PURL,
                null,
                Map.of(HashAlgorithm.SHA256, "bbbbbbbbbbbbbbbb"),
                AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(target, List.of(source));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.IDENTITY_CONFLICT));
    }

    @Test
    void shouldNotConflictWhenHashIsMissing() {
        final ComponentIdentity target = component(
                TARGET_ID, "libc6", "2.36", FULL_PURL, null, Map.of(HashAlgorithm.SHA256, "aaaaaaaaaaaaaaaa"));
        final SourceCandidate source = candidate(
                SOURCE_ID,
                "libc6",
                "2.36",
                FULL_PURL,
                null,
                Map.of(HashAlgorithm.SHA1, "bbbbbbbbbbbbbbbb"),
                AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(target, List.of(source));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Matched.class,
                        matched -> assertThat(matched.candidate().component().uuid())
                                .isEqualTo(SOURCE_ID));
    }

    @Test
    void shouldMatchFullPurlWhenComponentNameAndClassifierDiffer() {
        final ComponentIdentity target =
                component(TARGET_ID, "GNU C Library", "2.36", FULL_PURL, null, Classifier.LIBRARY);
        final SourceCandidate source = candidate(
                SOURCE_ID, "libc6", "2.36-2", FULL_PURL, null, Classifier.APPLICATION, AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(target, List.of(source));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Matched.class,
                        matched -> assertThat(matched.candidate().component().uuid())
                                .isEqualTo(SOURCE_ID));
    }

    @Test
    void shouldConflictWhenCpeAgreesButComponentNameDiffers() {
        final ComponentIdentity target = component(TARGET_ID, "linux_kernel", "5.14.121", null, CONCRETE_CPE);
        final SourceCandidate source =
                candidate(SOURCE_ID, "other-kernel", "5.14.121", null, CONCRETE_CPE, AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(target, List.of(source));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.IDENTITY_CONFLICT));
    }

    @Test
    void shouldReturnAmbiguousComponentForDuplicateIdentity() {
        final ComponentIdentity target = component(TARGET_ID, "libc6", "2.36", FULL_PURL, null);
        final SourceCandidate first = candidate(SOURCE_ID, "libc6", "2.36", FULL_PURL, null, AssessmentOwnership.LOCAL);
        final SourceCandidate second =
                candidate(OTHER_ID, "libc6", "2.36", FULL_PURL_REORDERED, null, AssessmentOwnership.POLICY);

        final MatchResult result = AssessmentMatcher.match(target, List.of(first, second));

        assertThat(result).isNotInstanceOf(MatchResult.Matched.class);
        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Unavailable.class,
                        unavailable ->
                                assertThat(unavailable.reason()).isEqualTo(AssessmentReason.AMBIGUOUS_COMPONENT));
    }

    @Test
    void shouldNotTreatDistinctIdentitiesAsAmbiguous() {
        final ComponentIdentity target = component(TARGET_ID, "libc6", "2.36", FULL_PURL, null);
        final SourceCandidate match = candidate(SOURCE_ID, "libc6", "2.36", FULL_PURL, null, AssessmentOwnership.LOCAL);
        final SourceCandidate other =
                candidate(OTHER_ID, "openssl", "3.0.11", COORDINATES_PURL, null, AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(target, List.of(other, match));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Matched.class,
                        matched -> assertThat(matched.candidate().component().uuid())
                                .isEqualTo(SOURCE_ID));
    }

    @Test
    void shouldMatchSameVulnerabilityUuid() {
        final UUID vulnerability = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        final VulnerabilityIdentity target = new VulnerabilityIdentity(vulnerability, "CVE-2099-1210", true);
        final VulnerabilityIdentity source = new VulnerabilityIdentity(vulnerability, "CVE-2099-1210", true);

        final VulnerabilityMatch result = AssessmentMatcher.matchVulnerability(target, source);

        assertThat(result).isInstanceOf(VulnerabilityMatch.Same.class);
    }

    @Test
    void shouldNotMatchDifferentVulnerabilityUuidsWithTheSameCve() {
        final VulnerabilityIdentity target = new VulnerabilityIdentity(
                UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), "CVE-2099-1210", true);
        final VulnerabilityIdentity source = new VulnerabilityIdentity(
                UUID.fromString("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), "CVE-2099-1210", true);

        final VulnerabilityMatch result = AssessmentMatcher.matchVulnerability(target, source);

        assertThat(result).isInstanceOf(VulnerabilityMatch.Different.class);
    }

    @Test
    void shouldRejectInactiveAttribution() {
        final UUID vulnerability = UUID.fromString("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
        final VulnerabilityIdentity active = new VulnerabilityIdentity(vulnerability, "CVE-2099-1210", true);
        final VulnerabilityIdentity inactive = new VulnerabilityIdentity(vulnerability, "CVE-2099-1210", false);

        assertThat(AssessmentMatcher.matchVulnerability(active, inactive))
                .isInstanceOfSatisfying(
                        VulnerabilityMatch.Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.FINDING_INACTIVE));
        assertThat(AssessmentMatcher.matchVulnerability(inactive, active))
                .isInstanceOfSatisfying(
                        VulnerabilityMatch.Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.FINDING_INACTIVE));
    }

    @Test
    void shouldExcludeInheritedSource() {
        final ComponentIdentity target = component(TARGET_ID, "libc6", "2.36", FULL_PURL, null);
        final SourceCandidate inherited =
                candidate(SOURCE_ID, "libc6", "2.36", FULL_PURL, null, AssessmentOwnership.INHERITED);

        final MatchResult result = AssessmentMatcher.match(target, List.of(inherited));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.NO_AUTHORED_SOURCE));
    }

    @Test
    void shouldIncludeLegacyNullOrigin() {
        final ComponentIdentity target = component(TARGET_ID, "libc6", "2.36", FULL_PURL, null);
        final SourceCandidate legacy = candidate(SOURCE_ID, "libc6", "2.36", FULL_PURL, null, null);

        final MatchResult result = AssessmentMatcher.match(target, List.of(legacy));

        assertThat(result).isInstanceOfSatisfying(MatchResult.Matched.class, matched -> {
            assertThat(matched.candidate().component().uuid()).isEqualTo(SOURCE_ID);
            assertThat(matched.candidate().origin()).isNull();
        });
    }

    @Test
    void shouldIncludePolicyOrigin() {
        final ComponentIdentity target = component(TARGET_ID, "libc6", "2.36", FULL_PURL, null);
        final SourceCandidate policy =
                candidate(SOURCE_ID, "libc6", "2.36", FULL_PURL, null, AssessmentOwnership.POLICY);

        final MatchResult result = AssessmentMatcher.match(target, List.of(policy));

        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Matched.class,
                        matched -> assertThat(matched.candidate().origin()).isEqualTo(AssessmentOwnership.POLICY));
    }

    @Test
    void shouldNotMatchMarkerToADescendantPackage() {
        final ComponentIdentity marker =
                component(TARGET_ID, "mrt.base.linux", "5.14.121", null, CONCRETE_CPE, Classifier.OPERATING_SYSTEM);
        final SourceCandidate descendant = candidate(
                SOURCE_ID, "libc6", "2.36", FULL_PURL, PACKAGE_CPE, Classifier.LIBRARY, AssessmentOwnership.LOCAL);

        final MatchResult result = AssessmentMatcher.match(marker, List.of(descendant));

        assertThat(result).isNotInstanceOf(MatchResult.Matched.class);
        assertThat(result)
                .isInstanceOfSatisfying(
                        MatchResult.Unavailable.class,
                        unavailable -> assertThat(unavailable.reason()).isEqualTo(AssessmentReason.IDENTITY_MISSING));
    }

    private static ComponentIdentity component(
            final UUID uuid, final String name, final String version, final String purl, final String cpe) {
        return component(uuid, name, version, purl, cpe, Classifier.LIBRARY, Map.of());
    }

    private static ComponentIdentity component(
            final UUID uuid,
            final String name,
            final String version,
            final String purl,
            final String cpe,
            final Classifier classifier) {
        return component(uuid, name, version, purl, cpe, classifier, Map.of());
    }

    private static ComponentIdentity component(
            final UUID uuid,
            final String name,
            final String version,
            final String purl,
            final String cpe,
            final Map<HashAlgorithm, String> hashes) {
        return component(uuid, name, version, purl, cpe, Classifier.LIBRARY, hashes);
    }

    private static ComponentIdentity component(
            final UUID uuid,
            final String name,
            final String version,
            final String purl,
            final String cpe,
            final Classifier classifier,
            final Map<HashAlgorithm, String> hashes) {
        return new ComponentIdentity(uuid, classifier, name, version, purl, cpe, hashes);
    }

    private static SourceCandidate candidate(
            final UUID uuid,
            final String name,
            final String version,
            final String purl,
            final String cpe,
            final AssessmentOwnership origin) {
        return new SourceCandidate(component(uuid, name, version, purl, cpe), origin);
    }

    private static SourceCandidate candidate(
            final UUID uuid,
            final String name,
            final String version,
            final String purl,
            final String cpe,
            final Classifier classifier,
            final AssessmentOwnership origin) {
        return new SourceCandidate(component(uuid, name, version, purl, cpe, classifier), origin);
    }

    private static SourceCandidate candidate(
            final UUID uuid,
            final String name,
            final String version,
            final String purl,
            final String cpe,
            final Map<HashAlgorithm, String> hashes,
            final AssessmentOwnership origin) {
        return new SourceCandidate(component(uuid, name, version, purl, cpe, hashes), origin);
    }
}
