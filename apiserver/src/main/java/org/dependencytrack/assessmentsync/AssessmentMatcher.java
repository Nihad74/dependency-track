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

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.dependencytrack.model.Classifier;
import org.jspecify.annotations.Nullable;
import us.springett.parsers.cpe.Cpe;
import us.springett.parsers.cpe.CpeParser;
import us.springett.parsers.cpe.exceptions.CpeParsingException;
import us.springett.parsers.cpe.values.LogicalValue;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/// Component and vulnerability identity. Does not choose among different valid identities.
public final class AssessmentMatcher {

    private AssessmentMatcher() {}

    /// Match {@code target} to at most one source component.
    ///
    /// Two source components with the same winning identity are ambiguous. Candidates that are
    /// different identities are not collapsed to a winner.
    public static MatchResult match(final ComponentIdentity target, final List<SourceCandidate> sourceCandidates) {
        Objects.requireNonNull(target, "target must not be null");
        Objects.requireNonNull(sourceCandidates, "sourceCandidates must not be null");

        final var byComponent = new LinkedHashMap<UUID, Classified>();
        for (final SourceCandidate candidate : sourceCandidates) {
            Objects.requireNonNull(candidate, "source candidate must not be null");
            final Classified classified = classify(target, candidate);
            if (classified.relation() == Relation.IGNORE) {
                continue;
            }
            final Classified existing = byComponent.get(candidate.component().uuid());
            if (existing == null) {
                byComponent.put(candidate.component().uuid(), classified);
            } else if (existing.relation() != classified.relation()) {
                byComponent.put(candidate.component().uuid(), existing.asConflict());
            }
        }

        final var matches = new ArrayList<Classified>();
        final var conflicts = new ArrayList<Classified>();
        for (final Classified classified : byComponent.values()) {
            if (classified.relation() == Relation.MATCH) {
                matches.add(classified);
            } else if (classified.relation() == Relation.CONFLICT) {
                conflicts.add(classified);
            }
        }
        if (!matches.isEmpty() && !conflicts.isEmpty()) {
            return new MatchResult.Unavailable(AssessmentReason.IDENTITY_CONFLICT);
        }
        if (matches.size() > 1) {
            return new MatchResult.Unavailable(AssessmentReason.AMBIGUOUS_COMPONENT);
        }
        if (matches.size() == 1) {
            final SourceCandidate candidate = matches.getFirst().candidate();
            if (!AssessmentConsensus.eligible(candidate.origin())) {
                return new MatchResult.Unavailable(AssessmentReason.NO_AUTHORED_SOURCE);
            }
            return new MatchResult.Matched(candidate);
        }
        if (!conflicts.isEmpty()) {
            return new MatchResult.Unavailable(AssessmentReason.IDENTITY_CONFLICT);
        }
        return new MatchResult.Unavailable(AssessmentReason.IDENTITY_MISSING);
    }

    /// Same vulnerability row, both attributions still active. A shared vulnerability id is not enough.
    public static VulnerabilityMatch matchVulnerability(
            final VulnerabilityIdentity target, final VulnerabilityIdentity source) {
        Objects.requireNonNull(target, "target must not be null");
        Objects.requireNonNull(source, "source must not be null");
        if (!target.attributionActive() || !source.attributionActive()) {
            return new VulnerabilityMatch.Unavailable(AssessmentReason.FINDING_INACTIVE);
        }
        if (!target.vulnerabilityUuid().equals(source.vulnerabilityUuid())) {
            return new VulnerabilityMatch.Different();
        }
        return new VulnerabilityMatch.Same();
    }

    private static Classified classify(final ComponentIdentity target, final SourceCandidate candidate) {
        final ComponentIdentity other = candidate.component();
        final String targetPurl = canonicalVersionedPurl(target.purl());
        final String candidatePurl = canonicalVersionedPurl(other.purl());
        final boolean hashConflict = hashesConflict(target, other);
        final boolean comparableConflict = comparableIdentifiersConflict(target, other);

        if (targetPurl != null) {
            if (targetPurl.equals(candidatePurl)) {
                // Name, version, and classifier are not a second identity check once the full PURL matches.
                // Those comparable fields apply to the CPE fallback below. Hashes still conflict.
                if (hashConflict) {
                    return new Classified(candidate, Relation.CONFLICT);
                }
                return new Classified(candidate, Relation.MATCH);
            }
            return new Classified(candidate, Relation.IGNORE);
        }

        final Cpe targetCpe = concreteCpe(target.cpe());
        final Cpe candidateCpe = concreteCpe(other.cpe());
        if (targetCpe == null || candidateCpe == null || !targetCpe.equals(candidateCpe)) {
            return new Classified(candidate, Relation.IGNORE);
        }
        if (parsePurl(other.purl()) != null || hashConflict || comparableConflict) {
            return new Classified(candidate, Relation.CONFLICT);
        }
        return new Classified(candidate, Relation.MATCH);
    }

    private static boolean hashesConflict(final ComponentIdentity target, final ComponentIdentity candidate) {
        for (final Map.Entry<HashAlgorithm, String> entry : target.hashes().entrySet()) {
            final String other = candidate.hashes().get(entry.getKey());
            if (other != null && !other.equals(entry.getValue())) {
                return true;
            }
        }
        return false;
    }

    private static boolean comparableIdentifiersConflict(
            final ComponentIdentity target, final ComponentIdentity candidate) {
        if (target.classifier() != null
                && candidate.classifier() != null
                && target.classifier() != candidate.classifier()) {
            return true;
        }
        final String targetName = target.name();
        final String candidateName = candidate.name();
        if (targetName != null
                && candidateName != null
                && !targetName.isBlank()
                && !candidateName.isBlank()
                && !targetName.equals(candidateName)) {
            return true;
        }
        final String targetVersion = target.version();
        final String candidateVersion = candidate.version();
        if (targetVersion != null
                && candidateVersion != null
                && !targetVersion.isBlank()
                && !candidateVersion.isBlank()
                && !targetVersion.equals(candidateVersion)) {
            return true;
        }
        return false;
    }

    private static @Nullable String canonicalVersionedPurl(final @Nullable String purl) {
        final PackageURL parsed = parsePurl(purl);
        if (parsed == null) {
            return null;
        }
        final String version = parsed.getVersion();
        if (version == null || version.isEmpty()) {
            return null;
        }
        return parsed.canonicalize();
    }

    private static @Nullable PackageURL parsePurl(final @Nullable String purl) {
        if (purl == null || purl.isBlank()) {
            return null;
        }
        try {
            return new PackageURL(purl);
        } catch (MalformedPackageURLException e) {
            return unrecognizedPurl(e);
        }
    }

    private static @Nullable PackageURL unrecognizedPurl(final MalformedPackageURLException exception) {
        Objects.requireNonNull(exception);
        return null;
    }

    private static @Nullable Cpe concreteCpe(final @Nullable String cpe) {
        final Cpe parsed = parseCpe(cpe);
        if (parsed == null || !concreteVersion(parsed)) {
            return null;
        }
        return parsed;
    }

    /// Wildcard ({@code *}, including {@code 5.*}) and unspecified ({@code -}) versions are not concrete.
    private static boolean concreteVersion(final Cpe cpe) {
        final String version = cpe.getVersion();
        if (version == null
                || version.isBlank()
                || LogicalValue.NA.getAbbreviation().equals(version)) {
            return false;
        }
        return version.indexOf('*') < 0 && version.indexOf('?') < 0;
    }

    private static @Nullable Cpe parseCpe(final @Nullable String cpe) {
        if (cpe == null || cpe.isBlank()) {
            return null;
        }
        try {
            return CpeParser.parse(cpe);
        } catch (CpeParsingException e) {
            return unrecognizedCpe(e);
        }
    }

    private static @Nullable Cpe unrecognizedCpe(final CpeParsingException exception) {
        Objects.requireNonNull(exception);
        return null;
    }

    /// Identity facts used for exact matching. Hashes are keyed by algorithm.
    public record ComponentIdentity(
            UUID uuid,
            @Nullable Classifier classifier,
            @Nullable String name,
            @Nullable String version,
            @Nullable String purl,
            @Nullable String cpe,
            Map<HashAlgorithm, String> hashes) {

        public ComponentIdentity {
            Objects.requireNonNull(uuid, "uuid must not be null");
            Objects.requireNonNull(hashes, "hashes must not be null");
            hashes = Map.copyOf(hashes);
        }
    }

    /// Algorithms stored on a component. Names follow the component hash columns.
    public enum HashAlgorithm {
        MD5,
        SHA1,
        SHA256,
        SHA384,
        SHA512,
        SHA3_256,
        SHA3_384,
        SHA3_512,
        BLAKE2B_256,
        BLAKE2B_384,
        BLAKE2B_512,
        BLAKE3,
        STREEBOG_256,
        STREEBOG_512
    }

    /// A source component and the ownership of its analysis, when one exists.
    public record SourceCandidate(
            ComponentIdentity component, @Nullable AssessmentOwnership origin) {

        public SourceCandidate {
            Objects.requireNonNull(component, "component must not be null");
        }
    }

    public sealed interface MatchResult {

        record Matched(SourceCandidate candidate) implements MatchResult {

            public Matched {
                Objects.requireNonNull(candidate, "candidate must not be null");
            }
        }

        record Unavailable(AssessmentReason reason) implements MatchResult {

            public Unavailable {
                Objects.requireNonNull(reason, "reason must not be null");
            }
        }
    }

    /// Vulnerability row identity. {@code vulnerabilityId} is not used for matching.
    public record VulnerabilityIdentity(
            UUID vulnerabilityUuid, @Nullable String vulnerabilityId, boolean attributionActive) {

        public VulnerabilityIdentity {
            Objects.requireNonNull(vulnerabilityUuid, "vulnerabilityUuid must not be null");
        }
    }

    public sealed interface VulnerabilityMatch {

        record Same() implements VulnerabilityMatch {}

        /// Active rows whose vulnerability UUIDs differ. No alias or vulnerability-id fallback.
        record Different() implements VulnerabilityMatch {}

        record Unavailable(AssessmentReason reason) implements VulnerabilityMatch {

            public Unavailable {
                Objects.requireNonNull(reason, "reason must not be null");
            }
        }
    }

    private enum Relation {
        MATCH,
        CONFLICT,
        IGNORE
    }

    private record Classified(SourceCandidate candidate, Relation relation) {

        private Classified asConflict() {
            return new Classified(candidate, Relation.CONFLICT);
        }
    }
}
