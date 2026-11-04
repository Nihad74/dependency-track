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
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * Component and vulnerability identity. Does not choose among different valid identities.
 */
public final class AssessmentMatcher {

    private AssessmentMatcher() {}

    /**
     * Match {@code target} to at most one source component.
     *
     * <p>Two source components with the same winning identity are ambiguous. Candidates that are
     * different identities are not collapsed to a winner.
     */
    public static MatchResult match(final ComponentIdentity target, final List<ComponentIdentity> sourceCandidates) {
        return match(target, Candidates.of(sourceCandidates));
    }

    /**
     * Same as {@link #match(ComponentIdentity, List)}, against candidates parsed once for many targets.
     */
    public static MatchResult match(final ComponentIdentity target, final Candidates sourceCandidates) {
        Objects.requireNonNull(target, "target must not be null");
        Objects.requireNonNull(sourceCandidates, "sourceCandidates must not be null");

        final TargetKey key = TargetKey.of(target);
        final var byComponent = new LinkedHashMap<UUID, Classified>();
        for (final ParsedCandidate candidate : sourceCandidates.comparableTo(key)) {
            final Classified classified = classify(target, key, candidate);
            if (classified.relation() == Relation.IGNORE) {
                continue;
            }
            final Classified existing = byComponent.get(candidate.identity().uuid());
            if (existing == null) {
                byComponent.put(candidate.identity().uuid(), classified);
            } else if (existing.relation() != classified.relation()) {
                byComponent.put(candidate.identity().uuid(), existing.asConflict());
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
            return new MatchResult.Matched(matches.getFirst().candidate());
        }
        if (!conflicts.isEmpty()) {
            return new MatchResult.Unavailable(AssessmentReason.IDENTITY_CONFLICT);
        }
        return new MatchResult.Unavailable(AssessmentReason.IDENTITY_MISSING);
    }

    /**
     * Same vulnerability row, both attributions still active. A shared vulnerability id is not enough.
     */
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

    private static Classified classify(
            final ComponentIdentity target, final TargetKey key, final ParsedCandidate candidate) {
        final ComponentIdentity other = candidate.identity();
        final String targetPurl = key.canonicalPurl();
        final boolean hashConflict = hashesConflict(target, other);

        if (targetPurl != null) {
            if (targetPurl.equals(candidate.canonicalPurl())) {
                // Name, version, and classifier are not a second identity check once the full PURL matches.
                // Those comparable fields apply to the CPE fallback below. Hashes still conflict.
                if (hashConflict) {
                    return new Classified(other, Relation.CONFLICT);
                }
                return new Classified(other, Relation.MATCH);
            }
            return new Classified(other, Relation.IGNORE);
        }

        final Cpe targetCpe = key.concreteCpe();
        if (targetCpe == null || !targetCpe.equals(candidate.concreteCpe())) {
            return new Classified(other, Relation.IGNORE);
        }
        if (candidate.hasPurl() || hashConflict || comparableIdentifiersConflict(target, other)) {
            return new Classified(other, Relation.CONFLICT);
        }
        return new Classified(other, Relation.MATCH);
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

    private static @Nullable String canonicalVersioned(final @Nullable PackageURL parsed) {
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
            // An unparseable PURL is no identity; the target or candidate then cannot match on it.
            return null;
        }
    }

    private static @Nullable Cpe concreteCpe(final @Nullable String cpe) {
        final Cpe parsed = parseCpe(cpe);
        if (parsed == null || !concreteVersion(parsed)) {
            return null;
        }
        return parsed;
    }

    /**
     * Wildcard ({@code *}, including {@code 5.*}) and unspecified ({@code -}) versions are not concrete.
     */
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
            // An unparseable CPE is no identity, as for an unparseable PURL.
            return null;
        }
    }

    /**
     * Identity facts used for exact matching. Hashes are keyed by algorithm.
     */
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

    /**
     * Algorithms stored on a component. Names follow the component hash columns.
     */
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

    public sealed interface MatchResult {

        record Matched(ComponentIdentity component) implements MatchResult {

            public Matched {
                Objects.requireNonNull(component, "component must not be null");
            }
        }

        record Unavailable(AssessmentReason reason) implements MatchResult {

            public Unavailable {
                Objects.requireNonNull(reason, "reason must not be null");
            }
        }
    }

    /**
     * Vulnerability row identity. {@code vulnerabilityId} is not used for matching.
     */
    public record VulnerabilityIdentity(
            UUID vulnerabilityUuid, @Nullable String vulnerabilityId, boolean attributionActive) {

        public VulnerabilityIdentity {
            Objects.requireNonNull(vulnerabilityUuid, "vulnerabilityUuid must not be null");
        }
    }

    public sealed interface VulnerabilityMatch {

        record Same() implements VulnerabilityMatch {}

        /**
         * Active rows whose vulnerability UUIDs differ. No alias or vulnerability-id fallback.
         */
        record Different() implements VulnerabilityMatch {}

        record Unavailable(AssessmentReason reason) implements VulnerabilityMatch {

            public Unavailable {
                Objects.requireNonNull(reason, "reason must not be null");
            }
        }
    }

    /**
     * Source candidates with PURL and CPE parsed once, indexed by the identity a target can match on.
     */
    public static final class Candidates {

        private final Map<String, List<ParsedCandidate>> byPurl;
        private final Map<Cpe, List<ParsedCandidate>> byCpe;

        private Candidates(
                final Map<String, List<ParsedCandidate>> byPurl, final Map<Cpe, List<ParsedCandidate>> byCpe) {
            this.byPurl = byPurl;
            this.byCpe = byCpe;
        }

        public static Candidates of(final Collection<ComponentIdentity> identities) {
            Objects.requireNonNull(identities, "identities must not be null");
            final var byPurl = new HashMap<String, List<ParsedCandidate>>();
            final var byCpe = new HashMap<Cpe, List<ParsedCandidate>>();
            for (final ComponentIdentity identity : identities) {
                Objects.requireNonNull(identity, "source candidate must not be null");
                final PackageURL purl = parsePurl(identity.purl());
                final var candidate = new ParsedCandidate(
                        identity, canonicalVersioned(purl), concreteCpe(identity.cpe()), purl != null);
                if (candidate.canonicalPurl() != null) {
                    byPurl.computeIfAbsent(candidate.canonicalPurl(), ignored -> new ArrayList<>())
                            .add(candidate);
                }
                if (candidate.concreteCpe() != null) {
                    byCpe.computeIfAbsent(candidate.concreteCpe(), ignored -> new ArrayList<>())
                            .add(candidate);
                }
            }
            return new Candidates(byPurl, byCpe);
        }

        /**
         * The only candidates {@code classify} does not ignore for this target.
         */
        private List<ParsedCandidate> comparableTo(final TargetKey key) {
            if (key.canonicalPurl() != null) {
                return byPurl.getOrDefault(key.canonicalPurl(), List.of());
            }
            final Cpe targetCpe = key.concreteCpe();
            return targetCpe == null ? List.of() : byCpe.getOrDefault(targetCpe, List.of());
        }
    }

    /**
     * The target's identity, parsed once per match.
     */
    private record TargetKey(
            @Nullable String canonicalPurl, @Nullable Cpe concreteCpe) {

        private static TargetKey of(final ComponentIdentity target) {
            return new TargetKey(
                    canonicalVersioned(parsePurl(target.purl())), AssessmentMatcher.concreteCpe(target.cpe()));
        }
    }

    private record ParsedCandidate(
            ComponentIdentity identity,
            @Nullable String canonicalPurl,
            @Nullable Cpe concreteCpe,
            boolean hasPurl) {}

    private enum Relation {
        MATCH,
        CONFLICT,
        IGNORE
    }

    private record Classified(ComponentIdentity candidate, Relation relation) {

        private Classified asConflict() {
            return new Classified(candidate, Relation.CONFLICT);
        }
    }
}
