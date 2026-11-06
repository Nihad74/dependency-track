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
package org.dependencytrack.parser.cyclonedx;

import org.cyclonedx.model.Bom;
import org.cyclonedx.util.BomLink;
import org.dependencytrack.analysis.AnalysisMutationPlanner;
import org.dependencytrack.analysis.AnalysisWriter;
import org.dependencytrack.assessmentsync.AssessmentMutationGuard;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.ComponentIdentity;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.parser.cyclonedx.util.ModelConverter;
import org.dependencytrack.persistence.AnalysisCache;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigDecimal;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;

import static org.apache.commons.lang3.StringUtils.isBlank;
import static org.apache.commons.lang3.StringUtils.trimToNull;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertCdxVulnAnalysisJustificationToDtAnalysisJustification;
import static org.dependencytrack.parser.cyclonedx.util.ModelConverter.convertCdxVulnAnalysisStateToDtAnalysisState;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

public class CycloneDXVexImporter {

    private static final Logger LOGGER = LoggerFactory.getLogger(CycloneDXVexImporter.class);

    private static final String COMMENTER = "CycloneDX VEX";

    public void applyVex(final QueryManager qm, final Bom bom, final Project project) {
        qm.runInTransaction(() -> applyInTransaction(qm, bom, project));
    }

    private void applyInTransaction(final QueryManager qm, final Bom bom, final Project project) {
        if (bom.getVulnerabilities() == null || bom.getVulnerabilities().isEmpty()) {
            LOGGER.info("The uploaded VEX does not contain any vulnerabilities; Skipping VEX import");
            return;
        }
        if (!qm.hasVulnerabilities(project)) {
            LOGGER.info("The project {} does not have any vulnerabilities; Skipping VEX import", project);
            return;
        }

        final List<org.cyclonedx.model.vulnerability.Vulnerability> vexVulns =
                getApplicableVexVulnerabilities(bom.getVulnerabilities());
        if (vexVulns.isEmpty()) {
            LOGGER.info("The uploaded VEX does not contain any applicable vulnerabilities; Skipping VEX import");
            return;
        }

        final var pending = new PendingAnalyses(qm, project);
        final var projectUuid = project.getUuid();
        useJdbiHandle(qm, handle -> AssessmentMutationGuard.lockProject(handle, projectUuid));
        final Map<String, BomRefTarget> targetByBomRef = indexComponents(bom);
        final Map<String, List<Component>> componentsByBomRef = new HashMap<>();

        for (final org.cyclonedx.model.vulnerability.Vulnerability vexVuln : vexVulns) {
            final Vulnerability dtVuln = resolveVulnerability(qm, vexVuln);
            if (dtVuln == null) {
                continue;
            }

            final var request = analysisRequest(vexVuln);
            final var appliedComponents = new HashSet<Long>();
            final List<Component> vulnerableComponents = qm.getAllVulnerableComponents(project, dtVuln);
            final var vulnerableIds = new HashSet<Long>();
            vulnerableComponents.forEach(component -> vulnerableIds.add(component.getId()));

            for (final org.cyclonedx.model.vulnerability.Vulnerability.Affect affect : vexVuln.getAffects()) {
                final String affectedBomRef = affect.getRef();
                final BomRefTarget target = affectedBomRef != null ? targetByBomRef.get(affectedBomRef) : null;

                final boolean isProjectScoped = (target != null && target.isMetadataComponent())
                        || (target == null && affectedBomRef != null && BomLink.isBomLink(affectedBomRef));

                if (isProjectScoped) {
                    for (final Component component : vulnerableComponents) {
                        if (appliedComponents.add(component.getId())) {
                            pending.add(component, dtVuln, request);
                        }
                    }
                } else if (target != null) {
                    final List<Component> components = componentsByBomRef.computeIfAbsent(affectedBomRef, _ -> {
                        final var cid = new ComponentIdentity(target.component());
                        return qm.matchIdentity(project, cid);
                    });
                    for (final Component component : components) {
                        if (vulnerableIds.contains(component.getId()) && appliedComponents.add(component.getId())) {
                            pending.add(component, dtVuln, request);
                        }
                    }
                } else {
                    LOGGER.warn("""
                            Unable to locate affected element (metadata.component or components[].component) \
                            based on the BOM reference {}. The vulnerability.affects[].ref \
                            node of {}/{} is not resolvable; Skipping it\
                            """, affectedBomRef, sourceNameOf(vexVuln), vexVuln.getId());
                }
            }
        }
        pending.flush();
    }

    private static @Nullable String sourceNameOf(final org.cyclonedx.model.vulnerability.Vulnerability vexVuln) {
        if (vexVuln.getSource() == null) {
            return null;
        }

        return trimToNull(vexVuln.getSource().getName());
    }

    private static @Nullable Vulnerability resolveVulnerability(
            final QueryManager qm, final org.cyclonedx.model.vulnerability.Vulnerability vexVuln) {
        final String vexVulnId = vexVuln.getId();
        final String vexVulnSource = sourceNameOf(vexVuln);

        if (vexVulnSource != null && Vulnerability.Source.isKnownSource(vexVulnSource)) {
            final Vulnerability dtVuln = qm.getVulnerabilityByVulnId(vexVulnSource, vexVulnId);
            if (dtVuln != null) {
                return dtVuln;
            }
        }

        final List<Vulnerability> candidates = qm.getVulnerabilitiesByVulnId(vexVulnId);
        if (candidates.isEmpty()) {
            LOGGER.warn("""
                    VEX contains analysis for vulnerability {}, but the project is not affected by it. \
                    Analyses can currently only be applied to existing findings.\
                    """, vexVulnId);
            return null;
        }
        if (candidates.size() > 1) {
            LOGGER.warn(
                    """
                    VEX contains analysis for vulnerability {} from source {}, which does not identify \
                    a vulnerability in Dependency-Track. The ID alone matches vulnerabilities from \
                    multiple sources ({}); Skipping it\
                    """,
                    vexVulnId,
                    vexVulnSource,
                    candidates.stream().map(Vulnerability::getSource).toList());
            return null;
        }

        return candidates.getFirst();
    }

    private static List<org.cyclonedx.model.vulnerability.Vulnerability> getApplicableVexVulnerabilities(
            final List<org.cyclonedx.model.vulnerability.Vulnerability> vexVulns) {
        final var applicableVulns = new ArrayList<org.cyclonedx.model.vulnerability.Vulnerability>();
        for (int vexVulnPos = 0; vexVulnPos < vexVulns.size(); vexVulnPos++) {
            final var vexVuln = vexVulns.get(vexVulnPos);
            if (isBlank(vexVuln.getId())) {
                LOGGER.warn("VEX vulnerability at position #{} does not have an ID; Skipping it", vexVulnPos);
                continue;
            }

            final String vexVulnId = vexVuln.getId();
            final String vexVulnSource = sourceNameOf(vexVuln);
            if (vexVuln.getAffects() == null || vexVuln.getAffects().isEmpty()) {
                LOGGER.debug(
                        "VEX vulnerability {}/{} at position #{} does not have an affects node; Skipping it",
                        vexVulnSource,
                        vexVulnId,
                        vexVulnPos);
                continue;
            }
            if (vexVuln.getAnalysis() == null && findOwaspRating(vexVuln) == null) {
                LOGGER.debug(
                        "VEX vulnerability {}/{} at position #{} does not have an analysis or OWASP rating; Skipping it",
                        vexVulnSource,
                        vexVulnId,
                        vexVulnPos);
                continue;
            }

            applicableVulns.add(vexVuln);
        }

        return applicableVulns;
    }

    private record BomRefTarget(org.cyclonedx.model.Component component, boolean isMetadataComponent) {}

    private static Map<String, BomRefTarget> indexComponents(final Bom bom) {
        final Map<String, BomRefTarget> targetByBomRef = new HashMap<>();
        if (bom == null) {
            return targetByBomRef;
        }

        if (bom.getMetadata() != null && bom.getMetadata().getComponent() != null) {
            indexComponents(List.of(bom.getMetadata().getComponent()), targetByBomRef, true);
        }

        indexComponents(bom.getComponents(), targetByBomRef, false);
        return targetByBomRef;
    }

    private static void indexComponents(
            final List<org.cyclonedx.model.Component> components,
            final Map<String, BomRefTarget> targetByBomRef,
            final boolean metadataComponent) {
        if (components == null) {
            return;
        }

        for (final var component : components) {
            if (component.getBomRef() != null) {
                targetByBomRef.putIfAbsent(component.getBomRef(), new BomRefTarget(component, metadataComponent));
            }

            if (component.getComponents() != null && !component.getComponents().isEmpty()) {
                indexComponents(component.getComponents(), targetByBomRef, false);
            }
        }
    }

    private static AnalysisMutationPlanner.Request analysisRequest(
            final org.cyclonedx.model.vulnerability.Vulnerability cdxVuln) {
        AnalysisState state = null;
        AnalysisJustification justification = null;
        AnalysisResponse response = null;
        String details = null;
        Boolean suppressed = null;
        if (cdxVuln.getAnalysis() != null) {
            state = convertCdxVulnAnalysisStateToDtAnalysisState(
                    cdxVuln.getAnalysis().getState());
            justification = convertCdxVulnAnalysisJustificationToDtAnalysisJustification(
                    cdxVuln.getAnalysis().getJustification());
            final var responses = cdxVuln.getAnalysis().getResponses();
            // Preserve the legacy last-response rule without mapping and allocating an entire list.
            if (responses != null && !responses.isEmpty()) {
                response = ModelConverter.convertCdxVulnAnalysisResponseToDtAnalysisResponse(responses.getLast());
            }
            details = cdxVuln.getAnalysis().getDetail();
            suppressed = state == AnalysisState.FALSE_POSITIVE
                    || state == AnalysisState.NOT_AFFECTED
                    || state == AnalysisState.RESOLVED;
        }
        final var rating = findOwaspRating(cdxVuln);
        return new AnalysisMutationPlanner.Request(
                state,
                justification,
                response,
                details,
                suppressed,
                null,
                rating == null ? null : rating.getVector(),
                rating == null || rating.getScore() == null ? null : BigDecimal.valueOf(rating.getScore()),
                Set.of(),
                MakeAnalysisCommand.DecisionAction.TAKE_LOCAL,
                null);
    }

    private record FindingKey(long componentId, long vulnerabilityId) {}

    /** Bounded batches; repeated findings start a new batch to preserve their decision/audit order. */
    private static final class PendingAnalyses {
        private static final int BATCH_SIZE = 250;
        private final QueryManager qm;
        private final Project project;
        private final List<AnalysisWriter.Entry> entries = new ArrayList<>();
        private final Set<FindingKey> keys = new HashSet<>();

        private PendingAnalyses(final QueryManager qm, final Project project) {
            this.qm = qm;
            this.project = project;
        }

        private void add(
                final Component component,
                final Vulnerability vulnerability,
                final AnalysisMutationPlanner.Request request) {
            final var key = new FindingKey(component.getId(), vulnerability.getId());
            if (entries.size() == BATCH_SIZE || keys.contains(key)) {
                flush();
            }
            keys.add(key);
            // Resolve every JDO field before lending its connection to the batch writer.
            final var finding = new AnalysisWriter.Finding(
                    project.getId(),
                    project.getUuid(),
                    project.getName(),
                    project.getVersion(),
                    component.getId(),
                    component.getUuid(),
                    vulnerability.getId(),
                    vulnerability.getUuid());
            entries.add(new AnalysisWriter.Entry(request, finding, COMMENTER));
        }

        private void flush() {
            if (entries.isEmpty()) {
                return;
            }
            if (Thread.currentThread().isInterrupted()) {
                throw new CancellationException("VEX import interrupted");
            }
            final var batch = List.copyOf(entries);
            final var ids = withJdbiHandle(qm, handle -> AnalysisWriter.writeAll(handle, batch));
            AnalysisCache.evict(qm.getPersistenceManager(), ids);
            entries.clear();
            keys.clear();
        }
    }

    private static org.cyclonedx.model.vulnerability.Vulnerability.Rating findOwaspRating(
            final org.cyclonedx.model.vulnerability.Vulnerability cdxVuln) {
        if (cdxVuln.getRatings() == null) {
            return null;
        }

        for (final org.cyclonedx.model.vulnerability.Vulnerability.Rating rating : cdxVuln.getRatings()) {
            if (rating.getMethod() == org.cyclonedx.model.vulnerability.Vulnerability.Rating.Method.OWASP
                    && (rating.getVector() != null || rating.getScore() != null)) {
                return rating;
            }
        }

        return null;
    }
}
