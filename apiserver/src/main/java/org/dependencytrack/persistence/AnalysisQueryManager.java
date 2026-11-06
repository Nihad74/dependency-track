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
package org.dependencytrack.persistence;

import alpine.model.auth.ApiKeyPrincipal;
import alpine.model.auth.UserPrincipal;
import alpine.resources.AlpineRequest;
import org.dependencytrack.analysis.AnalysisMutationPlanner;
import org.dependencytrack.analysis.AnalysisWriter;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.jspecify.annotations.Nullable;

import javax.jdo.PersistenceManager;
import javax.jdo.Query;
import java.util.List;

import static org.dependencytrack.util.PersistenceUtil.assertPersistent;

public class AnalysisQueryManager extends QueryManager {

    /**
     * Constructs a new QueryManager.
     *
     * @param pm a PersistenceManager object
     */
    AnalysisQueryManager(final PersistenceManager pm) {
        super(pm);
    }

    /**
     * Constructs a new QueryManager.
     *
     * @param pm      a PersistenceManager object
     * @param request an AlpineRequest object
     */
    AnalysisQueryManager(final PersistenceManager pm, final AlpineRequest request) {
        super(pm, request);
    }

    /**
     * Returns a Analysis for the specified Project, Component, and Vulnerability.
     *
     * @param component     the Component
     * @param vulnerability the Vulnerability
     * @return a Analysis object, or null if not found
     */
    @Override
    public Analysis getAnalysis(Component component, Vulnerability vulnerability) {
        final Query<Analysis> query =
                pm.newQuery(Analysis.class, "component == :component && vulnerability == :vulnerability");
        query.setRange(0, 1);
        return singleResult(query.execute(component, vulnerability));
    }

    /**
     * @since 5.0.0
     */
    @Override
    public long makeAnalysis(final MakeAnalysisCommand command) {
        assertPersistent(command.component(), "component must be persistent");
        assertPersistent(command.vulnerability(), "vulnerability must be persistent");
        final var mutation = new AnalysisMutationPlanner.Request(
                command.state(),
                command.justification(),
                command.response(),
                command.details(),
                command.suppress(),
                command.comment(),
                command.owaspVector(),
                command.owaspScore(),
                command.options(),
                command.decisionAction(),
                command.expectedDecisionVersion());

        final long analysisId = callInTransaction(() -> {
            final Project project = command.component().getProject();
            if (project == null || project.getUuid() == null) {
                throw new IllegalStateException("component must belong to a project");
            }
            // JDO cannot load fields while the JDBI handle holds its connection, so read them first.
            final var finding = new AnalysisWriter.Finding(
                    project.getId(),
                    project.getUuid(),
                    project.getName(),
                    project.getVersion(),
                    command.component().getId(),
                    command.component().getUuid(),
                    command.vulnerability().getId(),
                    command.vulnerability().getUuid());
            final String principalCommenter = commenter(command.commenter());
            return JdbiFactory.withJdbiHandle(
                    this, handle -> AnalysisWriter.write(handle, mutation, finding, principalCommenter));
        });
        // The row was written through JDBI; cached JDO copies would show the old values.
        AnalysisCache.evict(pm, List.of(analysisId));
        return analysisId;
    }

    /**
     * The commenter the command names, else the calling principal.
     */
    private @Nullable String commenter(final @Nullable String commenter) {
        final String commenterToUse;
        if (commenter == null) {
            commenterToUse = switch (principal) {
                case UserPrincipal user -> user.username();
                case ApiKeyPrincipal apiKey ->
                    apiKey.teams().isEmpty()
                            ? apiKey.maskedKey()
                            : apiKey.teams().getFirst().name();
                case null -> null;
            };
        } else {
            commenterToUse = commenter;
        }

        return commenterToUse;
    }
}
