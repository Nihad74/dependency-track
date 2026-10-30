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

import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.List;
import java.util.UUID;

/// The ids and UUIDs that name one analysed finding in an assessment change.
public record FindingIdentity(
        long analysisId,
        long componentId,
        long vulnerabilityId,
        UUID projectUuid,
        @Nullable String projectName,
        @Nullable String projectVersion,
        UUID componentUuid,
        UUID vulnerabilityUuid) {

    /// Select list for {@link #MAPPER}, over {@code ANALYSIS a}, {@code PROJECT p}, {@code COMPONENT c} and
    /// {@code VULNERABILITY v}.
    public static final String COLUMNS = """
            a."ID" AS analysis_id
                 , a."COMPONENT_ID" AS component_id
                 , a."VULNERABILITY_ID" AS vulnerability_id
                 , p."UUID" AS project_uuid
                 , p."NAME" AS project_name
                 , p."VERSION" AS project_version
                 , c."UUID" AS component_uuid
                 , v."UUID" AS vulnerability_uuid""";

    public static final RowMapper<FindingIdentity> MAPPER = (rs, ctx) -> new FindingIdentity(
            rs.getLong("analysis_id"),
            rs.getLong("component_id"),
            rs.getLong("vulnerability_id"),
            rs.getObject("project_uuid", UUID.class),
            rs.getString("project_name"),
            rs.getString("project_version"),
            rs.getObject("component_uuid", UUID.class),
            rs.getObject("vulnerability_uuid", UUID.class));

    /// Loads the identities of existing analyses. Fails when one of them is gone, because callers pass ids
    /// they wrote in the same transaction.
    public static List<FindingIdentity> ofAnalyses(final Handle handle, final Collection<Long> analysisIds) {
        if (analysisIds.isEmpty()) {
            return List.of();
        }
        final long[] ids =
                analysisIds.stream().mapToLong(Long::longValue).distinct().toArray();
        final List<FindingIdentity> identities = handle.createQuery(/* language=SQL */ """
                        SELECT %s
                          FROM "ANALYSIS" AS a
                         INNER JOIN "PROJECT" AS p
                            ON p."ID" = a."PROJECT_ID"
                         INNER JOIN "COMPONENT" AS c
                            ON c."ID" = a."COMPONENT_ID"
                         INNER JOIN "VULNERABILITY" AS v
                            ON v."ID" = a."VULNERABILITY_ID"
                         WHERE a."ID" = ANY(:ids)
                        """.formatted(COLUMNS))
                .bind("ids", ids)
                .map(MAPPER)
                .list();
        if (identities.size() != ids.length) {
            throw new IllegalStateException("An analysis written in this transaction is missing its finding identity");
        }
        return identities;
    }

    public AssessmentChange change(final AssessmentChange.Reason reason) {
        return AssessmentChange.finding(
                projectUuid, componentUuid, vulnerabilityUuid, reason, projectName, projectVersion);
    }
}
