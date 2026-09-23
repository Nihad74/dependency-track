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
package org.dependencytrack.persistence.jdbi.mapping;

import com.github.packageurl.PackageURL;
import org.dependencytrack.model.PackageHealthScorecardCheck;
import org.jdbi.v3.core.config.ConfigRegistry;
import org.jdbi.v3.core.mapper.ColumnMapper;
import org.jdbi.v3.core.mapper.ColumnMappers;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.core.statement.StatementContext;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.sql.Array;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;

import static java.util.Objects.requireNonNull;

/**
 * Maps rows from {@code PACKAGE_HEALTH_SCORECARD_CHECK} to
 * {@link PackageHealthScorecardCheck}.
 *
 * @since 5.2.0
 */
@NullMarked
public final class PackageHealthScorecardCheckRowMapper implements RowMapper<PackageHealthScorecardCheck> {

    private @Nullable ColumnMapper<PackageURL> purlColumnMapper;

    @Override
    public void init(final ConfigRegistry registry) {
        purlColumnMapper =
                registry.get(ColumnMappers.class).findFor(PackageURL.class).orElseThrow();
    }

    @Override
    public PackageHealthScorecardCheck map(final ResultSet rs, final StatementContext ctx) throws SQLException {

        requireNonNull(purlColumnMapper);

        return new PackageHealthScorecardCheck(
                purlColumnMapper.map(rs, "PURL", ctx),
                rs.getString("CHECK_NAME"),
                rs.getString("DESCRIPTION"),
                rs.getObject("SCORE", Float.class),
                rs.getString("REASON"),
                getDetails(rs),
                rs.getString("DOCUMENTATION_URL"));
    }

    private static List<String> getDetails(final ResultSet rs) throws SQLException {

        final Array detailsArray = rs.getArray("DETAILS");
        if (detailsArray == null) {
            return List.of();
        }

        try {
            return List.copyOf(Arrays.asList((String[]) detailsArray.getArray()));
        } finally {
            detailsArray.free();
        }
    }
}
