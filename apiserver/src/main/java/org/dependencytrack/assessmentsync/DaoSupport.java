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
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;

import static java.util.Objects.requireNonNull;

/**
 * Argument checks and row readers shared by the assessment sync DAOs.
 */
final class DaoSupport {

    private DaoSupport() {}

    static void requireTransaction(final Handle handle) {
        if (!handle.isInTransaction()) {
            throw new IllegalStateException("Assessment sync writes require an active transaction");
        }
    }

    static void requirePositive(final long value, final String name) {
        if (value <= 0) {
            throw new IllegalArgumentException(name + " must be positive");
        }
    }

    static @Nullable Long nullableLong(final ResultSet rs, final String column) throws SQLException {
        final long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    static @Nullable Instant readNullableInstant(final ResultSet rs, final String column) throws SQLException {
        final OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
        return value == null ? null : value.toInstant();
    }

    static Instant readInstant(final ResultSet rs, final String column) throws SQLException {
        return requireNonNull(readNullableInstant(rs, column), column);
    }
}
