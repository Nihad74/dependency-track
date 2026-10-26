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

import org.dependencytrack.model.FindingKey;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/// Durable per-target reconciliation and refresh revisions. Mutators lock the work row first.
public final class AssessmentSyncWorkDao {

    private static final RowMapper<WorkRow> WORK_ROW = (rs, ctx) -> new WorkRow(
            rs.getObject("TARGET_UUID", UUID.class),
            rs.getLong("REQUESTED_REVISION"),
            rs.getLong("COMPLETED_REVISION"),
            rs.getLong("FULL_REVISION"),
            nullableLong(rs, "ACTIVE_REVISION"),
            rs.getBoolean("ACTIVE_FULL"),
            nullableLong(rs, "CURSOR_COMPONENT_ID"),
            nullableLong(rs, "CURSOR_VULNERABILITY_ID"),
            rs.getLong("REFRESH_REQUESTED"),
            rs.getLong("REFRESH_COMPLETED"),
            readInstant(rs, "NEXT_DISPATCH_AT"),
            readNullableInstant(rs, "LAST_SUCCESS_AT"),
            rs.getString("LAST_ERROR_CODE"));

    private final Handle handle;

    public AssessmentSyncWorkDao(final Handle handle) {
        this.handle = requireNonNull(handle, "handle must not be null");
    }

    /// Allocates the next revision and marks it as a full-project pass.
    public long requestFull(final UUID targetUuid) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireTransaction();
        return handle.createQuery(/* language=SQL */ """
                        INSERT INTO "ASSESSMENT_SYNC_WORK" (
                          "TARGET_UUID"
                        , "REQUESTED_REVISION"
                        , "FULL_REVISION"
                        , "NEXT_DISPATCH_AT"
                        )
                        VALUES (:targetUuid, 1, 1, date_trunc('milliseconds', clock_timestamp()))
                        ON CONFLICT ("TARGET_UUID") DO UPDATE
                        SET "REQUESTED_REVISION" = "ASSESSMENT_SYNC_WORK"."REQUESTED_REVISION" + 1
                          , "FULL_REVISION" = "ASSESSMENT_SYNC_WORK"."REQUESTED_REVISION" + 1
                          , "NEXT_DISPATCH_AT" = date_trunc('milliseconds', clock_timestamp())
                        RETURNING "REQUESTED_REVISION"
                        """)
                .bind("targetUuid", targetUuid)
                .mapTo(long.class)
                .one();
    }

    /// Allocates the next revision and upserts finding keys at that revision.
    public long requestFindings(final UUID targetUuid, final Collection<FindingKey> keys) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireNonNull(keys, "keys must not be null");
        requireTransaction();
        final long revision = handle.createQuery(/* language=SQL */ """
                        INSERT INTO "ASSESSMENT_SYNC_WORK" (
                          "TARGET_UUID"
                        , "REQUESTED_REVISION"
                        , "NEXT_DISPATCH_AT"
                        )
                        VALUES (:targetUuid, 1, date_trunc('milliseconds', clock_timestamp()))
                        ON CONFLICT ("TARGET_UUID") DO UPDATE
                        SET "REQUESTED_REVISION" = "ASSESSMENT_SYNC_WORK"."REQUESTED_REVISION" + 1
                          , "NEXT_DISPATCH_AT" = date_trunc('milliseconds', clock_timestamp())
                        RETURNING "REQUESTED_REVISION"
                        """)
                .bind("targetUuid", targetUuid)
                .mapTo(long.class)
                .one();

        final Collection<FindingKey> unique = dedupe(keys);
        if (unique.isEmpty()) {
            return revision;
        }
        final var componentIds = new long[unique.size()];
        final var vulnerabilityIds = new long[unique.size()];
        int i = 0;
        for (final FindingKey key : unique) {
            componentIds[i] = key.componentId();
            vulnerabilityIds[i] = key.vulnDbId();
            i++;
        }
        handle.createUpdate(/* language=SQL */ """
                        INSERT INTO "ASSESSMENT_SYNC_FINDING" (
                          "TARGET_UUID"
                        , "COMPONENT_ID"
                        , "VULNERABILITY_ID"
                        , "REVISION"
                        )
                        SELECT :targetUuid
                             , t.component_id
                             , t.vulnerability_id
                             , :revision
                          FROM UNNEST(:componentIds, :vulnerabilityIds) AS t(component_id, vulnerability_id)
                        ON CONFLICT ("TARGET_UUID", "COMPONENT_ID", "VULNERABILITY_ID") DO UPDATE
                        SET "REVISION" = GREATEST("ASSESSMENT_SYNC_FINDING"."REVISION", EXCLUDED."REVISION")
                        """)
                .bind("targetUuid", targetUuid)
                .bind("revision", revision)
                .bind("componentIds", componentIds)
                .bind("vulnerabilityIds", vulnerabilityIds)
                .execute();
        return revision;
    }

    /// Captures {@code REQUESTED_REVISION} or resumes the pass already in progress.
    public @Nullable Pass beginOrResumePass(final UUID targetUuid) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireTransaction();
        final WorkRow locked = lock(targetUuid);
        if (locked == null) {
            return null;
        }
        if (locked.activeRevision() != null) {
            return new Pass(
                    locked.activeRevision(),
                    locked.activeFull(),
                    locked.cursorComponentId(),
                    locked.cursorVulnerabilityId(),
                    true);
        }
        if (locked.requestedRevision() == locked.completedRevision()) {
            return null;
        }
        return handle.createQuery(/* language=SQL */ """
                        UPDATE "ASSESSMENT_SYNC_WORK"
                           SET "ACTIVE_REVISION" = "REQUESTED_REVISION"
                             , "ACTIVE_FULL" = "FULL_REVISION" > "COMPLETED_REVISION"
                             , "CURSOR_COMPONENT_ID" = NULL
                             , "CURSOR_VULNERABILITY_ID" = NULL
                         WHERE "TARGET_UUID" = :targetUuid
                           AND "ACTIVE_REVISION" IS NULL
                        RETURNING "ACTIVE_REVISION"
                                , "ACTIVE_FULL"
                                , "CURSOR_COMPONENT_ID"
                                , "CURSOR_VULNERABILITY_ID"
                        """)
                .bind("targetUuid", targetUuid)
                .map((rs, ctx) -> new Pass(
                        rs.getLong("ACTIVE_REVISION"),
                        rs.getBoolean("ACTIVE_FULL"),
                        nullableLong(rs, "CURSOR_COMPONENT_ID"),
                        nullableLong(rs, "CURSOR_VULNERABILITY_ID"),
                        false))
                .one();
    }

    /// Saves the keyset cursor for the captured pass. A mismatched revision is left unchanged.
    public boolean advancePass(
            final UUID targetUuid,
            final long activeRevision,
            final @Nullable Long cursorComponentId,
            final @Nullable Long cursorVulnerabilityId) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireTransaction();
        lock(targetUuid);
        final int updated = handle.createUpdate(/* language=SQL */ """
                        UPDATE "ASSESSMENT_SYNC_WORK"
                           SET "CURSOR_COMPONENT_ID" = :cursorComponentId
                             , "CURSOR_VULNERABILITY_ID" = :cursorVulnerabilityId
                         WHERE "TARGET_UUID" = :targetUuid
                           AND "ACTIVE_REVISION" = :activeRevision
                        """)
                .bind("targetUuid", targetUuid)
                .bind("activeRevision", activeRevision)
                .bind("cursorComponentId", cursorComponentId)
                .bind("cursorVulnerabilityId", cursorVulnerabilityId)
                .execute();
        return updated == 1;
    }

    /// Acknowledges only {@code activeRevision}. Newer finding rows and a newer full request stay pending.
    public boolean completePass(final UUID targetUuid, final long activeRevision) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireTransaction();
        final WorkRow locked = lock(targetUuid);
        if (locked == null || locked.activeRevision() == null || locked.activeRevision() != activeRevision) {
            return false;
        }
        handle.createUpdate(/* language=SQL */ """
                        DELETE FROM "ASSESSMENT_SYNC_FINDING"
                         WHERE "TARGET_UUID" = :targetUuid
                           AND "REVISION" <= :activeRevision
                        """)
                .bind("targetUuid", targetUuid)
                .bind("activeRevision", activeRevision)
                .execute();
        final int updated = handle.createUpdate(/* language=SQL */ """
                        UPDATE "ASSESSMENT_SYNC_WORK"
                           SET "COMPLETED_REVISION" = :activeRevision
                             , "ACTIVE_REVISION" = NULL
                             , "ACTIVE_FULL" = FALSE
                             , "CURSOR_COMPONENT_ID" = NULL
                             , "CURSOR_VULNERABILITY_ID" = NULL
                             , "LAST_SUCCESS_AT" = now()
                         WHERE "TARGET_UUID" = :targetUuid
                           AND "ACTIVE_REVISION" = :activeRevision
                        """)
                .bind("targetUuid", targetUuid)
                .bind("activeRevision", activeRevision)
                .execute();
        return updated == 1;
    }

    /// Completes reconciliation and refresh for a target that no longer exists.
    ///
    /// Pending finding keys are removed. Newer work cannot arrive for a deleted project
    /// through this row once both revisions are caught up.
    public boolean acknowledgeCancellation(final UUID targetUuid) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireTransaction();
        if (lock(targetUuid) == null) {
            return false;
        }
        handle.createUpdate(/* language=SQL */ """
                        DELETE FROM "ASSESSMENT_SYNC_FINDING"
                         WHERE "TARGET_UUID" = :targetUuid
                        """)
                .bind("targetUuid", targetUuid)
                .execute();
        final int updated = handle.createUpdate(/* language=SQL */ """
                        UPDATE "ASSESSMENT_SYNC_WORK"
                           SET "COMPLETED_REVISION" = "REQUESTED_REVISION"
                             , "REFRESH_COMPLETED" = "REFRESH_REQUESTED"
                             , "ACTIVE_REVISION" = NULL
                             , "ACTIVE_FULL" = FALSE
                             , "CURSOR_COMPONENT_ID" = NULL
                             , "CURSOR_VULNERABILITY_ID" = NULL
                             , "LAST_SUCCESS_AT" = now()
                             , "LAST_ERROR_CODE" = NULL
                         WHERE "TARGET_UUID" = :targetUuid
                        """)
                .bind("targetUuid", targetUuid)
                .execute();
        return updated == 1;
    }

    public long requestRefresh(final UUID targetUuid) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireTransaction();
        return handle.createQuery(/* language=SQL */ """
                        INSERT INTO "ASSESSMENT_SYNC_WORK" (
                          "TARGET_UUID"
                        , "REFRESH_REQUESTED"
                        , "NEXT_DISPATCH_AT"
                        )
                        VALUES (:targetUuid, 1, date_trunc('milliseconds', clock_timestamp()))
                        ON CONFLICT ("TARGET_UUID") DO UPDATE
                        SET "REFRESH_REQUESTED" = "ASSESSMENT_SYNC_WORK"."REFRESH_REQUESTED" + 1
                          , "NEXT_DISPATCH_AT" = date_trunc('milliseconds', clock_timestamp())
                        RETURNING "REFRESH_REQUESTED"
                        """)
                .bind("targetUuid", targetUuid)
                .mapTo(long.class)
                .one();
    }

    /// Advances refresh completion up to {@code capturedRefresh}, and never past the requested value.
    public long acknowledgeRefresh(final UUID targetUuid, final long capturedRefresh) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        if (capturedRefresh < 0) {
            throw new IllegalArgumentException("capturedRefresh must not be negative");
        }
        requireTransaction();
        if (lock(targetUuid) == null) {
            throw new IllegalStateException("No assessment sync work for " + targetUuid);
        }
        return handle.createQuery(/* language=SQL */ """
                        UPDATE "ASSESSMENT_SYNC_WORK"
                           SET "REFRESH_COMPLETED" = LEAST(
                                 "REFRESH_REQUESTED"
                               , GREATEST("REFRESH_COMPLETED", :capturedRefresh)
                               )
                         WHERE "TARGET_UUID" = :targetUuid
                        RETURNING "REFRESH_COMPLETED"
                        """)
                .bind("targetUuid", targetUuid)
                .bind("capturedRefresh", capturedRefresh)
                .mapTo(long.class)
                .one();
    }

    /// Locks due rows whose reconciliation or refresh is unfinished.
    public List<WorkRow> pollDue(final int limit) {
        requireTransaction();
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be positive");
        }
        return handle.createQuery(/* language=SQL */ """
                        SELECT "TARGET_UUID"
                             , "REQUESTED_REVISION"
                             , "COMPLETED_REVISION"
                             , "FULL_REVISION"
                             , "ACTIVE_REVISION"
                             , "ACTIVE_FULL"
                             , "CURSOR_COMPONENT_ID"
                             , "CURSOR_VULNERABILITY_ID"
                             , "REFRESH_REQUESTED"
                             , "REFRESH_COMPLETED"
                             , "NEXT_DISPATCH_AT"
                             , "LAST_SUCCESS_AT"
                             , "LAST_ERROR_CODE"
                          FROM "ASSESSMENT_SYNC_WORK"
                         WHERE "NEXT_DISPATCH_AT" <= clock_timestamp()
                           AND (
                             "COMPLETED_REVISION" < "REQUESTED_REVISION"
                             OR "REFRESH_COMPLETED" < "REFRESH_REQUESTED"
                           )
                         ORDER BY "NEXT_DISPATCH_AT", "TARGET_UUID"
                         LIMIT :limit
                           FOR UPDATE SKIP LOCKED
                        """)
                .bind("limit", limit)
                .map(WORK_ROW)
                .list();
    }

    public boolean scheduleDispatch(
            final UUID targetUuid, final Instant nextDispatchAt, final @Nullable String lastErrorCode) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireNonNull(nextDispatchAt, "nextDispatchAt must not be null");
        requireTransaction();
        final int updated = handle.createUpdate(/* language=SQL */ """
                        UPDATE "ASSESSMENT_SYNC_WORK"
                           SET "NEXT_DISPATCH_AT" = :nextDispatchAt
                             , "LAST_ERROR_CODE" = :lastErrorCode
                         WHERE "TARGET_UUID" = :targetUuid
                        """)
                .bind("targetUuid", targetUuid)
                .bind("nextDispatchAt", nextDispatchAt)
                .bind("lastErrorCode", lastErrorCode)
                .execute();
        return updated == 1;
    }

    public @Nullable WorkRow find(final UUID targetUuid) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        return handle.createQuery(selectWorkSql() + """
                         WHERE "TARGET_UUID" = :targetUuid
                        """)
                .bind("targetUuid", targetUuid)
                .map(WORK_ROW)
                .findOne()
                .orElse(null);
    }

    public List<PendingFinding> pendingFindings(final UUID targetUuid) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        return handle.createQuery(/* language=SQL */ """
                        SELECT "COMPONENT_ID"
                             , "VULNERABILITY_ID"
                             , "REVISION"
                          FROM "ASSESSMENT_SYNC_FINDING"
                         WHERE "TARGET_UUID" = :targetUuid
                         ORDER BY "COMPONENT_ID", "VULNERABILITY_ID"
                        """)
                .bind("targetUuid", targetUuid)
                .map((rs, ctx) -> new PendingFinding(
                        rs.getLong("COMPONENT_ID"), rs.getLong("VULNERABILITY_ID"), rs.getLong("REVISION")))
                .list();
    }

    private @Nullable WorkRow lock(final UUID targetUuid) {
        return handle.createQuery(selectWorkSql() + """
                         WHERE "TARGET_UUID" = :targetUuid
                           FOR UPDATE
                        """)
                .bind("targetUuid", targetUuid)
                .map(WORK_ROW)
                .findOne()
                .orElse(null);
    }

    private static String selectWorkSql() {
        return """
                SELECT "TARGET_UUID"
                     , "REQUESTED_REVISION"
                     , "COMPLETED_REVISION"
                     , "FULL_REVISION"
                     , "ACTIVE_REVISION"
                     , "ACTIVE_FULL"
                     , "CURSOR_COMPONENT_ID"
                     , "CURSOR_VULNERABILITY_ID"
                     , "REFRESH_REQUESTED"
                     , "REFRESH_COMPLETED"
                     , "NEXT_DISPATCH_AT"
                     , "LAST_SUCCESS_AT"
                     , "LAST_ERROR_CODE"
                  FROM "ASSESSMENT_SYNC_WORK"
                """;
    }

    private static Collection<FindingKey> dedupe(final Collection<FindingKey> keys) {
        final var unique = new LinkedHashMap<FindingKey, FindingKey>();
        for (final FindingKey key : keys) {
            requireNonNull(key, "finding key must not be null");
            unique.putIfAbsent(key, key);
        }
        return unique.values();
    }

    private void requireTransaction() {
        if (!handle.isInTransaction()) {
            throw new IllegalStateException("Assessment work writes require an active transaction");
        }
    }

    private static @Nullable Long nullableLong(final ResultSet rs, final String column) throws SQLException {
        final long value = rs.getLong(column);
        return rs.wasNull() ? null : value;
    }

    private static Instant readInstant(final ResultSet rs, final String column) throws SQLException {
        return requireNonNull(readNullableInstant(rs, column), column);
    }

    private static @Nullable Instant readNullableInstant(final ResultSet rs, final String column) throws SQLException {
        final OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
        return value == null ? null : value.toInstant();
    }

    /// One target's durable progress.
    public record WorkRow(
            UUID targetUuid,
            long requestedRevision,
            long completedRevision,
            long fullRevision,
            @Nullable Long activeRevision,
            boolean activeFull,
            @Nullable Long cursorComponentId,
            @Nullable Long cursorVulnerabilityId,
            long refreshRequested,
            long refreshCompleted,
            Instant nextDispatchAt,
            @Nullable Instant lastSuccessAt,
            @Nullable String lastErrorCode) {

        public WorkRow {
            requireNonNull(targetUuid, "targetUuid must not be null");
            requireNonNull(nextDispatchAt, "nextDispatchAt must not be null");
        }
    }

    /// A pass captured from the locked work row. {@code resumed} means the cursor was kept.
    public record Pass(
            long activeRevision,
            boolean full,
            @Nullable Long cursorComponentId,
            @Nullable Long cursorVulnerabilityId,
            boolean resumed) {}

    /// One pending finding key and the revision that requested it.
    public record PendingFinding(long componentId, long vulnerabilityId, long revision) {}
}
