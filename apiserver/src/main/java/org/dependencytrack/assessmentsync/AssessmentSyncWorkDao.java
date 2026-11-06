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

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static java.util.Objects.requireNonNull;
import static org.dependencytrack.assessmentsync.DaoSupport.nullableLong;
import static org.dependencytrack.assessmentsync.DaoSupport.readInstant;
import static org.dependencytrack.assessmentsync.DaoSupport.requirePositive;
import static org.dependencytrack.assessmentsync.DaoSupport.requireTransaction;

/**
 * Durable per-target reconciliation and refresh revisions. Mutators lock the work row first.
 *
 * <p>{@code PENDING_SINCE} is set when an idle row receives a request and cleared once reconciliation
 * and refresh have both caught up. Its age is an upper bound on the delay of any pending request.
 */
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
            rs.getInt("DISPATCH_ATTEMPTS"));

    private final Handle handle;

    public AssessmentSyncWorkDao(final Handle handle) {
        this.handle = requireNonNull(handle, "handle must not be null");
    }

    /**
     * Allocates the next revision and marks it as a full-project pass.
     */
    public long requestFull(final UUID targetUuid) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireTransaction(handle);
        return handle.createQuery(/* language=SQL */ """
                        INSERT INTO "ASSESSMENT_SYNC_WORK" (
                          "TARGET_UUID"
                        , "REQUESTED_REVISION"
                        , "FULL_REVISION"
                        , "NEXT_DISPATCH_AT"
                        , "PENDING_SINCE"
                        )
                        VALUES (
                          :targetUuid
                        , 1
                        , 1
                        , date_trunc('milliseconds', clock_timestamp())
                        , date_trunc('milliseconds', clock_timestamp())
                        )
                        ON CONFLICT ("TARGET_UUID") DO UPDATE
                        SET "REQUESTED_REVISION" = "ASSESSMENT_SYNC_WORK"."REQUESTED_REVISION" + 1
                          , "FULL_REVISION" = "ASSESSMENT_SYNC_WORK"."REQUESTED_REVISION" + 1
                          , "NEXT_DISPATCH_AT" = date_trunc('milliseconds', clock_timestamp())
                          , "PENDING_SINCE" = COALESCE(
                              "ASSESSMENT_SYNC_WORK"."PENDING_SINCE"
                            , date_trunc('milliseconds', clock_timestamp())
                            )
                        RETURNING "REQUESTED_REVISION"
                        """)
                .bind("targetUuid", targetUuid)
                .mapTo(long.class)
                .one();
    }

    /**
     * {@link #requestFull(UUID)} for many targets in one statement. Rows are locked in UUID order.
     */
    public void requestFull(final Collection<UUID> targetUuids) {
        requestWork(targetUuids, Map.of());
    }

    /**
     * {@link #requestFindings(UUID, Collection)} for many targets in one statement.
     */
    public void requestFindings(final Map<UUID, ? extends Collection<FindingKey>> keysByTarget) {
        requestWork(List.of(), keysByTarget);
    }

    /**
     * Allocates one revision per target for a mixed page, locking all work rows in UUID order.
     * Full passes take precedence over keys for the same target. Input is validated before SQL.
     */
    public void requestWork(
            final Collection<UUID> fullTargets, final Map<UUID, ? extends Collection<FindingKey>> keysByTarget) {
        requireNonNull(fullTargets, "fullTargets must not be null");
        requireNonNull(keysByTarget, "keysByTarget must not be null");
        requireTransaction(handle);
        final var full = new LinkedHashSet<UUID>();
        for (final UUID uuid : fullTargets) {
            full.add(requireNonNull(uuid, "targetUuid must not be null"));
        }
        final var targets = new LinkedHashSet<>(full);
        final var keyTargets = new ArrayList<UUID>();
        final var componentIds = new ArrayList<Long>();
        final var vulnerabilityIds = new ArrayList<Long>();
        for (final var entry : keysByTarget.entrySet()) {
            final UUID uuid = requireNonNull(entry.getKey(), "targetUuid must not be null");
            final var keys = dedupe(requireNonNull(entry.getValue(), "keys must not be null"));
            targets.add(uuid);
            if (full.contains(uuid)) {
                continue;
            }
            for (final FindingKey key : keys) {
                keyTargets.add(uuid);
                componentIds.add(key.componentId());
                vulnerabilityIds.add(key.vulnDbId());
            }
        }
        if (targets.isEmpty()) {
            return;
        }
        final UUID[] targetUuids = targets.toArray(UUID[]::new);
        final var fullPasses = new boolean[targetUuids.length];
        for (int i = 0; i < targetUuids.length; i++) {
            fullPasses[i] = full.contains(targetUuids[i]);
        }
        handle.createUpdate(/* language=SQL */ """
                        WITH requested AS (
                          INSERT INTO "ASSESSMENT_SYNC_WORK" (
                            "TARGET_UUID"
                          , "REQUESTED_REVISION"
                          , "FULL_REVISION"
                          , "NEXT_DISPATCH_AT"
                          , "PENDING_SINCE"
                          )
                          SELECT t.target_uuid
                               , 1
                               , CASE WHEN t.full_pass THEN 1 ELSE 0 END
                               , date_trunc('milliseconds', clock_timestamp())
                               , date_trunc('milliseconds', clock_timestamp())
                            FROM UNNEST(:targetUuids, :fullPasses) AS t(target_uuid, full_pass)
                           ORDER BY t.target_uuid
                          ON CONFLICT ("TARGET_UUID") DO UPDATE
                          SET "REQUESTED_REVISION" = "ASSESSMENT_SYNC_WORK"."REQUESTED_REVISION" + 1
                            , "FULL_REVISION" = CASE WHEN EXCLUDED."FULL_REVISION" = 1
                                THEN "ASSESSMENT_SYNC_WORK"."REQUESTED_REVISION" + 1
                                ELSE "ASSESSMENT_SYNC_WORK"."FULL_REVISION" END
                            , "NEXT_DISPATCH_AT" = date_trunc('milliseconds', clock_timestamp())
                            , "PENDING_SINCE" = COALESCE(
                                "ASSESSMENT_SYNC_WORK"."PENDING_SINCE"
                              , date_trunc('milliseconds', clock_timestamp())
                              )
                          RETURNING "TARGET_UUID", "REQUESTED_REVISION"
                        )
                        INSERT INTO "ASSESSMENT_SYNC_FINDING" (
                          "TARGET_UUID"
                        , "COMPONENT_ID"
                        , "VULNERABILITY_ID"
                        , "REVISION"
                        )
                        SELECT k.target_uuid
                             , k.component_id
                             , k.vulnerability_id
                             , requested."REQUESTED_REVISION"
                          FROM UNNEST(:keyTargets, :componentIds, :vulnerabilityIds)
                            AS k(target_uuid, component_id, vulnerability_id)
                         INNER JOIN requested
                            ON requested."TARGET_UUID" = k.target_uuid
                        ON CONFLICT ("TARGET_UUID", "COMPONENT_ID", "VULNERABILITY_ID") DO UPDATE
                        SET "REVISION" = GREATEST("ASSESSMENT_SYNC_FINDING"."REVISION", EXCLUDED."REVISION")
                        """)
                .bind("targetUuids", targetUuids)
                .bind("fullPasses", fullPasses)
                .bind("keyTargets", keyTargets.toArray(UUID[]::new))
                .bind(
                        "componentIds",
                        componentIds.stream().mapToLong(Long::longValue).toArray())
                .bind(
                        "vulnerabilityIds",
                        vulnerabilityIds.stream().mapToLong(Long::longValue).toArray())
                .execute();
    }

    /**
     * Allocates the next revision and upserts finding keys at that revision.
     */
    public long requestFindings(final UUID targetUuid, final Collection<FindingKey> keys) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireNonNull(keys, "keys must not be null");
        requireTransaction(handle);
        final Collection<FindingKey> unique = dedupe(keys);
        final long revision = handle.createQuery(/* language=SQL */ """
                        INSERT INTO "ASSESSMENT_SYNC_WORK" (
                          "TARGET_UUID"
                        , "REQUESTED_REVISION"
                        , "NEXT_DISPATCH_AT"
                        , "PENDING_SINCE"
                        )
                        VALUES (
                          :targetUuid
                        , 1
                        , date_trunc('milliseconds', clock_timestamp())
                        , date_trunc('milliseconds', clock_timestamp())
                        )
                        ON CONFLICT ("TARGET_UUID") DO UPDATE
                        SET "REQUESTED_REVISION" = "ASSESSMENT_SYNC_WORK"."REQUESTED_REVISION" + 1
                          , "NEXT_DISPATCH_AT" = date_trunc('milliseconds', clock_timestamp())
                          , "PENDING_SINCE" = COALESCE(
                              "ASSESSMENT_SYNC_WORK"."PENDING_SINCE"
                            , date_trunc('milliseconds', clock_timestamp())
                            )
                        RETURNING "REQUESTED_REVISION"
                        """)
                .bind("targetUuid", targetUuid)
                .mapTo(long.class)
                .one();

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

    /**
     * Captures {@code REQUESTED_REVISION} or resumes the pass already in progress.
     */
    public @Nullable Pass beginOrResumePass(final UUID targetUuid) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireTransaction(handle);
        final WorkRow locked = lock(targetUuid);
        if (locked == null) {
            return null;
        }
        if (locked.activeRevision() != null) {
            return new Pass(locked.activeRevision(), locked.activeFull(), locked.cursor(), true);
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
                        """)
                .bind("targetUuid", targetUuid)
                .map((rs, ctx) -> new Pass(rs.getLong("ACTIVE_REVISION"), rs.getBoolean("ACTIVE_FULL"), null, false))
                .one();
    }

    /**
     * Saves the keyset cursor for the captured pass. A mismatched revision is left unchanged.
     */
    public boolean advancePass(final UUID targetUuid, final long activeRevision, final FindingKey cursor) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireTransaction(handle);
        lock(targetUuid);
        final int updated = handle.createUpdate(/* language=SQL */ """
                        UPDATE "ASSESSMENT_SYNC_WORK"
                           SET "CURSOR_COMPONENT_ID" = :cursorComponentId
                             , "CURSOR_VULNERABILITY_ID" = :cursorVulnerabilityId
                             , "DISPATCH_ATTEMPTS" = 0
                             , "NEXT_DISPATCH_AT" = LEAST("NEXT_DISPATCH_AT", date_trunc('milliseconds', clock_timestamp()))
                         WHERE "TARGET_UUID" = :targetUuid
                           AND "ACTIVE_REVISION" = :activeRevision
                        """)
                .bind("targetUuid", targetUuid)
                .bind("activeRevision", activeRevision)
                .bind("cursorComponentId", cursor.componentId())
                .bind("cursorVulnerabilityId", cursor.vulnDbId())
                .execute();
        return updated == 1;
    }

    /**
     * Acknowledges only {@code activeRevision}. Newer finding rows and a newer full request stay pending.
     */
    public boolean completePass(final UUID targetUuid, final long activeRevision) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireTransaction(handle);
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
                             , "DISPATCH_ATTEMPTS" = 0
                             , "NEXT_DISPATCH_AT" = CASE
                                 WHEN "REQUESTED_REVISION" = :activeRevision
                                  AND "REFRESH_COMPLETED" = "REFRESH_REQUESTED"
                                 THEN "NEXT_DISPATCH_AT"
                                 ELSE LEAST("NEXT_DISPATCH_AT", date_trunc('milliseconds', clock_timestamp()))
                               END
                             , "PENDING_SINCE" = CASE
                                 WHEN "REQUESTED_REVISION" = :activeRevision
                                  AND "REFRESH_COMPLETED" = "REFRESH_REQUESTED"
                                 THEN NULL
                                 ELSE "PENDING_SINCE"
                               END
                         WHERE "TARGET_UUID" = :targetUuid
                           AND "ACTIVE_REVISION" = :activeRevision
                        """)
                .bind("targetUuid", targetUuid)
                .bind("activeRevision", activeRevision)
                .execute();
        return updated == 1;
    }

    /**
     * Completes reconciliation and refresh for a target that no longer exists.
     *
     * <p>Pending finding keys are removed. Newer work cannot arrive for a deleted project
     * through this row once both revisions are caught up.
     */
    public boolean acknowledgeCancellation(final UUID targetUuid) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireTransaction(handle);
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
                             , "DISPATCH_ATTEMPTS" = 0
                             , "PENDING_SINCE" = NULL
                         WHERE "TARGET_UUID" = :targetUuid
                        """)
                .bind("targetUuid", targetUuid)
                .execute();
        return updated == 1;
    }

    public long requestRefresh(final UUID targetUuid) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireTransaction(handle);
        return handle.createQuery(/* language=SQL */ """
                        INSERT INTO "ASSESSMENT_SYNC_WORK" (
                          "TARGET_UUID"
                        , "REFRESH_REQUESTED"
                        , "NEXT_DISPATCH_AT"
                        , "PENDING_SINCE"
                        )
                        VALUES (
                          :targetUuid
                        , 1
                        , date_trunc('milliseconds', clock_timestamp())
                        , date_trunc('milliseconds', clock_timestamp())
                        )
                        ON CONFLICT ("TARGET_UUID") DO UPDATE
                        SET "REFRESH_REQUESTED" = "ASSESSMENT_SYNC_WORK"."REFRESH_REQUESTED" + 1
                          , "NEXT_DISPATCH_AT" = date_trunc('milliseconds', clock_timestamp())
                          , "PENDING_SINCE" = COALESCE(
                              "ASSESSMENT_SYNC_WORK"."PENDING_SINCE"
                            , date_trunc('milliseconds', clock_timestamp())
                            )
                        RETURNING "REFRESH_REQUESTED"
                        """)
                .bind("targetUuid", targetUuid)
                .mapTo(long.class)
                .one();
    }

    /**
     * Advances refresh completion up to {@code capturedRefresh}, and never past the requested value.
     */
    public long acknowledgeRefresh(final UUID targetUuid, final long capturedRefresh) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        if (capturedRefresh < 0) {
            throw new IllegalArgumentException("capturedRefresh must not be negative");
        }
        requireTransaction(handle);
        if (lock(targetUuid) == null) {
            throw new IllegalStateException("No assessment sync work for " + targetUuid);
        }
        return handle.createQuery(/* language=SQL */ """
                        UPDATE "ASSESSMENT_SYNC_WORK"
                           SET "DISPATCH_ATTEMPTS" = 0
                             , "NEXT_DISPATCH_AT" = CASE
                                 WHEN "COMPLETED_REVISION" = "REQUESTED_REVISION"
                                  AND LEAST(
                                        "REFRESH_REQUESTED"
                                      , GREATEST("REFRESH_COMPLETED", :capturedRefresh)
                                      ) = "REFRESH_REQUESTED"
                                 THEN "NEXT_DISPATCH_AT"
                                 ELSE LEAST("NEXT_DISPATCH_AT", date_trunc('milliseconds', clock_timestamp()))
                               END
                             , "REFRESH_COMPLETED" = LEAST(
                                 "REFRESH_REQUESTED"
                               , GREATEST("REFRESH_COMPLETED", :capturedRefresh)
                               )
                             , "PENDING_SINCE" = CASE
                                 WHEN "COMPLETED_REVISION" = "REQUESTED_REVISION"
                                  AND LEAST(
                                        "REFRESH_REQUESTED"
                                      , GREATEST("REFRESH_COMPLETED", :capturedRefresh)
                                      ) = "REFRESH_REQUESTED"
                                 THEN NULL
                                 ELSE "PENDING_SINCE"
                               END
                         WHERE "TARGET_UUID" = :targetUuid
                        RETURNING "REFRESH_COMPLETED"
                        """)
                .bind("targetUuid", targetUuid)
                .bind("capturedRefresh", capturedRefresh)
                .mapTo(long.class)
                .one();
    }

    /**
     * Locks due rows whose reconciliation or refresh is unfinished. Without {@code includeReconciliation},
     * only rows with a refresh pending are returned.
     */
    public List<WorkRow> pollDue(final int limit, final boolean includeReconciliation) {
        requireTransaction(handle);
        requirePositive(limit, "limit");
        return handle.createQuery(selectWorkSql() + /* language=SQL */ """
                         WHERE "NEXT_DISPATCH_AT" <= clock_timestamp()
                           AND (
                             (:includeReconciliation AND "COMPLETED_REVISION" < "REQUESTED_REVISION")
                             OR "REFRESH_COMPLETED" < "REFRESH_REQUESTED"
                           )
                         ORDER BY "NEXT_DISPATCH_AT", "TARGET_UUID"
                         LIMIT :limit
                           FOR UPDATE SKIP LOCKED
                        """)
                .bind("limit", limit)
                .bind("includeReconciliation", includeReconciliation)
                .map(WORK_ROW)
                .list();
    }

    /**
     * Pushes the next dispatch back. Attempts reset when a pass or refresh makes progress.
     */
    public boolean recordDispatchAttempt(final UUID targetUuid, final Instant nextDispatchAt) {
        return recordDispatchAttempts(Map.of(targetUuid, nextDispatchAt)) == 1;
    }

    /**
     * Records one dispatch attempt per target in one statement.
     */
    public int recordDispatchAttempts(final Map<UUID, Instant> nextDispatchAtByTarget) {
        requireNonNull(nextDispatchAtByTarget, "nextDispatchAtByTarget must not be null");
        requireTransaction(handle);
        if (nextDispatchAtByTarget.isEmpty()) {
            return 0;
        }
        final var targetUuids = new UUID[nextDispatchAtByTarget.size()];
        final var nextDispatchAtMillis = new long[nextDispatchAtByTarget.size()];
        int i = 0;
        for (final var entry : nextDispatchAtByTarget.entrySet()) {
            targetUuids[i] = requireNonNull(entry.getKey(), "targetUuid must not be null");
            nextDispatchAtMillis[i] = requireNonNull(entry.getValue(), "nextDispatchAt must not be null")
                    .toEpochMilli();
            i++;
        }
        return handle.createUpdate(/* language=SQL */ """
                        UPDATE "ASSESSMENT_SYNC_WORK" AS w
                           SET "NEXT_DISPATCH_AT" = to_timestamp(t.next_dispatch_at_ms / 1000.0)
                             , "DISPATCH_ATTEMPTS" = w."DISPATCH_ATTEMPTS" + 1
                          FROM UNNEST(:targetUuids, :nextDispatchAtMillis) AS t(target_uuid, next_dispatch_at_ms)
                         WHERE w."TARGET_UUID" = t.target_uuid
                        """)
                .bind("targetUuids", targetUuids)
                .bind("nextDispatchAtMillis", nextDispatchAtMillis)
                .execute();
    }

    /**
     * Moves the next dispatch without counting an attempt, for work deferred on purpose.
     */
    public boolean scheduleDispatch(final UUID targetUuid, final Instant nextDispatchAt) {
        requireNonNull(targetUuid, "targetUuid must not be null");
        requireNonNull(nextDispatchAt, "nextDispatchAt must not be null");
        requireTransaction(handle);
        final int updated = handle.createUpdate(/* language=SQL */ """
                        UPDATE "ASSESSMENT_SYNC_WORK"
                           SET "NEXT_DISPATCH_AT" = :nextDispatchAt
                         WHERE "TARGET_UUID" = :targetUuid
                        """)
                .bind("targetUuid", targetUuid)
                .bind("nextDispatchAt", nextDispatchAt)
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
                     , "DISPATCH_ATTEMPTS"
                  FROM "ASSESSMENT_SYNC_WORK"
                """;
    }

    private static Collection<FindingKey> dedupe(final Collection<FindingKey> keys) {
        final var unique = new LinkedHashSet<FindingKey>();
        for (final FindingKey key : keys) {
            requireNonNull(key, "finding key must not be null");
            unique.add(key);
        }
        return unique;
    }

    /**
     * One target's durable progress.
     */
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
            int dispatchAttempts) {

        public WorkRow {
            requireNonNull(targetUuid, "targetUuid must not be null");
            requireNonNull(nextDispatchAt, "nextDispatchAt must not be null");
        }

        /**
         * The saved keyset cursor, or null when the pass has not finished a finding yet.
         */
        public @Nullable FindingKey cursor() {
            return cursorComponentId == null || cursorVulnerabilityId == null
                    ? null
                    : new FindingKey(cursorComponentId, cursorVulnerabilityId);
        }
    }

    /**
     * A pass captured from the locked work row. {@code resumed} means the cursor was kept.
     * One captured pass. {@code cursor} is the last finding finished, or null at the start.
     */
    public record Pass(
            long activeRevision, boolean full, @Nullable FindingKey cursor, boolean resumed) {}

    /**
     * One pending finding key and the revision that requested it.
     */
    public record PendingFinding(long componentId, long vulnerabilityId, long revision) {}
}
