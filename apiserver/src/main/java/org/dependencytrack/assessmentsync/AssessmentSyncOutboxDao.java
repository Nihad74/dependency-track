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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import org.dependencytrack.assessmentsync.AssessmentChange.LookupKey;
import org.dependencytrack.assessmentsync.AssessmentChange.Scope;
import org.jdbi.v3.core.Handle;
import org.jdbi.v3.core.mapper.RowMapper;
import org.jdbi.v3.jackson2.Jackson2Config;
import org.jspecify.annotations.Nullable;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/// Transactional outbox for assessment invalidations. Uses the caller's handle and transaction.
public final class AssessmentSyncOutboxDao {

    private static final TypeReference<List<LookupKey>> LOOKUP_KEYS = new TypeReference<>() {};

    private final Handle handle;

    public AssessmentSyncOutboxDao(final Handle handle) {
        this.handle = requireNonNull(handle, "handle must not be null");
    }

    /// Inserts one change. A same-transaction conflict keeps the row and unions lookup keys.
    public long record(final AssessmentChange change) {
        final List<Long> ids = recordAll(List.of(change));
        if (ids.size() != 1) {
            throw new IllegalStateException("Expected one outbox id, got " + ids.size());
        }
        return ids.getFirst();
    }

    /// Inserts a batch. Rows already stored in this transaction are merged, not replaced.
    public List<Long> recordAll(final Collection<AssessmentChange> changes) {
        requireNonNull(changes, "changes must not be null");
        requireTransaction();
        final List<AssessmentChange> coalesced = coalesce(changes);
        if (coalesced.isEmpty()) {
            return List.of();
        }

        final var scopeKeys = new String[coalesced.size()];
        final var scopes = new String[coalesced.size()];
        final var projectUuids = new UUID[coalesced.size()];
        final var componentUuids = new @Nullable UUID[coalesced.size()];
        final var vulnerabilityUuids = new @Nullable UUID[coalesced.size()];
        final var reasons = new String[coalesced.size()];
        final var lookupKeys = new String[coalesced.size()];
        for (int i = 0; i < coalesced.size(); i++) {
            final AssessmentChange change = coalesced.get(i);
            scopeKeys[i] = change.scopeKey();
            scopes[i] = change.scope().name();
            projectUuids[i] = change.projectUuid();
            componentUuids[i] = change.componentUuid();
            vulnerabilityUuids[i] = change.vulnerabilityUuid();
            reasons[i] = change.reason();
            lookupKeys[i] = writeLookupKeys(change.lookupKeys());
        }

        // In-batch duplicates are coalesced so one INSERT does not update the same conflict
        // row twice. Durable same-transaction dedup is still the unique (transaction, scope) merge.
        return handle.createQuery(/* language=SQL */ """
                        INSERT INTO "ASSESSMENT_SYNC_OUTBOX" (
                          "SCOPE_KEY"
                        , "SCOPE"
                        , "PROJECT_UUID"
                        , "COMPONENT_UUID"
                        , "VULNERABILITY_UUID"
                        , "REASON"
                        , "LOOKUP_KEYS"
                        , "NEXT_DISPATCH_AT"
                        )
                        SELECT t.scope_key
                             , t.scope
                             , t.project_uuid
                             , t.component_uuid
                             , t.vulnerability_uuid
                             , t.reason
                             , CAST(t.lookup_key AS jsonb)
                             , date_trunc('milliseconds', clock_timestamp())
                          FROM UNNEST(
                                 :scopeKeys
                               , :scopes
                               , :projectUuids
                               , :componentUuids
                               , :vulnerabilityUuids
                               , :reasons
                               , :lookupKeys
                               ) AS t(
                                 scope_key
                               , scope
                               , project_uuid
                               , component_uuid
                               , vulnerability_uuid
                               , reason
                               , lookup_key
                               )
                        ON CONFLICT ("TRANSACTION_ID", "SCOPE_KEY") DO UPDATE
                        SET "LOOKUP_KEYS" = (
                              SELECT COALESCE(
                                       jsonb_agg(deduped.element ORDER BY deduped.element->>'name', deduped.element->>'version')
                                     , '[]'::jsonb
                                     )
                                FROM (
                                  SELECT DISTINCT expanded.element
                                    FROM jsonb_array_elements(
                                           "ASSESSMENT_SYNC_OUTBOX"."LOOKUP_KEYS" || EXCLUDED."LOOKUP_KEYS"
                                         ) AS expanded(element)
                                ) AS deduped(element)
                            )
                        RETURNING "ID"
                        """)
                .bind("scopeKeys", scopeKeys)
                .bind("scopes", scopes)
                .bind("projectUuids", projectUuids)
                .bind("componentUuids", componentUuids)
                .bind("vulnerabilityUuids", vulnerabilityUuids)
                .bind("reasons", reasons)
                .bind("lookupKeys", lookupKeys)
                .mapTo(long.class)
                .list();
    }

    /// Locks due rows without deleting them. A lower id committed later is still eligible.
    public List<OutboxEntry> pollDue(final int limit) {
        requireTransaction();
        requireLimit(limit);
        return handle.createQuery(/* language=SQL */ """
                        SELECT "ID"
                             , "SCHEMA_VERSION"
                             , "SCOPE"
                             , "PROJECT_UUID"
                             , "COMPONENT_UUID"
                             , "VULNERABILITY_UUID"
                             , "REASON"
                             , "LOOKUP_KEYS"::text AS "LOOKUP_KEYS"
                             , "FANOUT_CURSOR"
                             , "CREATED_AT"
                             , "NEXT_DISPATCH_AT"
                             , "DISPATCH_ATTEMPTS"
                             , "LAST_ERROR_CODE"
                          FROM "ASSESSMENT_SYNC_OUTBOX"
                         WHERE "NEXT_DISPATCH_AT" <= clock_timestamp()
                         ORDER BY "NEXT_DISPATCH_AT", "ID"
                         LIMIT :limit
                           FOR UPDATE SKIP LOCKED
                        """)
                .bind("limit", limit)
                .map(entryMapper())
                .list();
    }

    /// Locks one row so the caller can advance its expansion cursor. Null means it was deleted.
    public @Nullable OutboxEntry lock(final long id) {
        requireTransaction();
        return handle.createQuery(/* language=SQL */ """
                        SELECT "ID"
                             , "SCHEMA_VERSION"
                             , "SCOPE"
                             , "PROJECT_UUID"
                             , "COMPONENT_UUID"
                             , "VULNERABILITY_UUID"
                             , "REASON"
                             , "LOOKUP_KEYS"::text AS "LOOKUP_KEYS"
                             , "FANOUT_CURSOR"
                             , "CREATED_AT"
                             , "NEXT_DISPATCH_AT"
                             , "DISPATCH_ATTEMPTS"
                             , "LAST_ERROR_CODE"
                          FROM "ASSESSMENT_SYNC_OUTBOX"
                         WHERE "ID" = :id
                           FOR UPDATE
                        """)
                .bind("id", id)
                .map(entryMapper())
                .findOne()
                .orElse(null);
    }

    public boolean updateFanoutCursor(final long id, final UUID fanoutCursor) {
        requireNonNull(fanoutCursor, "fanoutCursor must not be null");
        requireTransaction();
        final int updated = handle.createUpdate(/* language=SQL */ """
                        UPDATE "ASSESSMENT_SYNC_OUTBOX"
                           SET "FANOUT_CURSOR" = :fanoutCursor
                         WHERE "ID" = :id
                        """)
                .bind("id", id)
                .bind("fanoutCursor", fanoutCursor)
                .execute();
        return updated == 1;
    }

    /// Records a dispatch attempt. False means expansion already deleted the row.
    public boolean recordDispatchAttempt(
            final long id, final Instant nextDispatchAt, final @Nullable String lastErrorCode) {
        requireNonNull(nextDispatchAt, "nextDispatchAt must not be null");
        requireTransaction();
        final int updated = handle.createUpdate(/* language=SQL */ """
                        UPDATE "ASSESSMENT_SYNC_OUTBOX"
                           SET "NEXT_DISPATCH_AT" = :nextDispatchAt
                             , "DISPATCH_ATTEMPTS" = "DISPATCH_ATTEMPTS" + 1
                             , "LAST_ERROR_CODE" = :lastErrorCode
                         WHERE "ID" = :id
                        """)
                .bind("id", id)
                .bind("nextDispatchAt", nextDispatchAt)
                .bind("lastErrorCode", lastErrorCode)
                .execute();
        return updated == 1;
    }

    /// Deletes the row after the caller has finished expansion.
    public boolean deleteFinished(final long id) {
        requireTransaction();
        final int deleted =
                handle.createUpdate(/* language=SQL */ """
                        DELETE FROM "ASSESSMENT_SYNC_OUTBOX"
                         WHERE "ID" = :id
                        """).bind("id", id).execute();
        return deleted == 1;
    }

    private RowMapper<OutboxEntry> entryMapper() {
        return (rs, ctx) -> new OutboxEntry(
                rs.getLong("ID"),
                rs.getInt("SCHEMA_VERSION"),
                new AssessmentChange(
                        Scope.valueOf(rs.getString("SCOPE")),
                        rs.getObject("PROJECT_UUID", UUID.class),
                        rs.getObject("COMPONENT_UUID", UUID.class),
                        rs.getObject("VULNERABILITY_UUID", UUID.class),
                        rs.getString("REASON"),
                        readLookupKeys(rs.getString("LOOKUP_KEYS"))),
                rs.getObject("FANOUT_CURSOR", UUID.class),
                readInstant(rs, "CREATED_AT"),
                readInstant(rs, "NEXT_DISPATCH_AT"),
                rs.getInt("DISPATCH_ATTEMPTS"),
                rs.getString("LAST_ERROR_CODE"));
    }

    private List<AssessmentChange> coalesce(final Collection<AssessmentChange> changes) {
        final var byScopeKey = new LinkedHashMap<String, AssessmentChange>();
        for (final AssessmentChange change : changes) {
            requireNonNull(change, "change must not be null");
            final AssessmentChange existing = byScopeKey.get(change.scopeKey());
            if (existing == null) {
                byScopeKey.put(change.scopeKey(), change);
                continue;
            }
            final var keys = new ArrayList<LookupKey>(existing.lookupKeys());
            keys.addAll(change.lookupKeys());
            byScopeKey.put(
                    change.scopeKey(),
                    new AssessmentChange(
                            existing.scope(),
                            existing.projectUuid(),
                            existing.componentUuid(),
                            existing.vulnerabilityUuid(),
                            existing.reason(),
                            keys));
        }
        return List.copyOf(byScopeKey.values());
    }

    private String writeLookupKeys(final List<LookupKey> keys) {
        try {
            return handle.getConfig(Jackson2Config.class).getMapper().writeValueAsString(keys);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not encode lookup keys", e);
        }
    }

    private List<LookupKey> readLookupKeys(final String json) {
        try {
            final List<LookupKey> keys =
                    handle.getConfig(Jackson2Config.class).getMapper().readValue(json, LOOKUP_KEYS);
            return List.copyOf(keys);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Could not read lookup keys", e);
        }
    }

    private void requireTransaction() {
        if (!handle.isInTransaction()) {
            throw new IllegalStateException("Assessment outbox writes require an active transaction");
        }
    }

    private static void requireLimit(final int limit) {
        if (limit <= 0) {
            throw new IllegalArgumentException("limit must be positive");
        }
    }

    private static Instant readInstant(final ResultSet rs, final String column) throws SQLException {
        final OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
        return requireNonNull(value, column).toInstant();
    }

    /// One durable outbox row. {@code change} is the stored invalidation.
    public record OutboxEntry(
            long id,
            int schemaVersion,
            AssessmentChange change,
            @Nullable UUID fanoutCursor,
            Instant createdAt,
            Instant nextDispatchAt,
            int dispatchAttempts,
            @Nullable String lastErrorCode) {

        public OutboxEntry {
            requireNonNull(change, "change must not be null");
            requireNonNull(createdAt, "createdAt must not be null");
            requireNonNull(nextDispatchAt, "nextDispatchAt must not be null");
        }
    }
}
