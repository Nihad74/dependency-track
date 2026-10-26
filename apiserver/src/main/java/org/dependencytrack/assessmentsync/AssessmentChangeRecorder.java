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

import org.dependencytrack.assessmentsync.AssessmentChange.LookupKey;
import org.jdbi.v3.core.Handle;
import org.jspecify.annotations.Nullable;

import java.util.Collection;
import java.util.List;

import static java.util.Objects.requireNonNull;

/// Writes assessment invalidations through the caller's transaction.
///
/// Does not commit, open a transaction, or call Dex.
public final class AssessmentChangeRecorder {

    public static final String AUTHORED = "AUTHORED";
    public static final String POLICY = "POLICY";
    public static final String POLICY_UNASSIGNED = "POLICY_UNASSIGNED";

    private final Handle handle;

    public AssessmentChangeRecorder(final Handle handle) {
        this.handle = requireNonNull(handle, "handle must not be null");
    }

    /// Records one change when the current mode captures outbox rows.
    public void record(final AssessmentChange change) {
        recordAll(List.of(change));
    }

    /// Records a batch when the current mode captures outbox rows.
    public void recordAll(final Collection<AssessmentChange> changes) {
        requireNonNull(changes, "changes must not be null");
        if (changes.isEmpty() || !AssessmentSyncMode.current().recordsOutbox()) {
            return;
        }
        new AssessmentSyncOutboxDao(handle).recordAll(changes);
    }

    /// One lookup key when both name and version are present.
    public static List<LookupKey> lookupKeys(final @Nullable String name, final @Nullable String version) {
        if (name == null || version == null || name.isBlank() || version.isBlank()) {
            return List.of();
        }
        return List.of(new LookupKey(name, version));
    }
}
