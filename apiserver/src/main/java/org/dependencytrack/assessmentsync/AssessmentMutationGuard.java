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

import java.util.Collection;
import java.util.UUID;

import static java.util.Objects.requireNonNull;

/// Transaction-scoped advisory guard for one target project.
///
/// The wait is bounded by the connection query timeout already installed on the handle.
/// This class does not clear that timeout or open a transaction.
public final class AssessmentMutationGuard {

    private AssessmentMutationGuard() {}

    /// Locks one project for the rest of the caller's transaction.
    public static void lockProject(final Handle handle, final UUID projectUuid) {
        requireNonNull(projectUuid, "projectUuid must not be null");
        requireTransaction(handle);
        lockCanonical(handle, projectUuid.toString());
    }

    /// Locks every project in canonical UUID string order.
    public static void lockProjects(final Handle handle, final Collection<UUID> projectUuids) {
        requireNonNull(projectUuids, "projectUuids must not be null");
        requireTransaction(handle);
        projectUuids.stream()
                .map(projectUuid -> requireNonNull(projectUuid, "projectUuid must not be null")
                        .toString())
                .distinct()
                .sorted()
                .forEach(canonical -> lockCanonical(handle, canonical));
    }

    private static void requireTransaction(final Handle handle) {
        requireNonNull(handle, "handle must not be null");
        if (!handle.isInTransaction()) {
            throw new IllegalStateException("Project guard requires an active transaction");
        }
    }

    private static void lockCanonical(final Handle handle, final String projectUuid) {
        handle.createQuery(/* language=SQL */ """
                        SELECT pg_advisory_xact_lock(hashtextextended('assessment-sync:' || CAST(:projectUuid AS text), 0))
                        """)
                .bind("projectUuid", projectUuid)
                .mapToMap()
                .list();
    }
}
