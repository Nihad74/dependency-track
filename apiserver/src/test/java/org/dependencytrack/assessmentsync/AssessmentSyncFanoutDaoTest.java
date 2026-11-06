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

import org.dependencytrack.PersistenceCapableTest;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.useJdbiTransaction;

class AssessmentSyncFanoutDaoTest extends PersistenceCapableTest {
    @Test
    void requiresAHandleAndAnActiveTransactionForBothPageShapes() {
        assertThatThrownBy(() -> new AssessmentSyncFanoutDao(null))
                .isInstanceOf(NullPointerException.class)
                .hasMessage("handle must not be null");
        try (final var handle = openJdbiHandle()) {
            final var dao = new AssessmentSyncFanoutDao(handle);
            assertThatThrownBy(() -> dao.pageProjectTargets(1, 1)).isInstanceOf(IllegalStateException.class);
            assertThatThrownBy(() -> dao.pageFindingTargets(1, 1, 1)).isInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void invalidPageBoundsFailBeforeOpeningAQuery() {
        try (final var handle = openJdbiHandle()) {
            final var dao = new AssessmentSyncFanoutDao(handle);
            for (final int invalid : new int[] {0, -1}) {
                assertThatThrownBy(() -> dao.pageProjectTargets(1, invalid))
                        .isInstanceOf(IllegalArgumentException.class);
                assertThatThrownBy(() -> dao.pageFindingTargets(1, invalid, 1))
                        .isInstanceOf(IllegalArgumentException.class);
                assertThatThrownBy(() -> dao.pageFindingTargets(1, 1, invalid))
                        .isInstanceOf(IllegalArgumentException.class);
            }
        }
    }

    @Test
    void completedOrMissingEventsHaveNoTargets() {
        useJdbiTransaction(h -> {
            final var dao = new AssessmentSyncFanoutDao(h);
            assertThat(dao.pageProjectTargets(Long.MAX_VALUE, 1)).isEmpty();
            assertThat(dao.pageFindingTargets(Long.MAX_VALUE, 1, 1)).isEmpty();
        });
    }
}
