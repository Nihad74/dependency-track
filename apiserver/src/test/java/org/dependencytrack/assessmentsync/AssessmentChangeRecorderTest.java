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
import org.dependencytrack.common.ConfigKeys;
import org.dependencytrack.support.config.source.memory.MemoryConfigSource;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class AssessmentChangeRecorderTest extends PersistenceCapableTest {

    @AfterEach
    void resetMode() {
        MemoryConfigSource.removeProperty(ConfigKeys.ASSESSMENT_SYNC_MODE);
    }

    @ParameterizedTest
    @EnumSource(AssessmentSyncMode.class)
    void onlyCaptureAndActivePersistChanges(final AssessmentSyncMode mode) {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, mode.name());
        inJdbiTransaction(handle -> {
            new AssessmentChangeRecorder(handle).record(change());
            return null;
        });
        assertThat(count()).isEqualTo(mode == AssessmentSyncMode.CAPTURE || mode == AssessmentSyncMode.ACTIVE ? 1 : 0);
    }

    @Test
    void sameRecorderReadsModeAgainOnEveryCall() {
        inJdbiTransaction(handle -> {
            final var recorder = new AssessmentChangeRecorder(handle);
            for (final String mode : List.of("OFF", "CAPTURE", "WITHDRAW", "ACTIVE")) {
                MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, mode);
                recorder.record(change());
            }
            assertThat(handle.createQuery("SELECT count(*) FROM \"ASSESSMENT_SYNC_OUTBOX\"")
                            .mapTo(int.class)
                            .one())
                    .isEqualTo(2);
            return null;
        });
    }

    @Test
    void enabledCaptureRequiresATransactionButDisabledAndEmptyBatchesDoNotWrite() {
        try (final var handle = openJdbiHandle()) {
            final var recorder = new AssessmentChangeRecorder(handle);
            recorder.record(change()); // default OFF
            MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "ACTIVE");
            recorder.recordAll(List.of());
            assertThatThrownBy(() -> recorder.record(change())).isInstanceOf(IllegalStateException.class);
            assertThatThrownBy(() -> recorder.recordAll(null)).isInstanceOf(NullPointerException.class);
        }
        assertThat(count()).isZero();
    }

    @Test
    void captureParticipatesInTheCallersRollback() {
        MemoryConfigSource.setProperty(ConfigKeys.ASSESSMENT_SYNC_MODE, "CAPTURE");
        try (final var handle = openJdbiHandle()) {
            handle.begin();
            new AssessmentChangeRecorder(handle).record(change());
            handle.rollback();
        }
        assertThat(count()).isZero();
    }

    private static AssessmentChange change() {
        return AssessmentChange.project(UUID.randomUUID(), AssessmentChange.Reason.PROJECT_UPDATED, "project", "1");
    }

    private static int count() {
        return withJdbiHandle(handle -> handle.createQuery("SELECT count(*) FROM \"ASSESSMENT_SYNC_OUTBOX\"")
                .mapTo(int.class)
                .one());
    }
}
