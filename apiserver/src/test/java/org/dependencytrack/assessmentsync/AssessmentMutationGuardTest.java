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
import org.jdbi.v3.core.Handle;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.CyclicBarrier;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.openJdbiHandle;

class AssessmentMutationGuardTest extends PersistenceCapableTest {

    @Test
    void shouldSerializeSameProjectAndLeaveDifferentProjectsUnlocked() throws Exception {
        final UUID project = UUID.fromString("11111111-1111-4111-8111-111111111111");
        final UUID other = UUID.fromString("22222222-2222-4222-8222-222222222222");
        final Handle first = openJdbiHandle();
        final Handle second = openJdbiHandle();
        final Handle third = openJdbiHandle();
        final ExecutorService executor = Executors.newSingleThreadExecutor();
        final var entered = new CountDownLatch(1);
        final var acquired = new CountDownLatch(1);
        try {
            first.begin();
            AssessmentMutationGuard.lockProject(first, project);
            executor.execute(() -> {
                second.begin();
                entered.countDown();
                AssessmentMutationGuard.lockProject(second, project);
                acquired.countDown();
                second.rollback();
            });

            assertThat(entered.await(5, TimeUnit.SECONDS)).isTrue();
            assertThat(acquired.await(300, TimeUnit.MILLISECONDS)).isFalse();

            third.begin();
            AssessmentMutationGuard.lockProject(third, other);
            third.rollback();

            first.rollback();
            assertThat(acquired.await(10, TimeUnit.SECONDS)).isTrue();
        } finally {
            if (first.isInTransaction()) {
                first.rollback();
            }
            if (third.isInTransaction()) {
                third.rollback();
            }
            executor.shutdown();
            assertThat(executor.awaitTermination(15, TimeUnit.SECONDS)).isTrue();
            if (second.isInTransaction()) {
                second.rollback();
            }
            first.close();
            second.close();
            third.close();
        }
    }

    @Test
    void shouldLockSeveralProjectsInCanonicalOrder() throws Exception {
        final UUID low = UUID.fromString("00000000-0000-4000-8000-000000000001");
        final UUID high = UUID.fromString("ffffffff-ffff-4fff-bfff-ffffffffffff");
        final Handle first = openJdbiHandle();
        final Handle second = openJdbiHandle();
        final ExecutorService executor = Executors.newFixedThreadPool(2);
        final var start = new CyclicBarrier(2);
        final var failure = new AtomicReference<Throwable>();
        try {
            final var finished = new CountDownLatch(2);
            executor.execute(() -> lockPair(first, List.of(high, low), start, finished, failure));
            executor.execute(() -> lockPair(second, List.of(low, high), start, finished, failure));
            assertThat(finished.await(5, TimeUnit.SECONDS)).isTrue();
            assertThat(failure.get()).isNull();
        } finally {
            if (first.isInTransaction()) {
                first.rollback();
            }
            if (second.isInTransaction()) {
                second.rollback();
            }
            executor.shutdownNow();
            assertThat(executor.awaitTermination(15, TimeUnit.SECONDS)).isTrue();
            first.close();
            second.close();
        }
    }

    @Test
    void shouldRequireAnOpenTransaction() {
        try (Handle handle = openJdbiHandle()) {
            assertThatThrownBy(() -> AssessmentMutationGuard.lockProject(handle, UUID.randomUUID()))
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    private static void lockPair(
            final Handle handle,
            final List<UUID> projectUuids,
            final CyclicBarrier start,
            final CountDownLatch finished,
            final AtomicReference<Throwable> failure) {
        try {
            start.await(5, TimeUnit.SECONDS);
            handle.begin();
            handle.execute("SET LOCAL statement_timeout = '3s'");
            AssessmentMutationGuard.lockProjects(handle, projectUuids);
            handle.rollback();
        } catch (Throwable thrown) {
            failure.set(thrown);
            if (handle.isInTransaction()) {
                handle.rollback();
            }
        } finally {
            finished.countDown();
        }
    }
}
