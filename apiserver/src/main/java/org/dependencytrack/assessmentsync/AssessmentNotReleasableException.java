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

/// Only a local decision can be released (ADR 044).
///
/// Releasing a policy row would drop its suppression until the next policy evaluation.
/// An inherited or neutral row already follows its sources, so there is nothing to release.
/// A row without origin metadata predates the feature and counts as local.
public final class AssessmentNotReleasableException extends RuntimeException {

    public AssessmentNotReleasableException() {
        super("Only a local analysis decision can be released");
    }
}
