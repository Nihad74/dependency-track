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
package org.dependencytrack.pkghealth.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.dependencytrack.common.HttpClient;
import org.dependencytrack.common.Mappers;
import org.jspecify.annotations.NullMarked;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Optional;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;

@NullMarked
abstract class ApiClient {

    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);

    protected final java.net.http.HttpClient httpClient;
    protected final ObjectMapper objectMapper;

    protected ApiClient() {
        this(HttpClient.INSTANCE, Mappers.jsonMapper());
    }

    protected ApiClient(java.net.http.HttpClient httpClient, ObjectMapper objectMapper) {
        this.httpClient = requireNonNull(httpClient, "httpClient must not be null");
        this.objectMapper = requireNonNull(objectMapper, "objectMapper must not be null");
    }

    protected final HttpResponse<String> get(String url) throws IOException, InterruptedException {
        final HttpRequest.Builder requestBuilder = HttpRequest.newBuilder(URI.create(url))
                .timeout(REQUEST_TIMEOUT)
                .header("Accept", "application/json")
                .GET();

        configureRequest(requestBuilder);

        try {
            return httpClient.send(requestBuilder.build(), HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw e;
        }
    }

    protected final Optional<JsonNode> requestJson(String url) throws IOException, InterruptedException {
        final HttpResponse<String> response = get(url);

        if (response.statusCode() == 404 || response.statusCode() == 204) {
            return Optional.empty();
        }

        if (response.statusCode() != 200) {
            throw new IOException("API returned HTTP %d for %s".formatted(response.statusCode(), url));
        }

        return Optional.of(objectMapper.readTree(response.body()));
    }

    protected final <T> Optional<T> requestParseJsonForResult(String url, Function<JsonNode, Optional<T>> parser)
            throws IOException, InterruptedException {
        requireNonNull(parser, "parser must not be null");

        final Optional<JsonNode> response = requestJson(url);
        if (response.isEmpty()) {
            return Optional.empty();
        }

        try {
            return requireNonNull(parser.apply(response.get()), "parser result must not be null");
        } catch (RuntimeException e) {
            throw new IOException("Failed to parse API response from " + url, e);
        }
    }

    protected void configureRequest(HttpRequest.Builder requestBuilder) {
        // Subclasses may add headers, for example GitHub authentication.
    }

    protected final String urlEncode(String value) {
        requireNonNull(value, "value must not be null");

        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
