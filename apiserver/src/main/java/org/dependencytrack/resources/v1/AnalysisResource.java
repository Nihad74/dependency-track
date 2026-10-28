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
package org.dependencytrack.resources.v1;

import alpine.common.validation.RegexSequence;
import alpine.common.validation.ValidationTask;
import alpine.model.auth.Principal;
import alpine.server.auth.PermissionRequired;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.apache.commons.lang3.StringUtils;
import org.dependencytrack.assessmentsync.AssessmentMutationGuard;
import org.dependencytrack.assessmentsync.AssessmentNotReleasableException;
import org.dependencytrack.assessmentsync.AssessmentOwnership;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao;
import org.dependencytrack.assessmentsync.AssessmentTrailAssembler;
import org.dependencytrack.assessmentsync.StaleAssessmentDecisionException;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisJustification;
import org.dependencytrack.model.AnalysisResponse;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.model.validation.ValidUuid;
import org.dependencytrack.persistence.QueryManager;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.jdbi.JdbiFactory;
import org.dependencytrack.resources.AbstractApiResource;
import org.dependencytrack.resources.v1.problems.ProblemDetails;
import org.dependencytrack.resources.v1.vo.AnalysisRequest;
import org.dependencytrack.resources.v1.vo.AnalysisRequest.DecisionAction;
import org.dependencytrack.resources.v1.vo.AnalysisTrailResponse;

import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.List;

import static java.util.Objects.requireNonNullElse;

/**
 * JAX-RS resources for processing analysis decisions.
 *
 * @author Steve Springett
 * @since 3.1.0
 */
@Path("/v1/analysis")
@Tag(name = "analysis")
@SecurityRequirements({@SecurityRequirement(name = "ApiKeyAuth"), @SecurityRequirement(name = "BearerAuth")})
public class AnalysisResource extends AbstractApiResource {

    @GET
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Retrieves an analysis trail",
            description = "<p>Requires permission <strong>VIEW_VULNERABILITY</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "An analysis trail",
                        content = @Content(schema = @Schema(implementation = AnalysisTrailResponse.class))),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the requested project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(
                        responseCode = "404",
                        description = "The project, component, or vulnerability could not be found")
            })
    @PermissionRequired(Permissions.Constants.VIEW_VULNERABILITY)
    public Response retrieveAnalysis(
            @Parameter(description = "The UUID of the project", schema = @Schema(type = "string", format = "uuid"))
                    @QueryParam("project")
                    @ValidUuid
                    String projectUuid,
            @Parameter(
                            description = "The UUID of the component",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @QueryParam("component")
                    @ValidUuid
                    String componentUuid,
            @Parameter(
                            description = "The UUID of the vulnerability",
                            schema = @Schema(type = "string", format = "uuid"),
                            required = true)
                    @QueryParam("vulnerability")
                    @ValidUuid
                    String vulnerabilityUuid) {
        failOnValidationError(
                new ValidationTask(
                        RegexSequence.Pattern.UUID,
                        projectUuid,
                        "Project is not a valid UUID",
                        false), // this is optional
                new ValidationTask(RegexSequence.Pattern.UUID, componentUuid, "Component is not a valid UUID"),
                new ValidationTask(RegexSequence.Pattern.UUID, vulnerabilityUuid, "Vulnerability is not a valid UUID"));
        try (QueryManager qm = new QueryManager(getAlpineRequest())) {
            if (StringUtils.trimToNull(projectUuid) != null) {
                final Project project = qm.getObjectByUuid(Project.class, projectUuid);
                if (project == null) {
                    return Response.status(Response.Status.NOT_FOUND)
                            .entity("The project could not be found.")
                            .build();
                }
            }
            final Component component = qm.getObjectByUuid(Component.class, componentUuid);
            if (component == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The component could not be found.")
                        .build();
            }
            requireAccess(qm, component.getProject());
            final Vulnerability vulnerability = qm.getObjectByUuid(Vulnerability.class, vulnerabilityUuid);
            if (vulnerability == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("The vulnerability could not be found.")
                        .build();
            }
            final Analysis analysis = qm.getAnalysis(component, vulnerability);
            if (analysis == null) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("No analysis exists.")
                        .build();
            }
            return Response.ok(trail(qm, analysis)).build();
        }
    }

    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Operation(
            summary = "Records an analysis decision",
            description =
                    "<p>Requires permission <strong>VULNERABILITY_ANALYSIS</strong></strong> or <strong>VULNERABILITY_ANALYSIS_UPDATE</strong></p>")
    @ApiResponses(
            value = {
                @ApiResponse(
                        responseCode = "200",
                        description = "The created analysis",
                        content = @Content(schema = @Schema(implementation = AnalysisTrailResponse.class))),
                @ApiResponse(responseCode = "401", description = "Unauthorized"),
                @ApiResponse(
                        responseCode = "403",
                        description = "Access to the requested project is forbidden",
                        content =
                                @Content(
                                        schema = @Schema(implementation = ProblemDetails.class),
                                        mediaType = ProblemDetails.MEDIA_TYPE_JSON)),
                @ApiResponse(
                        responseCode = "400",
                        description = "The decision action does not match the supplied fields"),
                @ApiResponse(
                        responseCode = "404",
                        description = "The project, component, or vulnerability could not be found"),
                @ApiResponse(
                        responseCode = "409",
                        description = "The supplied decision version is stale, or RELEASE_LOCAL targets a decision"
                                + " that is not local")
            })
    @PermissionRequired({
        Permissions.Constants.VULNERABILITY_ANALYSIS,
        Permissions.Constants.VULNERABILITY_ANALYSIS_UPDATE
    })
    public Response updateAnalysis(AnalysisRequest request) {
        final Validator validator = getValidator();
        failOnValidationError(
                validator.validateProperty(request, "project"),
                validator.validateProperty(request, "component"),
                validator.validateProperty(request, "vulnerability"),
                validator.validateProperty(request, "analysisState"),
                validator.validateProperty(request, "analysisJustification"),
                validator.validateProperty(request, "analysisResponse"),
                validator.validateProperty(request, "analysisDetails"),
                validator.validateProperty(request, "comment"));
        final Response shapeError = rejectDecisionShape(request);
        if (shapeError != null) {
            return shapeError;
        }
        try (final var qm = new QueryManager(getAlpineRequest())) {
            try {
                return qm.callInTransaction(() -> {
                    final var component = qm.getObjectByUuid(Component.class, request.getComponent());
                    if (component == null) {
                        return Response.status(Response.Status.NOT_FOUND)
                                .entity("The component could not be found.")
                                .build();
                    }

                    requireAccess(qm, component.getProject());

                    final var vulnerability = qm.getObjectByUuid(Vulnerability.class, request.getVulnerability());
                    if (vulnerability == null) {
                        return Response.status(Response.Status.NOT_FOUND)
                                .entity("The vulnerability could not be found.")
                                .build();
                    }

                    final long analysisId = qm.makeAnalysis(commandFor(qm, request, component, vulnerability));
                    return Response.ok(trail(qm, qm.getObjectById(Analysis.class, analysisId)))
                            .build();
                });
            } catch (StaleAssessmentDecisionException e) {
                return Response.status(Response.Status.CONFLICT)
                        .entity("The analysis decision version is stale. Reload the analysis and retry.")
                        .build();
            } catch (AssessmentNotReleasableException e) {
                return Response.status(Response.Status.CONFLICT)
                        .entity("Only a local analysis decision can be released.")
                        .build();
            }
        }
    }

    private static Response rejectDecisionShape(final AnalysisRequest request) {
        if (request.getDecisionAction() == DecisionAction.COMMENT_ONLY) {
            if (StringUtils.isBlank(request.getComment())) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("COMMENT_ONLY requires a comment.")
                        .build();
            }
            if (hasDecisionField(request)) {
                return Response.status(Response.Status.BAD_REQUEST)
                        .entity("COMMENT_ONLY cannot include decision fields.")
                        .build();
            }
        }
        if (request.getDecisionAction() == DecisionAction.RELEASE_LOCAL && hasDecisionField(request)) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity("RELEASE_LOCAL cannot include a new decision field.")
                    .build();
        }
        return null;
    }

    private static MakeAnalysisCommand commandFor(
            final QueryManager qm,
            final AnalysisRequest request,
            final Component component,
            final Vulnerability vulnerability) {
        final MakeAnalysisCommand base = new MakeAnalysisCommand(component, vulnerability)
                .withComment(request.getComment())
                .withExpectedDecisionVersion(request.getExpectedDecisionVersion());
        return switch (request.getDecisionAction()) {
            case COMMENT_ONLY -> base.withDecisionAction(MakeAnalysisCommand.DecisionAction.COMMENT_ONLY);
            case RELEASE_LOCAL -> base.withDecisionAction(MakeAnalysisCommand.DecisionAction.RELEASE_LOCAL);
            case TAKE_LOCAL ->
                applySentFields(base, request).withDecisionAction(MakeAnalysisCommand.DecisionAction.TAKE_LOCAL);
            case AUTO -> {
                JdbiFactory.useJdbiHandle(
                        qm,
                        handle -> AssessmentMutationGuard.lockProject(
                                handle, component.getProject().getUuid()));
                final Analysis existing = qm.getAnalysis(component, vulnerability);
                final var origin = existing == null
                        ? null
                        : JdbiFactory.withJdbiHandle(
                                qm, handle -> new AssessmentProjectionDao(handle).findOrigin(existing.getId()));
                if (origin == null || origin.owner() != AssessmentOwnership.INHERITED) {
                    // Unchanged v1 behavior: an omitted state, justification, or response resets to NOT_SET.
                    yield base.withState(requireNonNullElse(request.getAnalysisState(), AnalysisState.NOT_SET))
                            .withJustification(requireNonNullElse(
                                    request.getAnalysisJustification(), AnalysisJustification.NOT_SET))
                            .withResponse(requireNonNullElse(request.getAnalysisResponse(), AnalysisResponse.NOT_SET))
                            .withDetails(request.getAnalysisDetails())
                            .withSuppress(request.isSuppressed())
                            .withDecisionAction(MakeAnalysisCommand.DecisionAction.AUTO);
                }
                final boolean comment = StringUtils.isNotBlank(request.getComment());
                final boolean decisionPresent = hasDecisionField(request);
                // A changed decision from a client without decisionAction is an explicit takeover (ADR 044).
                // The comment travels on the base command, so both are stored. Rejecting this shape
                // would break existing v1 clients on inherited rows.
                if (decisionPresent && echoedDecisionDiffers(existing, request)) {
                    yield applySentFields(base, request)
                            .withDecisionAction(MakeAnalysisCommand.DecisionAction.TAKE_LOCAL);
                }
                if (comment) {
                    yield base.withDecisionAction(MakeAnalysisCommand.DecisionAction.COMMENT_ONLY);
                }
                yield base.withDecisionAction(MakeAnalysisCommand.DecisionAction.AUTO);
            }
        };
    }

    /// Applies only the fields the client sent. Omitted fields keep their stored value.
    private static MakeAnalysisCommand applySentFields(
            final MakeAnalysisCommand command, final AnalysisRequest request) {
        return command.withState(request.getAnalysisState())
                .withJustification(request.getAnalysisJustification())
                .withResponse(request.getAnalysisResponse())
                .withDetails(request.getAnalysisDetails())
                .withSuppress(request.isSuppressed());
    }

    private static boolean hasDecisionField(final AnalysisRequest request) {
        return request.getAnalysisState() != null
                || request.getAnalysisJustification() != null
                || request.getAnalysisResponse() != null
                || request.isSuppressed() != null
                || request.getAnalysisDetails() != null;
    }

    private static boolean echoedDecisionDiffers(final Analysis analysis, final AnalysisRequest request) {
        if (request.getAnalysisState() != null && request.getAnalysisState() != analysis.getAnalysisState()) {
            return true;
        }
        if (request.getAnalysisJustification() != null
                && request.getAnalysisJustification() != analysis.getAnalysisJustification()) {
            return true;
        }
        if (request.getAnalysisResponse() != null && request.getAnalysisResponse() != analysis.getAnalysisResponse()) {
            return true;
        }
        if (request.isSuppressed() != null && request.isSuppressed() != analysis.isSuppressed()) {
            return true;
        }
        return request.getAnalysisDetails() != null
                && !request.getAnalysisDetails().equals(analysis.getAnalysisDetails());
    }

    private static AnalysisTrailResponse trail(final QueryManager qm, final Analysis analysis) {
        final Principal principal =
                qm.getAlpineRequest() == null ? null : qm.getAlpineRequest().getPrincipal();
        final long analysisId = analysis.getId();
        final var trails = JdbiFactory.withJdbiHandle(
                qm, handle -> new AssessmentTrailAssembler().assemble(handle, principal, List.of(analysisId)));
        return AnalysisTrailResponse.of(analysis, trails.isEmpty() ? null : trails.getFirst());
    }
}
