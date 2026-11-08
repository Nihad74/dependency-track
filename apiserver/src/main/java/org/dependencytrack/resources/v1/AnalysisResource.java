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
import org.dependencytrack.assessmentsync.AssessmentNotReleasableException;
import org.dependencytrack.assessmentsync.AssessmentTrailAssembler;
import org.dependencytrack.assessmentsync.StaleAssessmentDecisionException;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.model.Analysis;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.validation.Validator;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import java.util.EnumSet;
import java.util.List;

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

    private static final Logger LOGGER = LoggerFactory.getLogger(AnalysisResource.class);

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
                final Response response = qm.callInTransaction(() -> {
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

                    final long analysisId = qm.makeAnalysis(commandFor(request, component, vulnerability));
                    return Response.ok(trail(qm, qm.getObjectById(Analysis.class, analysisId)))
                            .build();
                });
                if (response.getEntity() instanceof AnalysisTrailResponse assessment && LOGGER.isInfoEnabled()) {
                    LOGGER.info(
                            "Assessment write committed componentUuid={} vulnerabilityUuid={} action={} origin={} decisionVersion={}",
                            request.getComponent(),
                            request.getVulnerability(),
                            request.getDecisionAction(),
                            assessment.decisionOrigin(),
                            assessment.decisionVersion());
                }
                return response;
            } catch (StaleAssessmentDecisionException e) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(
                            "Assessment write rejected componentUuid={} vulnerabilityUuid={} action={} expectedDecisionVersion={} reason=STALE_DECISION_VERSION",
                            request.getComponent(),
                            request.getVulnerability(),
                            request.getDecisionAction(),
                            request.getExpectedDecisionVersion());
                }
                return Response.status(Response.Status.CONFLICT)
                        .entity("The analysis decision version is stale. Reload the analysis and retry.")
                        .build();
            } catch (AssessmentNotReleasableException e) {
                if (LOGGER.isDebugEnabled()) {
                    LOGGER.debug(
                            "Assessment write rejected componentUuid={} vulnerabilityUuid={} action={} reason=TARGET_NOT_LOCAL",
                            request.getComponent(),
                            request.getVulnerability(),
                            request.getDecisionAction());
                }
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
            final AnalysisRequest request, final Component component, final Vulnerability vulnerability) {
        final var builder = MakeAnalysisCommand.builder(component, vulnerability)
                .comment(request.getComment())
                .expectedDecisionVersion(request.getExpectedDecisionVersion());
        return switch (request.getDecisionAction()) {
            case COMMENT_ONLY ->
                builder.decisionAction(MakeAnalysisCommand.DecisionAction.COMMENT_ONLY)
                        .build();
            case RELEASE_LOCAL ->
                builder.decisionAction(MakeAnalysisCommand.DecisionAction.RELEASE_LOCAL)
                        .build();
            case TAKE_LOCAL ->
                applySentFields(builder, request)
                        .decisionAction(MakeAnalysisCommand.DecisionAction.TAKE_LOCAL)
                        .build();
            // On an inherited row, a changed field takes local ownership and the comment is kept (ADR 044).
            case AUTO ->
                applySentFields(builder, request)
                        .options(EnumSet.of(MakeAnalysisCommand.Option.V1_RESET_OMITTED_DECISION))
                        .decisionAction(MakeAnalysisCommand.DecisionAction.AUTO)
                        .build();
        };
    }

    /** Applies only the fields the client sent. Omitted fields keep their stored value. */
    private static MakeAnalysisCommand.Builder applySentFields(
            final MakeAnalysisCommand.Builder builder, final AnalysisRequest request) {
        return builder.state(request.getAnalysisState())
                .justification(request.getAnalysisJustification())
                .response(request.getAnalysisResponse())
                .details(request.getAnalysisDetails())
                .suppress(request.isSuppressed());
    }

    private static boolean hasDecisionField(final AnalysisRequest request) {
        return request.getAnalysisState() != null
                || request.getAnalysisJustification() != null
                || request.getAnalysisResponse() != null
                || request.isSuppressed() != null
                || request.getAnalysisDetails() != null;
    }

    private static AnalysisTrailResponse trail(final QueryManager qm, final Analysis analysis) {
        final long analysisId = analysis.getId();
        final var trails = JdbiFactory.withJdbiHandle(
                qm, handle -> AssessmentTrailAssembler.assemble(handle, List.of(analysisId)));
        return AnalysisTrailResponse.of(analysis, trails.getFirst());
    }
}
