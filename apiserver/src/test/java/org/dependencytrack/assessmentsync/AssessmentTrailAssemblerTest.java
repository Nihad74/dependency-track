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

import alpine.model.ApiKey;
import alpine.model.ManagedUser;
import alpine.model.Team;
import alpine.model.auth.ApiKeyPrincipal;
import alpine.model.auth.Principal;
import alpine.model.auth.UserPrincipal;
import alpine.model.auth.UserType;
import alpine.resources.AlpineRequest;
import com.fasterxml.jackson.databind.JsonNode;
import org.dependencytrack.PersistenceCapableTest;
import org.dependencytrack.assessmentsync.AssessmentConsensus.Contributor;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao.SourceCommentWrite;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao.SourceContributionWrite;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao.WorkerWrite;
import org.dependencytrack.assessmentsync.AssessmentProjectionDao.WorkerWriteStatus;
import org.dependencytrack.assessmentsync.AssessmentTrailAssembler.Trail;
import org.dependencytrack.auth.Permissions;
import org.dependencytrack.auth.ProjectAccess;
import org.dependencytrack.common.Mappers;
import org.dependencytrack.model.Analysis;
import org.dependencytrack.model.AnalysisState;
import org.dependencytrack.model.Component;
import org.dependencytrack.model.Finding;
import org.dependencytrack.model.Project;
import org.dependencytrack.model.Severity;
import org.dependencytrack.model.Vulnerability;
import org.dependencytrack.notification.NotificationModelConverter;
import org.dependencytrack.persistence.command.MakeAnalysisCommand;
import org.dependencytrack.persistence.jdbi.FindingDao;
import org.dependencytrack.persistence.jdbi.ProjectDao;
import org.dependencytrack.resources.v1.vo.AnalysisTrailResponse;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.inJdbiTransaction;
import static org.dependencytrack.persistence.jdbi.JdbiFactory.withJdbiHandle;

class AssessmentTrailAssemblerTest extends PersistenceCapableTest {

    private static final String VISIBLE_TEXT = "visible-source-explanation";
    private static final String HIDDEN_TEXT = "hidden-source-explanation";
    private static final String VISIBLE_COMMENT = "visible-source-comment";
    private static final String HIDDEN_COMMENT = "hidden-source-comment";
    private static final String VISIBLE_AUTHOR = "visible-author";
    private static final String HIDDEN_AUTHOR = "hidden-author";
    private static final String LOCAL_COMMENT = "local-only-note";
    private static final Instant EARLIER = Instant.parse("2020-01-02T03:04:05Z");
    private static final Instant LATER = Instant.parse("2024-05-06T07:08:09Z");

    @Test
    void bothSourceAndTargetAccessIncludesTheSourceGroup() {
        final OwnedProjects projects = inheritedProjects();
        final Principal viewer =
                memberOf(projects.target(), projects.visibleSource().project());

        final AnalysisTrailResponse response = response(projects.targetAnalysisId(), viewer, true);

        assertThat(response.analysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(response.decisionOrigin()).isEqualTo(AssessmentOwnership.INHERITED);
        assertThat(response.decisionVersion()).isPositive();
        assertThat(response.inheritanceStatus()).isEqualTo("SOURCE_CONFLICT");
        assertThat(response.analysisDetails()).isNull();
        assertThat(response.analysisComments())
                .extracting(AnalysisTrailResponse.Comment::comment)
                .containsExactly(LOCAL_COMMENT);
        assertThat(response.sourceAssessments()).singleElement().satisfies(group -> {
            assertThat(group.project().name()).isEqualTo("visible-kernel");
            assertThat(group.project().uuid())
                    .isEqualTo(projects.visibleSource().project().getUuid());
            assertThat(group.component().name()).isEqualTo("visible-kernel-lib");
            assertThat(group.sourceDetails()).isEqualTo(VISIBLE_TEXT);
            assertThat(group.comments())
                    .extracting(AnalysisTrailResponse.SourceComment::comment)
                    .containsExactly("earlier-note", VISIBLE_COMMENT);
            assertThat(group.comments().get(1).commenter()).isEqualTo(VISIBLE_AUTHOR);
        });
        assertThat(detailsColumn(projects.targetAnalysisId())).isNull();
    }

    @Test
    void sourceOnlyAccessStillReturnsThatSourceGroup() {
        final OwnedProjects projects = inheritedProjects();
        final Principal viewer = memberOf(projects.visibleSource().project());

        final AnalysisTrailResponse response = response(projects.targetAnalysisId(), viewer, true);

        assertThat(response.sourceAssessments())
                .singleElement()
                .extracting(AnalysisTrailResponse.SourceAssessment::sourceDetails)
                .isEqualTo(VISIBLE_TEXT);
        assertThat(response.decisionOrigin()).isEqualTo(AssessmentOwnership.INHERITED);
    }

    @Test
    void targetOnlyAccessKeepsTheMachineDecisionAndOmitsTheSource() {
        final OwnedProjects projects = inheritedProjects();
        final Principal viewer = memberOf(projects.target());

        final AnalysisTrailResponse response = response(projects.targetAnalysisId(), viewer, true);

        assertThat(response.analysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(response.decisionOrigin()).isEqualTo(AssessmentOwnership.INHERITED);
        assertThat(response.inheritanceStatus()).isEqualTo("SOURCE_CONFLICT");
        assertThat(response.sourceAssessments()).isEmpty();
        assertHidden(response, HIDDEN_TEXT, VISIBLE_TEXT, HIDDEN_AUTHOR, "visible-kernel");
    }

    @Test
    void neitherAccessOmitsSourcesWithoutDroppingTheMachineDecision() {
        final OwnedProjects projects = inheritedProjects();
        final Principal outsider = userPrincipal(qm.createManagedUser("outsider", TEST_PASSWORD_HASH));

        final AnalysisTrailResponse response = response(projects.targetAnalysisId(), outsider, true);

        assertThat(response.analysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(response.isSuppressed()).isFalse();
        assertThat(response.decisionOrigin()).isEqualTo(AssessmentOwnership.INHERITED);
        assertThat(response.sourceAssessments()).isEmpty();
        assertHidden(response, VISIBLE_TEXT, HIDDEN_TEXT, VISIBLE_AUTHOR);
    }

    @Test
    void portfolioAclDisabledIncludesExistingSources() {
        final OwnedProjects projects = inheritedProjects();
        final Principal outsider = userPrincipal(qm.createManagedUser("outsider", TEST_PASSWORD_HASH));

        final AnalysisTrailResponse response = response(projects.targetAnalysisId(), outsider, false);

        assertThat(response.sourceAssessments())
                .singleElement()
                .extracting(AnalysisTrailResponse.SourceAssessment::sourceDetails)
                .isEqualTo(VISIBLE_TEXT);
    }

    @Test
    void portfolioBypassIncludesExistingSources() {
        final OwnedProjects projects = inheritedProjects();
        final ManagedUser outsider = qm.createManagedUser("outsider", TEST_PASSWORD_HASH);
        final Principal bypass = userPrincipal(outsider, Permissions.Constants.PORTFOLIO_ACCESS_CONTROL_BYPASS);

        assertThat(response(projects.targetAnalysisId(), bypass, true).sourceAssessments())
                .singleElement()
                .extracting(AnalysisTrailResponse.SourceAssessment::sourceDetails)
                .isEqualTo(VISIBLE_TEXT);

        final Principal plain = userPrincipal(outsider);
        final List<Trail> unrestricted =
                ProjectAccess.unrestricted(() -> assemble(request(plain, true), plain, projects.targetAnalysisId()));
        assertThat(unrestricted.getFirst().sourceAssessments())
                .singleElement()
                .extracting(AssessmentTrailAssembler.SourceAssessment::sourceDetails)
                .isEqualTo(VISIBLE_TEXT);
    }

    @Test
    void apiKeyAccessFollowsTheKeyTeam() {
        final OwnedProjects projects = inheritedProjects();
        final Team allowed = grant(null, projects.visibleSource().project());
        final ApiKey allowedKey = qm.createApiKey(allowed);
        final Team denied = qm.createTeam("denied");
        final ApiKey deniedKey = qm.createApiKey(denied);

        assertThat(response(projects.targetAnalysisId(), apiKeyPrincipal(allowedKey), true)
                        .sourceAssessments())
                .singleElement()
                .extracting(AnalysisTrailResponse.SourceAssessment::sourceDetails)
                .isEqualTo(VISIBLE_TEXT);
        final AnalysisTrailResponse hidden = response(projects.targetAnalysisId(), apiKeyPrincipal(deniedKey), true);
        assertThat(hidden.sourceAssessments()).isEmpty();
        assertThat(hidden.decisionOrigin()).isEqualTo(AssessmentOwnership.INHERITED);
        assertHidden(hidden, VISIBLE_TEXT, VISIBLE_AUTHOR, "visible-kernel");
    }

    @Test
    void deletionAndRevocationHideCopiedTextWhileTheMachineDecisionRemains() {
        final OwnedProjects deleted = inheritedProjects();
        final Principal viewer = memberOf(deleted.visibleSource().project());
        assertThat(response(deleted.targetAnalysisId(), viewer, true).sourceAssessments())
                .hasSize(1);

        withJdbiHandle(handle -> handle.attach(ProjectDao.class)
                .deleteProject(deleted.visibleSource().project().getUuid()));

        final AnalysisTrailResponse afterDelete = response(deleted.targetAnalysisId(), viewer, true);
        assertThat(afterDelete.analysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(afterDelete.decisionOrigin()).isEqualTo(AssessmentOwnership.INHERITED);
        assertThat(afterDelete.sourceAssessments()).isEmpty();
        assertThat(contributionCount(deleted.targetAnalysisId())).isEqualTo(1);
        assertHidden(afterDelete, VISIBLE_TEXT, VISIBLE_COMMENT, VISIBLE_AUTHOR, "visible-kernel");
        assertThat(detailsColumn(deleted.targetAnalysisId())).isNull();

        final OwnedProjects revoked = inheritedProjects("revoked-kernel", "cmx500-revoked");
        final ManagedUser memberUser = qm.createManagedUser("member", TEST_PASSWORD_HASH);
        final Team team = grant(memberUser, revoked.visibleSource().project());
        final Principal member = userPrincipal(memberUser);
        assertThat(response(revoked.targetAnalysisId(), member, true).sourceAssessments())
                .hasSize(1);
        qm.callInTransaction(() -> {
            final Project managed = qm.getObjectById(
                    Project.class, revoked.visibleSource().project().getId());
            managed.removeAccessTeam(qm.getObjectById(Team.class, team.getId()));
            return Boolean.TRUE;
        });

        final AnalysisTrailResponse afterRevoke = response(revoked.targetAnalysisId(), member, true);
        assertThat(afterRevoke.sourceAssessments()).isEmpty();
        assertThat(afterRevoke.analysisState()).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(contributionCount(revoked.targetAnalysisId())).isEqualTo(1);
        assertThat(readContributionText(revoked.targetAnalysisId())).isEqualTo(VISIBLE_TEXT);
        assertHidden(afterRevoke, VISIBLE_TEXT, VISIBLE_AUTHOR);
    }

    @Test
    void mixedContributorsExposeOnlyTheAuthorizedGroup() {
        final Project target = project("cmx500");
        final Component targetComponent = component(target, "product-lib");
        final Vulnerability vulnerability = vulnerability("CVE-MIXED");
        final long targetAnalysisId = neutralAnalysis(targetComponent, vulnerability);
        final SourceProject visible = sourceProject("visible-kernel");
        final SourceProject hidden = sourceProject("hidden-kernel");
        inherit(
                targetAnalysisId,
                "SOURCE_CONFLICT",
                contribution(visible, VISIBLE_TEXT, 1, VISIBLE_COMMENT, VISIBLE_AUTHOR, LATER),
                contribution(hidden, HIDDEN_TEXT, 2, HIDDEN_COMMENT, HIDDEN_AUTHOR, LATER));
        final Principal viewer = memberOf(visible.project());

        final AnalysisTrailResponse response = response(targetAnalysisId, viewer, true);

        assertThat(response.sourceAssessments()).singleElement().satisfies(group -> {
            assertThat(group.project().uuid()).isEqualTo(visible.project().getUuid());
            assertThat(group.sourceDetails()).isEqualTo(VISIBLE_TEXT);
        });
        assertThat(response.inheritanceStatus()).isEqualTo("SOURCE_CONFLICT");
        assertHidden(
                response,
                HIDDEN_TEXT,
                HIDDEN_COMMENT,
                HIDDEN_AUTHOR,
                "hidden-kernel",
                hidden.project().getUuid().toString(),
                hidden.component().getUuid().toString());
    }

    @Test
    void unsafeReasonTextAndPoisonedDetailsStayOutOfTheResponse() {
        final OwnedProjects projects = inheritedProjects();
        final Principal viewer = memberOf(projects.visibleSource().project());
        withJdbiHandle(handle -> handle.createUpdate("""
                        UPDATE "ASSESSMENT_ORIGIN"
                           SET "LAST_REASON" = 'hidden-kernel'
                         WHERE "ANALYSIS_ID" = :analysisId
                        """)
                .bind("analysisId", projects.targetAnalysisId())
                .execute());
        withJdbiHandle(handle -> handle.createUpdate("""
                        UPDATE "ANALYSIS"
                           SET "DETAILS" = 'poison-column-text'
                         WHERE "ID" = :analysisId
                        """)
                .bind("analysisId", projects.targetAnalysisId())
                .execute());

        final AnalysisTrailResponse response = response(projects.targetAnalysisId(), viewer, true);

        assertThat(response.inheritanceStatus()).isNull();
        assertThat(response.analysisDetails()).isNull();
        assertThat(response.sourceAssessments())
                .singleElement()
                .extracting(AnalysisTrailResponse.SourceAssessment::sourceDetails)
                .isEqualTo(VISIBLE_TEXT);
        assertHidden(response, "hidden-kernel", "poison-column-text");
        assertThat(detailsColumn(projects.targetAnalysisId())).isEqualTo("poison-column-text");
    }

    @Test
    void nullPrincipalAndUnboundHandleAreNotSourceAuthorization() {
        final OwnedProjects projects = inheritedProjects();
        final Principal viewer = memberOf(projects.visibleSource().project());
        final AlpineRequest openRequest = request(viewer, false);

        final List<Trail> withoutPrincipal = withJdbiHandle(
                openRequest,
                handle -> new AssessmentTrailAssembler().assemble(handle, null, List.of(projects.targetAnalysisId())));
        assertThat(withoutPrincipal.getFirst().sourceAssessments()).isEmpty();
        assertThat(withoutPrincipal.getFirst().decisionOrigin()).isEqualTo(AssessmentOwnership.INHERITED);

        final List<Trail> unboundHandle = withJdbiHandle(handle ->
                new AssessmentTrailAssembler().assemble(handle, viewer, List.of(projects.targetAnalysisId())));
        assertThat(unboundHandle.getFirst().sourceAssessments()).isEmpty();
        assertThat(unboundHandle.getFirst().inheritanceStatus()).isEqualTo("SOURCE_CONFLICT");
    }

    @Test
    void findingReadsAndNotificationSubjectsStayOnTheTargetMachineRow() throws Exception {
        final Project target = project("cmx500");
        final Component targetComponent = component(target, "product-lib");
        final Vulnerability vulnerability = vulnerability("CVE-FINDING");
        qm.addVulnerability(vulnerability, targetComponent, "INTERNAL");
        final long targetAnalysisId = neutralAnalysis(targetComponent, vulnerability);
        final List<Finding> before =
                withJdbiHandle(handle -> handle.attach(FindingDao.class).getFindings(target.getId(), true));
        assertThat(before).hasSize(1);

        final SourceProject visible = sourceProject("visible-kernel");
        inherit(
                targetAnalysisId,
                "SOURCE_CONFLICT",
                contribution(visible, VISIBLE_TEXT, 1, VISIBLE_COMMENT, VISIBLE_AUTHOR, LATER));

        final List<Finding> after =
                withJdbiHandle(handle -> handle.attach(FindingDao.class).getFindings(target.getId(), true));
        assertThat(after).hasSize(1);
        assertThat(after.getFirst().getAnalysis().get("state")).isEqualTo(AnalysisState.NOT_AFFECTED);
        assertThat(after.getFirst().getAnalysis().get("isSuppressed")).isEqualTo(false);
        assertThat(after.getFirst().getAnalysis().get("detail")).isNull();
        final String findingJson = Mappers.jsonMapper().writeValueAsString(after.getFirst());
        assertThat(findingJson).doesNotContain(VISIBLE_TEXT, VISIBLE_COMMENT, VISIBLE_AUTHOR, "visible-kernel");

        qm.getPersistenceManager().evictAll();
        final Analysis analysis = qm.getObjectById(Analysis.class, targetAnalysisId);
        final String subject = NotificationModelConverter.convert(analysis).toString();
        assertThat(subject).doesNotContain(VISIBLE_TEXT, VISIBLE_COMMENT, VISIBLE_AUTHOR);
        assertThat(subject).contains("NOT_AFFECTED");
    }

    private OwnedProjects inheritedProjects() {
        return inheritedProjects("visible-kernel", "cmx500");
    }

    private OwnedProjects inheritedProjects(final String sourceName, final String targetName) {
        final Project target = project(targetName);
        final Component targetComponent = component(target, "product-lib");
        final Vulnerability vulnerability = vulnerability("CVE-" + targetName);
        final long targetAnalysisId = neutralAnalysis(targetComponent, vulnerability);
        final SourceProject visible = sourceProject(sourceName);
        inherit(
                targetAnalysisId,
                "SOURCE_CONFLICT",
                new SourceContributionWrite(
                        contributor(visible),
                        VISIBLE_TEXT,
                        List.of(
                                new SourceCommentWrite(1, "earlier-note", null, EARLIER),
                                new SourceCommentWrite(2, VISIBLE_COMMENT, VISIBLE_AUTHOR, LATER))));
        return new OwnedProjects(target, targetAnalysisId, visible);
    }

    private void inherit(
            final long targetAnalysisId, final String reason, final SourceContributionWrite... contributions) {
        final var written = inJdbiTransaction(handle -> {
            final var dao = new AssessmentProjectionDao(handle);
            final var origin = dao.findOrigin(targetAnalysisId);
            return dao.applyWorkerWrite(new WorkerWrite(
                    targetAnalysisId,
                    AssessmentOwnership.INHERITED,
                    AssessmentDecision.of(
                            AnalysisState.NOT_AFFECTED,
                            null,
                            null,
                            false,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null,
                            null),
                    null,
                    null,
                    reason,
                    origin.decisionVersion(),
                    List.of(contributions)));
        });
        assertThat(written.status()).isEqualTo(WorkerWriteStatus.APPLIED);
    }

    private static SourceContributionWrite contribution(
            final SourceProject source,
            final String details,
            final long commentId,
            final String comment,
            final String author,
            final Instant timestamp) {
        return new SourceContributionWrite(
                contributor(source), details, List.of(new SourceCommentWrite(commentId, comment, author, timestamp)));
    }

    private static Contributor contributor(final SourceProject source) {
        return new Contributor(
                source.project().getUuid(),
                source.component().getUuid(),
                source.vulnerability().getUuid(),
                source.analysisId());
    }

    private AnalysisTrailResponse response(final long analysisId, final Principal principal, final boolean pac) {
        qm.getPersistenceManager().evictAll();
        final Trail trail =
                assemble(request(principal, pac), principal, analysisId).getFirst();
        return AnalysisTrailResponse.of(qm.getObjectById(Analysis.class, analysisId), trail);
    }

    private static List<Trail> assemble(final AlpineRequest request, final Principal principal, final long analysisId) {
        return withJdbiHandle(
                request, handle -> new AssessmentTrailAssembler().assemble(handle, principal, List.of(analysisId)));
    }

    private Principal memberOf(final Project... projects) {
        final ManagedUser user = qm.createManagedUser("viewer-" + projects[0].getName(), TEST_PASSWORD_HASH);
        grant(user, projects);
        return userPrincipal(user);
    }

    private Team grant(final ManagedUser user, final Project... projects) {
        final Team team = qm.createTeam("team-" + projects[0].getUuid());
        if (user != null) {
            qm.addUserToTeam(user, team);
        }
        for (final Project project : projects) {
            qm.callInTransaction(() -> {
                qm.getObjectById(Project.class, project.getId()).addAccessTeam(team);
                return Boolean.TRUE;
            });
        }
        return team;
    }

    private SourceProject sourceProject(final String name) {
        final Project project = project(name);
        final Component component = component(project, name + "-lib");
        final Vulnerability vulnerability = vulnerability("CVE-" + name);
        final long analysisId = qm.makeAnalysis(new MakeAnalysisCommand(component, vulnerability)
                .withState(AnalysisState.NOT_AFFECTED)
                .withOptions(EnumSet.of(
                        MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL, MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
        return new SourceProject(project, component, vulnerability, analysisId);
    }

    private long neutralAnalysis(final Component component, final Vulnerability vulnerability) {
        return qm.makeAnalysis(new MakeAnalysisCommand(component, vulnerability)
                .withComment(LOCAL_COMMENT)
                .withCommenter("target-user")
                .withOptions(EnumSet.of(
                        MakeAnalysisCommand.Option.OMIT_AUDIT_TRAIL, MakeAnalysisCommand.Option.OMIT_NOTIFICATION)));
    }

    private Project project(final String name) {
        return qm.createProject(name, null, "1.0.0", null, null, null, null, false);
    }

    private Component component(final Project project, final String name) {
        final var component = new Component();
        component.setProject(project);
        component.setName(name);
        component.setVersion("1.0.0");
        return qm.createComponent(component, false);
    }

    private Vulnerability vulnerability(final String vulnId) {
        final var vulnerability = new Vulnerability();
        vulnerability.setVulnId(vulnId + "-" + UUID.randomUUID());
        vulnerability.setSource(Vulnerability.Source.INTERNAL);
        vulnerability.setSeverity(Severity.HIGH);
        return qm.createVulnerability(vulnerability);
    }

    private static AlpineRequest request(final Principal principal, final boolean portfolioAcl) {
        return new AlpineRequest(principal, null, null, null, null, portfolioAcl);
    }

    private static UserPrincipal userPrincipal(final ManagedUser user, final String... permissions) {
        return new UserPrincipal(user.getId(), user.getUsername(), UserType.MANAGED, List.of(), Set.of(permissions));
    }

    private static ApiKeyPrincipal apiKeyPrincipal(final ApiKey apiKey) {
        return new ApiKeyPrincipal(apiKey.getId(), apiKey.getPublicId(), List.of(), Set.of());
    }

    private static String detailsColumn(final long analysisId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "DETAILS"
                          FROM "ANALYSIS"
                         WHERE "ID" = :analysisId
                        """)
                .bind("analysisId", analysisId)
                .map((rs, ctx) -> rs.getString("DETAILS"))
                .one());
    }

    private static int contributionCount(final long analysisId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT COUNT(*)::int
                          FROM "ASSESSMENT_SOURCE_CONTRIBUTION"
                         WHERE "TARGET_ANALYSIS_ID" = :analysisId
                        """)
                .bind("analysisId", analysisId)
                .mapTo(int.class)
                .one());
    }

    private static String readContributionText(final long analysisId) {
        return withJdbiHandle(handle -> handle.createQuery("""
                        SELECT "SOURCE_DETAILS"
                          FROM "ASSESSMENT_SOURCE_CONTRIBUTION"
                         WHERE "TARGET_ANALYSIS_ID" = :analysisId
                        """)
                .bind("analysisId", analysisId)
                .mapTo(String.class)
                .one());
    }

    private static void assertHidden(final AnalysisTrailResponse response, final String... secrets) {
        try {
            final String json = Mappers.jsonMapper().writeValueAsString(response);
            assertThat(json).doesNotContain(secrets);
            final JsonNode node = Mappers.jsonMapper().readTree(json);
            assertThat(node.has("sourceCount")).isFalse();
            assertThat(node.has("hiddenCount")).isFalse();
            assertThat(node.has("contributorCount")).isFalse();
            assertThat(node.has("hiddenSourceCount")).isFalse();
        } catch (final Exception ex) {
            throw new IllegalStateException(ex);
        }
    }

    private record OwnedProjects(Project target, long targetAnalysisId, SourceProject visibleSource) {}

    private record SourceProject(Project project, Component component, Vulnerability vulnerability, long analysisId) {}
}
