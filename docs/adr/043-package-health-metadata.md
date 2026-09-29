| Status   | Date       | Author(s)     |
|:---------|:-----------|:--------------|
| Accepted | 2026-09-29 | Nihad Uddin   |

## Context

Dependency-Track can see vulnerabilities, licenses, and package age. It cannot see whether the
package's source repository is maintained. OpenSSF Scorecard and repository metrics answer that
question, but they are slow to fetch and they describe the repository now, not one package version.

The same package appears in many projects. A large bill of materials can contain thousands of
packages. Calling GitHub or deps.dev once per component would repeat the same work and hit rate
limits. Package metadata already has one row per versionless package URL. Health data belongs
next to that row, not next to each component.

Policy authors need a way to act on that data. A missing value must stay missing. Treating it as
zero would create violations for packages that have not been fetched yet.

### Possible Solutions

#### A: Fetch health while the project is analyzed

Start the external calls from project analysis, using the project UUID that the upload already has.

*Pro*: The project UUID is already known. No later search for projects is required.

*Con*: Analysis would wait on GitHub and deps.dev. A shared package would be fetched once per
project. Package metadata might not exist yet, and the health row has a foreign key to it.

#### B: Store health on the versionless package and refresh it on a schedule

Write health only after package metadata exists. A scheduled workflow selects packages that have
no health row, or whose last fetch is at least 24 hours old. When a value that a policy can read
changes, evaluate policies for the projects that use the package.

*Pro*: One fetch serves every project that uses the package. The foreign key is satisfied.
Project analysis stays independent of the external APIs.

*Con*: A new policy does not see health until the next fetch. Finding the affected projects
requires a query from the package back to components.

## Decision

We will store package health on the versionless package URL, in `PACKAGE_HEALTH_METADATA`, with a
foreign key to `PACKAGE_METADATA`. Individual OpenSSF Scorecard checks are stored in
`PACKAGE_HEALTH_SCORECARD_CHECK`.

A scheduled workflow fetches due packages through deps.dev and, for GitHub repositories, the
GitHub API. The first fetch happens after package metadata exists. Later fetches wait until
`LAST_FETCH` is at least 24 hours old. One workflow instance runs at a time. External calls for a
batch finish before the batch is written, in one database transaction.

Component policies can read a `health` value. The fields are the scorecard score, the scorecard
check name and score, stars, forks, dependents, bus factor, commit frequency, last commit, average
issue age, and whether the repository is archived. Other stored columns stay off the policy type.
A field that was not fetched stays absent. It is not zero, and it does not by itself create or
clear a violation.

When a policy field or a check score changes, Dependency-Track evaluates policies and updates
metrics for projects that contain the package and have an applicable condition that reads `health`.
Vulnerability analysis stays on project analysis.

The component health HTTP resource can return the full stored record. That resource is separate
from the policy type.

## Consequences

Shared packages are fetched once. Projects that import the same package see the same health row.

A policy saved before the first fetch does not match until health arrives and the policy run
starts. An unchanged refresh updates `LAST_FETCH` and does not start policy evaluation.

The project lookup repeats the existing rules for which policies apply to a project, so a limited
policy does not schedule every project that contains the package.

GitHub and deps.dev rate limits can delay a batch. Cancellation of that work must surface as an
interrupt, not as a fetch failure that is retried.
