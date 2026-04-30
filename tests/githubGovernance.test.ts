import test from "node:test";
import assert from "node:assert/strict";
import {
  flushPulumiMocks,
  installPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";

test("github governance stack creates repository controls for customer-code infrastructure", async () => {
  const { resources } = await installPulumiMocks();
  const { createGithubGovernance } = await import("../src/githubGovernance");

  createGithubGovernance({
    enabled: true,
    owner: "deus-ai",
    repository: "infra",
    defaultBranch: "main",
    requiredStatusChecks: ["npm test"],
    protectedEnvironments: [
      {
        name: "production",
        reviewerTeamIds: [1234],
        waitTimerMinutes: 5,
      },
    ],
    allowedActionsPatterns: ["actions/*", "github/codeql-action/*"],
    requireShaPinnedActions: true,
    requireCodeOwnerReview: true,
    requireSignedCommits: true,
    requireLinearHistory: true,
    requiredApprovingReviewCount: 2,
    requireCodeScanning: true,
    codeScanningTool: "CodeQL",
    manageOrganizationSettings: false,
    bypassActors: [
      {
        actorId: 12345,
        actorType: "OrganizationAdmin",
        bypassMode: "pull_request",
      },
    ],
  });

  await flushPulumiMocks();

  const actionsPermissions = resourcesOfType(
    resources,
    "github:index/actionsRepositoryPermissions:ActionsRepositoryPermissions",
  );
  assert.equal(actionsPermissions.length, 1);
  assert.equal(actionsPermissions[0].inputs.repository, "infra");
  assert.equal(actionsPermissions[0].inputs.allowedActions, "selected");
  assert.equal(actionsPermissions[0].inputs.shaPinningRequired, true);
  assert.deepEqual(
    actionsPermissions[0].inputs.allowedActionsConfig.patternsAlloweds,
    ["actions/*", "github/codeql-action/*"],
  );

  const rulesets = resourcesOfType(
    resources,
    "github:index/repositoryRuleset:RepositoryRuleset",
  );
  assert.equal(rulesets.length, 2);

  const mainRuleset = rulesets.find(
    (resource) => resource.inputs.target === "branch",
  );
  assert.ok(mainRuleset);
  assert.equal(mainRuleset.inputs.enforcement, "active");
  assert.deepEqual(mainRuleset.inputs.bypassActors, [
    {
      actorId: 12345,
      actorType: "OrganizationAdmin",
      bypassMode: "pull_request",
    },
  ]);
  assert.deepEqual(mainRuleset.inputs.conditions.refName.includes, [
    "~DEFAULT_BRANCH",
  ]);
  assert.equal(mainRuleset.inputs.rules.requiredSignatures, true);
  assert.equal(mainRuleset.inputs.rules.requiredLinearHistory, true);
  assert.equal(
    mainRuleset.inputs.rules.pullRequest.requireCodeOwnerReview,
    true,
  );
  assert.equal(
    mainRuleset.inputs.rules.pullRequest.requiredApprovingReviewCount,
    2,
  );
  assert.equal(
    mainRuleset.inputs.rules.requiredStatusChecks.requiredChecks[0].context,
    "npm test",
  );
  assert.equal(
    mainRuleset.inputs.rules.requiredCodeScanning.requiredCodeScanningTools[0]
      .securityAlertsThreshold,
    "highOrHigher",
  );

  const pushRuleset = rulesets.find(
    (resource) => resource.inputs.target === "push",
  );
  assert.ok(pushRuleset);
  assert.deepEqual(
    pushRuleset.inputs.rules.fileExtensionRestriction.restrictedFileExtensions,
    ["pem", "key", "p12", "pfx"],
  );
  assert.ok(
    pushRuleset.inputs.rules.filePathRestriction.restrictedFilePaths.includes(
      "**/.env",
    ),
  );

  const environments = resourcesOfType(
    resources,
    "github:index/repositoryEnvironment:RepositoryEnvironment",
  );
  assert.equal(environments.length, 1);
  assert.equal(environments[0].inputs.environment, "production");
  assert.equal(environments[0].inputs.canAdminsBypass, false);
  assert.equal(environments[0].inputs.preventSelfReview, true);
  assert.equal(environments[0].inputs.waitTimer, 5);
  assert.deepEqual(environments[0].inputs.reviewers, [{ teams: [1234] }]);

  assert.equal(
    resourcesOfType(
      resources,
      "github:index/repositoryVulnerabilityAlerts:RepositoryVulnerabilityAlerts",
    ).length,
    1,
  );
  assert.equal(
    resourcesOfType(
      resources,
      "github:index/repositoryDependabotSecurityUpdates:RepositoryDependabotSecurityUpdates",
    ).length,
    1,
  );
});
