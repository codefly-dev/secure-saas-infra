import * as github from "@pulumi/github";
import {
  GithubGovernanceConfig,
  GithubGovernanceEnvironmentConfig,
  GithubRulesetBypassActor,
  named,
} from "./config";

export interface GithubGovernanceResources {
  actionsPermissions?: github.ActionsRepositoryPermissions;
  mainRuleset?: github.RepositoryRuleset;
  pushRuleset?: github.RepositoryRuleset;
  branchProtection?: github.BranchProtection;
  vulnerabilityAlerts?: github.RepositoryVulnerabilityAlerts;
  dependabotSecurityUpdates?: github.RepositoryDependabotSecurityUpdates;
  environments: Record<string, github.RepositoryEnvironment>;
  organizationSettings?: github.OrganizationSettings;
}

type ResourceOptions = { provider: github.Provider };

export function createGithubGovernance(
  config: GithubGovernanceConfig,
): GithubGovernanceResources {
  if (!config.enabled) {
    return { environments: {} };
  }

  const provider = new github.Provider(named("github-provider"), {
    owner: config.owner,
  });
  const resourceOptions: ResourceOptions = { provider };

  const actionsPermissions = new github.ActionsRepositoryPermissions(
    named("github-actions-permissions"),
    {
      repository: config.repository,
      enabled: true,
      allowedActions: "selected",
      shaPinningRequired: config.requireShaPinnedActions,
      allowedActionsConfig: {
        githubOwnedAllowed: true,
        verifiedAllowed: true,
        patternsAlloweds: config.allowedActionsPatterns,
      },
    },
    resourceOptions,
  );

  const vulnerabilityAlerts = new github.RepositoryVulnerabilityAlerts(
    named("github-vulnerability-alerts"),
    {
      repository: config.repository,
      enabled: true,
    },
    resourceOptions,
  );

  const dependabotSecurityUpdates =
    new github.RepositoryDependabotSecurityUpdates(
      named("github-dependabot-security-updates"),
      {
        repository: config.repository,
        enabled: true,
      },
      resourceOptions,
    );

  const environments: Record<string, github.RepositoryEnvironment> = {};
  for (const environment of config.protectedEnvironments) {
    environments[environment.name] = createEnvironment(
      config.repository,
      environment,
      resourceOptions,
    );
  }

  let mainRuleset: github.RepositoryRuleset | undefined;
  let pushRuleset: github.RepositoryRuleset | undefined;
  let branchProtection: github.BranchProtection | undefined;

  if (config.useLegacyBranchProtection) {
    branchProtection = createLegacyBranchProtection(config, resourceOptions);
  } else {
    mainRuleset = createMainRuleset(
      config,
      config.bypassActors,
      resourceOptions,
    );
    pushRuleset = createPushRuleset(
      config,
      config.bypassActors,
      resourceOptions,
    );
  }

  const organizationSettings = config.manageOrganizationSettings
    ? new github.OrganizationSettings(
        named("github-organization-settings"),
        {
          billingEmail: config.organizationBillingEmail!,
          defaultRepositoryPermission: "read",
          dependencyGraphEnabledForNewRepositories: true,
          dependabotAlertsEnabledForNewRepositories: true,
          dependabotSecurityUpdatesEnabledForNewRepositories: true,
          advancedSecurityEnabledForNewRepositories: true,
          secretScanningEnabledForNewRepositories: true,
          secretScanningPushProtectionEnabledForNewRepositories: true,
          webCommitSignoffRequired: true,
          membersCanCreateRepositories: false,
          membersCanCreatePublicRepositories: false,
          membersCanCreatePrivateRepositories: false,
          membersCanCreateInternalRepositories: false,
          membersCanForkPrivateRepositories: false,
          membersCanCreatePages: false,
          membersCanCreatePublicPages: false,
          membersCanCreatePrivatePages: false,
        },
        resourceOptions,
      )
    : undefined;

  return {
    actionsPermissions,
    mainRuleset,
    pushRuleset,
    branchProtection,
    vulnerabilityAlerts,
    dependabotSecurityUpdates,
    environments,
    organizationSettings,
  };
}

function createMainRuleset(
  config: GithubGovernanceConfig,
  bypassActors: GithubRulesetBypassActor[],
  resourceOptions: ResourceOptions,
) {
  return new github.RepositoryRuleset(
    named("github-main-ruleset"),
    {
      repository: config.repository,
      name: named("main-protection"),
      target: "branch",
      enforcement: "active",
      bypassActors: bypassActors.map((entry) => ({
        actorId: entry.actorId,
        actorType: entry.actorType,
        bypassMode: entry.bypassMode,
      })),
      conditions: {
        refName: {
          includes: ["~DEFAULT_BRANCH"],
          excludes: [],
        },
      },
      rules: {
        deletion: true,
        nonFastForward: true,
        requiredLinearHistory: config.requireLinearHistory,
        requiredSignatures: config.requireSignedCommits,
        pullRequest: {
          allowedMergeMethods: ["squash", "rebase"],
          dismissStaleReviewsOnPush: true,
          requireCodeOwnerReview: config.requireCodeOwnerReview,
          requireLastPushApproval: true,
          requiredApprovingReviewCount: config.requiredApprovingReviewCount,
          requiredReviewThreadResolution: true,
        },
        requiredStatusChecks: {
          strictRequiredStatusChecksPolicy: true,
          requiredChecks: config.requiredStatusChecks.map((context) => ({
            context,
          })),
        },
        ...(config.requireCodeScanning
          ? {
              requiredCodeScanning: {
                requiredCodeScanningTools: [
                  {
                    tool: config.codeScanningTool,
                    alertsThreshold: "errors_and_warnings",
                    securityAlertsThreshold: "high_or_higher",
                  },
                ],
              },
            }
          : {}),
      },
    },
    resourceOptions,
  );
}

function createPushRuleset(
  config: GithubGovernanceConfig,
  bypassActors: GithubRulesetBypassActor[],
  resourceOptions: ResourceOptions,
) {
  return new github.RepositoryRuleset(
    named("github-push-ruleset"),
    {
      repository: config.repository,
      name: named("push-protection"),
      target: "push",
      enforcement: "active",
      bypassActors: bypassActors.map((entry) => ({
        actorId: entry.actorId,
        actorType: entry.actorType,
        bypassMode: entry.bypassMode,
      })),
      rules: {
        fileExtensionRestriction: {
          restrictedFileExtensions: ["pem", "key", "p12", "pfx"],
        },
        filePathRestriction: {
          restrictedFilePaths: [
            ".env",
            ".env.*",
            "**/.env",
            "**/.env.*",
            "Pulumi.*.yaml",
            "**/Pulumi.*.yaml",
            "*.pem",
            "*.key",
            "*.p12",
            "*.pfx",
          ],
        },
        maxFilePathLength: {
          maxFilePathLength: 240,
        },
        maxFileSize: {
          maxFileSize: 25,
        },
      },
    },
    resourceOptions,
  );
}

function createLegacyBranchProtection(
  config: GithubGovernanceConfig,
  resourceOptions: ResourceOptions,
) {
  // Repository rulesets require GitHub Pro/Team for private repos. On Free
  // plans we fall back to legacy branch protection. The control surface is
  // ~85% of what the ruleset gives us; the loss is the push-side file rules
  // and the typed bypass actor framework.
  return new github.BranchProtection(
    named("github-branch-protection"),
    {
      repositoryId: config.repository,
      pattern: config.defaultBranch,
      enforceAdmins: false,
      requireSignedCommits: config.requireSignedCommits,
      requiredLinearHistory: config.requireLinearHistory,
      allowsForcePushes: false,
      allowsDeletions: false,
      requiredPullRequestReviews: [
        {
          dismissStaleReviews: true,
          requireCodeOwnerReviews: config.requireCodeOwnerReview,
          requireLastPushApproval: true,
          requiredApprovingReviewCount: config.requiredApprovingReviewCount,
        },
      ],
      requiredStatusChecks: [
        {
          strict: true,
          contexts: config.requiredStatusChecks,
        },
      ],
    },
    resourceOptions,
  );
}

function createEnvironment(
  repository: string,
  environment: GithubGovernanceEnvironmentConfig,
  resourceOptions: ResourceOptions,
) {
  const reviewer = reviewerConfig(environment);

  return new github.RepositoryEnvironment(
    named(`github-env-${slug(environment.name)}`),
    {
      repository,
      environment: environment.name,
      canAdminsBypass: false,
      preventSelfReview: true,
      waitTimer: environment.waitTimerMinutes ?? 0,
      deploymentBranchPolicy: {
        protectedBranches: true,
        customBranchPolicies: false,
      },
      ...(reviewer ? { reviewers: [reviewer] } : {}),
    },
    resourceOptions,
  );
}

function reviewerConfig(environment: GithubGovernanceEnvironmentConfig) {
  const teams = environment.reviewerTeamIds ?? [];
  const users = environment.reviewerUserIds ?? [];

  if (teams.length === 0 && users.length === 0) {
    return undefined;
  }

  return {
    ...(teams.length > 0 ? { teams } : {}),
    ...(users.length > 0 ? { users } : {}),
  };
}

function slug(value: string) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}
