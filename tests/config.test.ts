import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  BackupConfig,
  CustomerDataConfig,
  DatabaseConfig,
  E2bByocAccessConfig,
  EksConfig,
  ExecutionSandboxConfig,
  GithubGovernanceConfig,
  GithubOidcConfig,
  IdentityCenterConfig,
  LogArchiveConfig,
  SharedServicesConfig,
  WafConfig,
  validateBackupConfig,
  validateConfigValues,
  validateCustomerDataConfig,
  validateDatabaseConfig,
  validateE2bByocAccessConfig,
  validateExecutionSandboxConfig,
  validateGithubGovernanceConfig,
  validateOperationalConfigValues,
  validateProductionPostureValues,
  resolvePlatformBlueprintConfig,
  deploymentStageForEnvironment,
  isProductionLikeEnvironment,
  validateStackKindValues,
  validateWafConfig,
  NetworkConfig,
  NetworkRoutingConfig,
  OrganizationConfig,
  SpokeStackConfig,
} from "../src/config";

const wardenMindPreset = {
  name: "warden-mind-v1",
  networkCidrs: {
    "egress-net": "10.0.0.0/16",
    "control-net": "10.12.0.0/16",
    "execution-shared-net": "10.22.0.0/16",
    "data-shared-net": "10.32.0.0/16",
  },
};

test("Warden/Mind blueprint preset resolves exact environment CIDRs", () => {
  const loaded = resolvePlatformBlueprintConfig(undefined, wardenMindPreset);
  assert.ok(loaded);
  assert.equal(loaded.blueprint.name, "warden-mind-platform");
  assert.deepEqual(
    Object.fromEntries(
      loaded.blueprint.networkDomains.map((domain) => [
        domain.id,
        domain.cidrs[0],
      ]),
    ),
    wardenMindPreset.networkCidrs,
  );
  assert.equal(loaded.migrationReport.migrated, false);
});

test("blueprint preset rejects ambiguity, missing domains, and unknown fields", () => {
  assert.throws(
    () =>
      resolvePlatformBlueprintConfig(
        { apiVersion: "ignored" },
        wardenMindPreset,
      ),
    /either platformBlueprint or platformBlueprintPreset/,
  );
  assert.throws(
    () =>
      resolvePlatformBlueprintConfig(undefined, {
        ...wardenMindPreset,
        networkCidrs: { "control-net": "10.12.0.0/16" },
      }),
    /egress-net must be a non-empty CIDR string/,
  );
  assert.throws(
    () =>
      resolvePlatformBlueprintConfig(undefined, {
        ...wardenMindPreset,
        providerCredentials: "forbidden",
      }),
    /unknown field 'providerCredentials'/,
  );
});

const organizationConfig: OrganizationConfig = {
  createOrganization: true,
  defaultAccountRoleName: "DeusOrganizationBootstrap",
  enableRamSharing: true,
  serviceAccessPrincipals: ["cloudtrail.amazonaws.com"],
  enabledPolicyTypes: ["SERVICE_CONTROL_POLICY"],
  organizationalUnits: [{ name: "Security" }, { name: "Workloads" }],
  accounts: [
    {
      name: "platform-dev",
      email: "platform-dev@example.com",
      ou: "Workloads",
      kind: "workload",
    },
    {
      name: "execution-dev",
      email: "execution-dev@example.com",
      ou: "Workloads",
      kind: "execution",
    },
  ],
  guardrailScpsEnabled: true,
  guardrailTargetOuNames: ["Security", "Workloads"],
};

const networkConfig: NetworkConfig = {
  egress: {
    cidr: "10.0.0.0/16",
    azCount: 3,
    networkFirewallEnabled: true,
    shareTransitGatewayWithOrganization: false,
    allowedDomains: ["github.com"],
  },
  spokes: [
    {
      name: "platform",
      cidr: "10.10.0.0/16",
      kind: "platform",
      createEks: true,
    },
    {
      name: "execution",
      cidr: "10.20.0.0/16",
      kind: "execution",
      createEks: true,
    },
  ],
};

test("validateConfigValues accepts the intended baseline", () => {
  assert.doesNotThrow(() =>
    validateConfigValues("all", networkConfig, organizationConfig),
  );
});

test("validateConfigValues rejects duplicate spoke names", () => {
  assert.throws(
    () =>
      validateConfigValues(
        "workload",
        {
          ...networkConfig,
          spokes: [
            { name: "platform", cidr: "10.10.0.0/16", kind: "platform" },
            { name: "platform", cidr: "10.11.0.0/16", kind: "platform" },
          ],
        },
        organizationConfig,
      ),
    /Duplicate network spoke name/,
  );
});

test("validateConfigValues rejects unsafe AZ counts", () => {
  assert.throws(
    () =>
      validateConfigValues(
        "workload",
        {
          ...networkConfig,
          egress: { ...networkConfig.egress, azCount: 1 },
        },
        organizationConfig,
      ),
    /azCount must be between 2 and 4/,
  );
});

test("blueprint-authoritative validation ignores unused legacy network decisions", () => {
  assert.doesNotThrow(() =>
    validateConfigValues(
      "workload",
      {
        egress: { ...networkConfig.egress, azCount: 1 },
        spokes: [
          { name: "duplicate", cidr: "not-a-cidr", kind: "platform" },
          { name: "duplicate", cidr: "also-invalid", kind: "execution" },
        ],
      },
      organizationConfig,
      true,
    ),
  );
});

test("validateConfigValues rejects accounts outside known OUs", () => {
  assert.throws(
    () =>
      validateConfigValues("organization", networkConfig, {
        ...organizationConfig,
        accounts: [
          {
            name: "bad",
            email: "bad@example.com",
            ou: "Missing",
            kind: "workload",
          },
        ],
      }),
    /references unknown OU/,
  );
});

test("validateConfigValues rejects malformed modular organization topology", () => {
  assert.throws(
    () =>
      validateConfigValues("organization", networkConfig, {
        ...organizationConfig,
        organizationalUnits: [
          { name: "Security" },
          { name: "PreProd", parent: "Workloads" },
          { name: "Workloads" },
        ],
      }),
    /unknown or later parent OU/,
  );
  assert.throws(
    () =>
      validateConfigValues("organization", networkConfig, {
        ...organizationConfig,
        accounts: organizationConfig.accounts.filter(
          (account) => account.name !== "execution-dev",
        ),
      }),
    /requires paired platform and execution accounts/,
  );
  assert.throws(
    () =>
      validateConfigValues("organization", networkConfig, {
        ...organizationConfig,
        accounts: organizationConfig.accounts.map((account) =>
          account.name === "platform-dev"
            ? { ...account, create: false }
            : account,
        ),
      }),
    /must be enabled or disabled together/,
  );
});

test("management example enables dev and prod but keeps preprod paired and disabled", () => {
  const management = readFileSync("Pulumi.management.yaml.example", "utf8");
  assert.match(management, /- name: NonProd\n\s+parent: Workloads/);
  assert.match(management, /- name: PreProd\n\s+parent: Workloads/);
  assert.match(management, /- name: Prod\n\s+parent: Workloads/);
  assert.match(
    management,
    /- name: platform-staging[\s\S]*?kind: workload\n\s+create: false/,
  );
  assert.match(
    management,
    /- name: execution-staging[\s\S]*?kind: execution\n\s+create: false/,
  );
  assert.doesNotMatch(management, /- name: Execution\n/);
});

const spokeConfig: SpokeStackConfig = {
  name: "platform-dev",
  kind: "platform",
  cidr: "10.10.0.0/16",
  azCount: 3,
  createEks: true,
  networkStackRef: "org/secure-saas-infra/network",
};

const routingConfig: NetworkRoutingConfig = {
  networkStackRef: "org/secure-saas-infra/network",
  spokeStackRefs: ["org/secure-saas-infra/platform-dev"],
  azCount: 3,
  networkFirewallEnabled: true,
};

const identityCenterConfig: IdentityCenterConfig = {
  groups: [{ name: "developers", displayName: "AWS Developers", create: true }],
  permissionSets: [
    {
      name: "DeveloperReadOnly",
      description: "Developer read-only access.",
      sessionDuration: "PT4H",
      managedPolicyArns: ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
    },
  ],
  assignments: [
    {
      groupName: "developers",
      permissionSetName: "DeveloperReadOnly",
      accountIds: ["111111111111"],
    },
  ],
};

const githubOidcConfig: GithubOidcConfig = {
  enabled: true,
  repositories: [
    {
      owner: "deus-ai",
      repo: "infra",
      allowedRefs: ["refs/heads/main"],
      allowedEnvironments: ["production"],
      managedPolicyArns: ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
    },
  ],
};

const githubGovernanceConfig: GithubGovernanceConfig = {
  enabled: true,
  owner: "deus-ai",
  repository: "infra",
  defaultBranch: "main",
  requiredStatusChecks: ["npm test"],
  protectedEnvironments: [{ name: "production" }],
  allowedActionsPatterns: ["actions/*", "github/codeql-action/*"],
  requireShaPinnedActions: true,
  requireCodeOwnerReview: true,
  requireSignedCommits: true,
  requireLinearHistory: true,
  requiredApprovingReviewCount: 1,
  requireCodeScanning: true,
  codeScanningTool: "CodeQL",
  manageOrganizationSettings: false,
  bypassActors: [],
  useLegacyBranchProtection: false,
};

const executionSandboxConfig: ExecutionSandboxConfig = {
  provider: "e2b-byoc",
  dedicatedAccountRequired: true,
  privateLoadBalancerRequired: true,
  centralizedEgressRequired: true,
  maxSandboxDurationMinutes: 1440,
  allowExternalControlPlane: true,
  allowAnonymizedMetricsExport: true,
  requirePerJobAuditMetadata: true,
  requireBrokeredCredentials: true,
};

const e2bByocAccessConfig: E2bByocAccessConfig = {
  createVendorRole: true,
  vendorPrincipalArns: [
    "arn:aws:iam::123456789012:role/e2b-byoc-control-plane",
  ],
  externalId: "example-external-id-123456",
  managedPolicyArns: [
    "arn:aws:iam::123456789012:policy/e2b-byoc-least-privilege",
  ],
  maxSessionDurationSeconds: 3600,
};

const customerDataConfig: CustomerDataConfig = {
  createArtifactStore: true,
  artifactRetentionDays: 90,
  noncurrentVersionExpirationDays: 30,
  requireTenantScopedPrefixes: true,
  requireDeletionManifests: true,
  requireExportManifests: true,
  enterpriseDedicatedKmsRequired: true,
};

test("validateStackKindValues accepts modular platform and routing stacks", () => {
  assert.doesNotThrow(() =>
    validateStackKindValues("platform", spokeConfig, routingConfig),
  );
  assert.doesNotThrow(() =>
    validateStackKindValues(
      "execution",
      { ...spokeConfig, name: "execution-dev", kind: "execution" },
      routingConfig,
      undefined,
      identityCenterConfig,
      githubOidcConfig,
      githubGovernanceConfig,
      executionSandboxConfig,
      e2bByocAccessConfig,
      customerDataConfig,
    ),
  );
  assert.doesNotThrow(() =>
    validateStackKindValues("network-routing", spokeConfig, routingConfig),
  );
  assert.doesNotThrow(() =>
    validateStackKindValues(
      "identity",
      spokeConfig,
      routingConfig,
      undefined,
      identityCenterConfig,
      githubOidcConfig,
    ),
  );
  assert.doesNotThrow(() =>
    validateStackKindValues(
      "github-oidc",
      spokeConfig,
      routingConfig,
      undefined,
      identityCenterConfig,
      githubOidcConfig,
    ),
  );
  assert.doesNotThrow(() =>
    validateStackKindValues(
      "github-governance",
      spokeConfig,
      routingConfig,
      undefined,
      identityCenterConfig,
      githubOidcConfig,
      githubGovernanceConfig,
    ),
  );
});

test("validateCustomerDataConfig rejects unsafe tenant data specs", () => {
  assert.doesNotThrow(() => validateCustomerDataConfig(customerDataConfig));

  assert.throws(
    () =>
      validateCustomerDataConfig({
        ...customerDataConfig,
        createArtifactStore: false,
      }),
    /artifact store/,
  );

  assert.throws(
    () =>
      validateCustomerDataConfig({
        ...customerDataConfig,
        noncurrentVersionExpirationDays: 91,
      }),
    /no greater than artifactRetentionDays/,
  );

  assert.throws(
    () =>
      validateCustomerDataConfig({
        ...customerDataConfig,
        requireTenantScopedPrefixes: false,
      }),
    /tenant-scoped/,
  );

  assert.throws(
    () =>
      validateCustomerDataConfig({
        ...customerDataConfig,
        requireDeletionManifests: false,
      }),
    /deletion manifests/,
  );

  assert.throws(
    () =>
      validateCustomerDataConfig({
        ...customerDataConfig,
        enterpriseDedicatedKmsRequired: false,
      }),
    /dedicated KMS/,
  );
});

test("validateE2bByocAccessConfig rejects unsafe vendor role specs", () => {
  assert.doesNotThrow(() =>
    validateE2bByocAccessConfig({
      ...e2bByocAccessConfig,
      createVendorRole: false,
    }),
  );
  assert.doesNotThrow(() => validateE2bByocAccessConfig(e2bByocAccessConfig));

  assert.throws(
    () =>
      validateE2bByocAccessConfig({
        ...e2bByocAccessConfig,
        vendorPrincipalArns: ["arn:aws:iam::123456789012:root"],
      }),
    /IAM role ARNs/,
  );

  assert.throws(
    () =>
      validateE2bByocAccessConfig({
        ...e2bByocAccessConfig,
        externalId: "too-short",
      }),
    /at least 16/,
  );

  assert.throws(
    () =>
      validateE2bByocAccessConfig({
        ...e2bByocAccessConfig,
        managedPolicyArns: ["arn:aws:iam::aws:policy/AdministratorAccess"],
      }),
    /administrator managed policies/,
  );
});

test("validateStackKindValues rejects unsafe modular stack wiring", () => {
  assert.throws(
    () =>
      validateStackKindValues(
        "execution",
        {
          ...spokeConfig,
          kind: "platform",
          networkStackRef: "",
          transitGatewayId: undefined,
        },
        routingConfig,
      ),
    /require either spoke.networkStackRef/,
  );

  assert.throws(
    () =>
      validateStackKindValues("network-routing", spokeConfig, {
        ...routingConfig,
        spokeStackRefs: [],
      }),
    /at least one/,
  );
});

test("validateStackKindValues rejects unsafe identity and github oidc wiring", () => {
  assert.throws(
    () =>
      validateStackKindValues(
        "identity",
        spokeConfig,
        routingConfig,
        undefined,
        {
          ...identityCenterConfig,
          permissionSets: [
            {
              ...identityCenterConfig.permissionSets[0],
              managedPolicyArns: ["arn:aws:iam::aws:policy/PowerUserAccess"],
            },
          ],
        },
      ),
    /must not attach AdministratorAccess, PowerUserAccess, or IAMFullAccess/,
  );

  assert.throws(
    () =>
      validateStackKindValues(
        "identity",
        spokeConfig,
        routingConfig,
        undefined,
        {
          ...identityCenterConfig,
          assignments: [
            {
              groupName: "missing",
              permissionSetName: "DeveloperReadOnly",
              accountIds: ["111111111111"],
            },
          ],
        },
      ),
    /unknown group/,
  );

  assert.throws(
    () =>
      validateStackKindValues(
        "github-oidc",
        spokeConfig,
        routingConfig,
        undefined,
        identityCenterConfig,
        {
          enabled: true,
          repositories: [
            {
              owner: "deus-ai",
              repo: "infra",
              allowedRefs: [],
              allowedEnvironments: [],
              managedPolicyArns: ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
            },
          ],
        },
      ),
    /requires an allowed ref or environment/,
  );

  assert.throws(
    () =>
      validateStackKindValues(
        "github-oidc",
        spokeConfig,
        routingConfig,
        undefined,
        identityCenterConfig,
        { ...githubOidcConfig, enabled: false },
      ),
    /enabled: true/,
  );
});

test("validateGithubGovernanceConfig rejects unsafe repository governance specs", () => {
  assert.doesNotThrow(() =>
    validateGithubGovernanceConfig(githubGovernanceConfig),
  );

  assert.throws(
    () =>
      validateGithubGovernanceConfig({
        ...githubGovernanceConfig,
        enabled: false,
      }),
    /enabled: true/,
  );

  assert.throws(
    () =>
      validateGithubGovernanceConfig({
        ...githubGovernanceConfig,
        owner: "your-github-org",
      }),
    /real GitHub values/,
  );

  assert.throws(
    () =>
      validateGithubGovernanceConfig({
        ...githubGovernanceConfig,
        defaultBranch: "develop",
      }),
    /defaultBranch must be main/,
  );

  assert.throws(
    () =>
      validateGithubGovernanceConfig({
        ...githubGovernanceConfig,
        requiredStatusChecks: [],
      }),
    /must include npm test/,
  );

  assert.throws(
    () =>
      validateGithubGovernanceConfig({
        ...githubGovernanceConfig,
        requireShaPinnedActions: false,
      }),
    /SHA-pinned Actions/,
  );

  assert.throws(
    () =>
      validateGithubGovernanceConfig({
        ...githubGovernanceConfig,
        manageOrganizationSettings: true,
        organizationBillingEmail: undefined,
      }),
    /organizationBillingEmail/,
  );
});

test("validateExecutionSandboxConfig rejects unsafe execution provider specs", () => {
  assert.doesNotThrow(() =>
    validateExecutionSandboxConfig(executionSandboxConfig),
  );

  assert.throws(
    () =>
      validateExecutionSandboxConfig({
        ...executionSandboxConfig,
        provider: "disabled",
      }),
    /must not disable/,
  );

  assert.throws(
    () =>
      validateExecutionSandboxConfig({
        ...executionSandboxConfig,
        privateLoadBalancerRequired: false,
      }),
    /private load balancers/,
  );

  assert.throws(
    () =>
      validateExecutionSandboxConfig({
        ...executionSandboxConfig,
        maxSandboxDurationMinutes: 1441,
      }),
    /between 1 and 1440/,
  );

  assert.throws(
    () =>
      validateExecutionSandboxConfig({
        ...executionSandboxConfig,
        requireBrokeredCredentials: false,
      }),
    /brokered/,
  );
});

test("validateExecutionSandboxConfig holds microvm-runtimeclass to the same isolation boundary", () => {
  assert.throws(
    () =>
      validateExecutionSandboxConfig({
        ...executionSandboxConfig,
        provider: "microvm-runtimeclass",
        dedicatedAccountRequired: false,
      }),
    /dedicated execution account/,
  );

  assert.throws(
    () =>
      validateExecutionSandboxConfig({
        ...executionSandboxConfig,
        provider: "microvm-runtimeclass",
        centralizedEgressRequired: false,
      }),
    /centralized inspected egress/,
  );

  assert.throws(
    () =>
      validateExecutionSandboxConfig({
        ...executionSandboxConfig,
        provider: "microvm-runtimeclass",
        privateLoadBalancerRequired: false,
      }),
    /private load balancers/,
  );
});

const sharedServicesConfig: SharedServicesConfig = {
  createVaultAutoUnsealKey: true,
  createVaultBackupBucket: true,
  vaultBackupRetentionDays: 90,
  createTailscaleBootstrapSecrets: true,
};

const logArchiveConfig: LogArchiveConfig = {
  objectLockRetentionDays: 2555,
  transitionToGlacierDays: 90,
  cloudTrailPrefix: "cloudtrail",
  createOrganizationTrail: true,
  organizationTrailName: "deus-organization-trail",
  cloudTrailSourceAccountId: "111111111111",
  s3DataEventBucketArns: [],
};

test("validateOperationalConfigValues rejects unsafe shared-services combinations", () => {
  assert.doesNotThrow(() =>
    validateOperationalConfigValues(
      "shared-services",
      logArchiveConfig,
      sharedServicesConfig,
    ),
  );

  assert.throws(
    () =>
      validateOperationalConfigValues("shared-services", logArchiveConfig, {
        ...sharedServicesConfig,
        createVaultAutoUnsealKey: false,
        createVaultBackupBucket: true,
      }),
    /createVaultBackupBucket requires createVaultAutoUnsealKey/,
  );

  assert.throws(
    () =>
      validateOperationalConfigValues("shared-services", logArchiveConfig, {
        ...sharedServicesConfig,
        createVaultAutoUnsealKey: false,
        createVaultBackupBucket: false,
        createTailscaleBootstrapSecrets: true,
      }),
    /createTailscaleBootstrapSecrets requires createVaultAutoUnsealKey/,
  );
});

const eksConfig: EksConfig = {
  version: "1.33",
  endpointPublicAccess: false,
  autoModeNodePools: ["system", "general-purpose"],
  networkPolicyMode: "strict",
  accessGrants: [
    {
      id: "platform-admin",
      principal: {
        kind: "identity-center-permission-set",
        category: "workforce",
        permissionSetName: "PlatformPowerUser",
      },
      accessPolicy: "cluster-admin",
      scope: { type: "cluster" },
    },
  ],
};

const backupConfig: BackupConfig = {
  replicaRegion: "us-west-2",
  vaultLockEnabled: true,
  vaultLockMinRetentionDays: 35,
  vaultLockMaxRetentionDays: 2555,
  vaultLockChangeableForDays: 3,
  createPlan: true,
  dailyScheduleExpression: "cron(0 5 ? * * *)",
  backupIntervalMinutes: 1440,
  restoreTestIntervalDays: 30,
  coldStorageAfterDays: 90,
  deleteAfterDays: 365,
  selectionTags: [{ key: "Backup", value: "required" }],
};

test("validateBackupConfig accepts the baseline and rejects unsafe combinations", () => {
  assert.doesNotThrow(() => validateBackupConfig(backupConfig));

  assert.throws(
    () => validateBackupConfig({ ...backupConfig, vaultLockEnabled: false }),
    /vaultLockEnabled/,
  );

  assert.throws(
    () =>
      validateBackupConfig({
        ...backupConfig,
        vaultLockMinRetentionDays: 7,
      }),
    /at least 35/,
  );

  assert.throws(
    () =>
      validateBackupConfig({ ...backupConfig, vaultLockChangeableForDays: 0 }),
    /at least 3/,
  );

  assert.throws(
    () =>
      validateBackupConfig({
        ...backupConfig,
        deleteAfterDays: 30,
      }),
    /deleteAfterDays/,
  );
});

const databaseBaseline: DatabaseConfig = {
  name: "control-plane",
  engine: "aurora-postgresql",
  engineVersion: "16.4",
  engineMajorVersion: "16",
  databaseName: "deus",
  masterUsername: "deus_admin",
  port: 5432,
  instanceClass: "db.r6g.large",
  instanceCount: 2,
  backupRetentionDays: 35,
  deletionProtection: true,
  createProxy: true,
};

test("validateDatabaseConfig accepts baseline and rejects unsafe deltas", () => {
  assert.doesNotThrow(() => validateDatabaseConfig(databaseBaseline));

  assert.throws(
    () =>
      validateDatabaseConfig({
        ...databaseBaseline,
        deletionProtection: false,
      }),
    /deletionProtection/,
  );

  assert.throws(
    () =>
      validateDatabaseConfig({
        ...databaseBaseline,
        backupRetentionDays: 7,
      }),
    /at least 14/,
  );

  assert.throws(
    () =>
      validateDatabaseConfig({
        ...databaseBaseline,
        instanceCount: 1,
      }),
    /at least 2/,
  );
});

const wafBaseline: WafConfig = {
  name: "public-ingress",
  scope: "REGIONAL",
  rateLimitPer5Minutes: 2000,
  enableBotControl: true,
  modelGatewayPathPrefixes: ["/v1/models"],
  modelGatewayRateLimitPer5Minutes: 200,
};

test("validateWafConfig accepts baseline and rejects bad rate limits", () => {
  assert.doesNotThrow(() => validateWafConfig(wafBaseline));

  assert.throws(
    () => validateWafConfig({ ...wafBaseline, rateLimitPer5Minutes: 0 }),
    /rateLimitPer5Minutes/,
  );

  assert.throws(
    () =>
      validateWafConfig({
        ...wafBaseline,
        modelGatewayPathPrefixes: ["/v1/models"],
        modelGatewayRateLimitPer5Minutes: 0,
      }),
    /modelGatewayRateLimitPer5Minutes/,
  );
});

test("validateProductionPostureValues enforces production hub firewall and admin role wiring", () => {
  assert.doesNotThrow(() =>
    validateProductionPostureValues(
      "network-hub",
      "network",
      networkConfig,
      eksConfig,
      spokeConfig,
    ),
  );

  assert.throws(
    () =>
      validateProductionPostureValues(
        "network-hub",
        "production",
        {
          ...networkConfig,
          egress: { ...networkConfig.egress, networkFirewallEnabled: false },
        },
        eksConfig,
        spokeConfig,
      ),
    /networkFirewallEnabled must be true/,
  );

  assert.throws(
    () =>
      validateProductionPostureValues(
        "platform",
        "platform-prod",
        networkConfig,
        { ...eksConfig, accessGrants: [] },
        spokeConfig,
      ),
    /eks\.accessGrants/,
  );

  assert.throws(
    () =>
      validateProductionPostureValues(
        "single-account",
        "dev",
        networkConfig,
        { ...eksConfig, accessGrants: [] },
        spokeConfig,
      ),
    /eks\.accessGrants/,
  );
});

test("production-like environment detection does not classify development as production", () => {
  assert.equal(isProductionLikeEnvironment("dev"), false);
  assert.equal(isProductionLikeEnvironment("network"), false);
  assert.equal(isProductionLikeEnvironment("platform-production"), true);
  assert.equal(isProductionLikeEnvironment("execution_prd"), true);
  assert.equal(isProductionLikeEnvironment("staging"), true);
});

test("managed PostgreSQL deployment stage is exact and rejects ambiguous environment names", () => {
  assert.equal(deploymentStageForEnvironment("platform-dev"), "development");
  assert.equal(deploymentStageForEnvironment("platform-staging"), "staging");
  assert.equal(deploymentStageForEnvironment("platform-prod"), "production");
  assert.equal(deploymentStageForEnvironment("platform"), undefined);
  assert.equal(deploymentStageForEnvironment("dev-prod"), undefined);
});
