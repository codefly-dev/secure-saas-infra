import * as pulumi from "@pulumi/pulumi";
import { lstatSync, readFileSync } from "node:fs";
import {
  awsWorkloadProviderExtensionsFromConfig,
  compileAwsBackups,
  compileAwsDataBoundaries,
  compileAwsDatabases,
  compileAwsApplyLaneIamConstraint,
  compileAwsEksAccessGrants,
  compileAwsNetworkBlueprint,
  compileAwsWorkloads,
  parseAwsBootstrapAccessPlan,
  validateAndCompileAwsNetwork,
  type AwsEksAccessGrantConfig,
} from "./adapters/aws";
import {
  assertBlueprint,
  BlueprintMigrationReport,
  createWardenMindBlueprint,
  currentBlueprintApiVersion,
  loadPlatformBlueprint,
  LoadedPlatformBlueprint,
  PlatformBlueprint,
  type ManagedPostgresEnvironment,
  WardenMindNetworkDomainId,
  wardenMindNetworkDomainIds,
} from "./core";
import { ARGOCD_CHART_VERSION } from "./argocdValues";

export type DeploymentMode = "organization" | "workload" | "all" | "disabled";
export type StackKind =
  | "management"
  | "account-access"
  | "network-hub"
  | "network-routing"
  | "organization-audit"
  | "identity"
  | "github-oidc"
  | "github-governance"
  | "platform"
  | "execution"
  | "single-account"
  | "security-tooling"
  | "log-archive"
  | "shared-services"
  | "backup"
  | "detection"
  | "compliance"
  | "cost-controls"
  | "macie"
  | "waf"
  | "ingress"
  | "dns"
  | "argocd"
  | "disabled";
export type SpokeKind = "platform" | "execution" | "data" | "shared";
export interface PlatformBlueprintPresetConfig {
  name: "warden-mind-v1";
  networkCidrs: Record<WardenMindNetworkDomainId, string>;
}
export type OrganizationAccountKind =
  | "management"
  | "security"
  | "log-archive"
  | "network"
  | "shared-services"
  | "workload"
  | "execution";

export interface OrganizationUnitConfig {
  name: string;
  parent?: string;
}

export interface OrganizationAccountConfig {
  name: string;
  email: string;
  ou: string;
  kind: OrganizationAccountKind;
  create?: boolean;
  roleName?: string;
  closeOnDeletion?: boolean;
  tags?: Record<string, string>;
}

export interface OrganizationConfig {
  createOrganization: boolean;
  defaultAccountRoleName: string;
  enableRamSharing: boolean;
  enableSecurityDelegatedAdmin?: boolean;
  securityDelegatedAdminAccountName?: string;
  serviceAccessPrincipals: string[];
  enabledPolicyTypes: string[];
  organizationalUnits: OrganizationUnitConfig[];
  accounts: OrganizationAccountConfig[];
  guardrailScpsEnabled: boolean;
  guardrailTargetOuNames: string[];
}

export interface EgressConfig {
  cidr: string;
  azCount: number;
  networkFirewallEnabled: boolean;
  shareTransitGatewayWithOrganization?: boolean;
  allowedDomains: string[];
}

export interface SpokeConfig {
  name: string;
  cidr: string;
  kind: SpokeKind;
  createEks?: boolean;
}

export interface NetworkConfig {
  egress: EgressConfig;
  spokes: SpokeConfig[];
}

export interface SpokeStackConfig {
  name: string;
  kind: SpokeKind;
  cidr: string;
  azCount: number;
  createEks: boolean;
  networkStackRef: string;
  transitGatewayId?: string;
  zoneId?: string;
  networkDomainId?: string;
}

export interface NetworkRoutingSpokeBinding {
  stackRef: string;
  zoneId: string;
  networkDomainId: string;
}

export interface NetworkRoutingConfig {
  networkStackRef: string;
  spokeStackRefs: string[];
  spokeBindings?: NetworkRoutingSpokeBinding[];
  azCount: number;
  networkFirewallEnabled: boolean;
}

export interface EksConfig {
  version: string;
  endpointPublicAccess: boolean;
  autoModeNodePools: string[];
  networkPolicyMode: "standard" | "strict";
  accessGrants: AwsEksAccessGrantConfig[];
}

export interface SecurityConfig {
  enableGuardDuty: boolean;
  enableSecurityHub: boolean;
}

export interface CodeflyRegistryConfig {
  enabled: boolean;
  repositories: string[];
  retainImageCount: number;
  untaggedRetentionDays: number;
}

export interface LogArchiveConfig {
  bucketName?: string;
  objectLockRetentionDays: number;
  transitionToGlacierDays: number;
  cloudTrailPrefix: string;
  createOrganizationTrail: boolean;
  organizationTrailName: string;
  cloudTrailSourceAccountId?: string;
  s3DataEventBucketArns: string[];
}

export interface OrganizationAuditConfig {
  logArchiveStackRef: string;
  organizationTrailName: string;
  cloudTrailPrefix: string;
  s3DataEventBucketArns: string[];
}

export interface SecurityToolingConfig {
  enableGuardDutyOrganization: boolean;
  enableSecurityHubOrganization: boolean;
  enableInspectorOrganization: boolean;
  enableConfigAggregator: boolean;
  configAggregatorAllRegions: boolean;
  inspectorAccountIds: string[];
}

export interface SharedServicesConfig {
  createVaultAutoUnsealKey: boolean;
  createVaultBackupBucket: boolean;
  vaultBackupRetentionDays: number;
  createTailscaleBootstrapSecrets: boolean;
}

export interface IdentityGroupConfig {
  name: string;
  displayName: string;
  description?: string;
  create?: boolean;
  groupId?: string;
}

export interface PermissionSetConfig {
  name: string;
  description: string;
  sessionDuration: string;
  managedPolicyArns: string[];
  inlinePolicy?: Record<string, unknown>;
}

export interface IdentityAssignmentConfig {
  groupName: string;
  permissionSetName: string;
  accountNames?: string[];
  accountIds?: string[];
}

export interface IdentityCenterConfig {
  identityCenterInstanceArn?: string;
  identityStoreId?: string;
  organizationStackRef?: string;
  groups: IdentityGroupConfig[];
  permissionSets: PermissionSetConfig[];
  assignments: IdentityAssignmentConfig[];
}

export interface GithubOidcRepositoryConfig {
  name?: string;
  owner: string;
  repo: string;
  description?: string;
  allowedRefs: string[];
  allowedEnvironments: string[];
  managedPolicyArns: string[];
  inlinePolicy?: Record<string, unknown>;
  maxSessionDurationSeconds?: number;
}

export interface GithubOidcConfig {
  enabled: boolean;
  repositories: GithubOidcRepositoryConfig[];
}

export interface GithubGovernanceEnvironmentConfig {
  name: string;
  reviewerTeamIds?: number[];
  reviewerUserIds?: number[];
  waitTimerMinutes?: number;
}

export interface GithubRulesetBypassActor {
  actorId: number;
  actorType:
    | "RepositoryRole"
    | "Team"
    | "Integration"
    | "OrganizationAdmin"
    | "DeployKey";
  bypassMode: "always" | "pull_request";
}

export interface GithubGovernanceConfig {
  enabled: boolean;
  owner: string;
  repository: string;
  defaultBranch: string;
  requiredStatusChecks: string[];
  protectedEnvironments: GithubGovernanceEnvironmentConfig[];
  allowedActionsPatterns: string[];
  requireShaPinnedActions: boolean;
  requireCodeOwnerReview: boolean;
  requireSignedCommits: boolean;
  requireLinearHistory: boolean;
  requiredApprovingReviewCount: number;
  requireCodeScanning: boolean;
  codeScanningTool: string;
  manageOrganizationSettings: boolean;
  organizationBillingEmail?: string;
  bypassActors: GithubRulesetBypassActor[];
  // Use legacy branch protection only when the repository's plan supports it
  // but repository rulesets are unavailable or intentionally not selected.
  // GitHub Free organization plans support neither control for private
  // repositories. Legacy protection covers signed commits, required reviews,
  // CODEOWNERS, status checks, linear history, and force-push denial, but loses
  // the push ruleset and typed bypass-actor framework.
  useLegacyBranchProtection: boolean;
}

export type ExecutionSandboxProvider =
  | "e2b-byoc"
  | "e2b-self-hosted"
  | "microvm-runtimeclass"
  | "disabled";

export interface ExecutionSandboxConfig {
  provider: ExecutionSandboxProvider;
  dedicatedAccountRequired: boolean;
  privateLoadBalancerRequired: boolean;
  centralizedEgressRequired: boolean;
  maxSandboxDurationMinutes: number;
  allowExternalControlPlane: boolean;
  allowAnonymizedMetricsExport: boolean;
  requirePerJobAuditMetadata: boolean;
  requireBrokeredCredentials: boolean;
}

export interface E2bByocAccessConfig {
  createVendorRole: boolean;
  vendorPrincipalArns: string[];
  externalId?: string;
  managedPolicyArns: string[];
  inlinePolicy?: Record<string, unknown>;
  maxSessionDurationSeconds?: number;
}

export interface CustomerDataConfig {
  createArtifactStore: boolean;
  artifactRetentionDays: number;
  noncurrentVersionExpirationDays: number;
  requireTenantScopedPrefixes: boolean;
  requireDeletionManifests: boolean;
  requireExportManifests: boolean;
  enterpriseDedicatedKmsRequired: boolean;
  replicationRegion?: string;
  replicationAccountId?: string;
}

export interface BackupConfig {
  replicaRegion?: string;
  vaultLockEnabled: boolean;
  vaultLockMinRetentionDays: number;
  vaultLockMaxRetentionDays: number;
  vaultLockChangeableForDays: number;
  createPlan: boolean;
  dailyScheduleExpression: string;
  backupIntervalMinutes: number;
  restoreTestIntervalDays: number;
  coldStorageAfterDays: number;
  deleteAfterDays: number;
  selectionTags: Array<{ key: string; value: string }>;
}

export type DatabaseEngine = "aurora-postgresql" | "aurora-mysql";

export interface DatabaseConfig {
  name: string;
  engine: DatabaseEngine;
  engineVersion: string;
  engineMajorVersion: string;
  databaseName: string;
  masterUsername: string;
  port: number;
  instanceClass: string;
  instanceCount: number;
  backupRetentionDays: number;
  deletionProtection: boolean;
  createProxy: boolean;
  replicaRegion?: string;
}

export interface WafConfig {
  name: string;
  scope: "REGIONAL" | "CLOUDFRONT";
  rateLimitPer5Minutes: number;
  enableBotControl: boolean;
  modelGatewayPathPrefixes: string[];
  modelGatewayRateLimitPer5Minutes: number;
}

export interface MacieClassificationJobConfig {
  accountId: string;
  buckets: string[];
  dayOfWeek:
    | "MONDAY"
    | "TUESDAY"
    | "WEDNESDAY"
    | "THURSDAY"
    | "FRIDAY"
    | "SATURDAY"
    | "SUNDAY";
}

export interface MacieConfig {
  classificationJobs: MacieClassificationJobConfig[];
}

export interface DetectionConfig {
  emailSubscriptions: string[];
}

export interface ComplianceConfig {
  deployConformancePack: boolean;
  createAuditManagerAssessment: boolean;
  auditManagerFrameworkArn?: string;
  auditEvidenceBucket?: string;
  auditManagerAccountIds: string[];
  auditManagerRoleArns: string[];
}

export interface CostControlsTenantBudget {
  tenantId: string;
  monthlyLimitUsd: number;
  thresholdPercent: number;
}

export interface CostControlsConfig {
  notificationEmails: string[];
  tenantBudgets: CostControlsTenantBudget[];
  enableAnomalyDetection: boolean;
  anomalyMinImpactUsd: number;
}

export interface DnsConfig {
  rootDomain: string;
  createRootZone: boolean;
  enableQueryLogging: boolean;
  environmentSubdomains: string[];
}

export interface ArgocdConfig {
  clusterStackRef: string;
  clusterName: string;
  clusterRole: "platform" | "execution";
  clusterAccessRoleArn: string;
  argocdHostname: string;
  chartVersion: string;
  bootstrap: {
    repository: string;
    revision: string;
    entrypoint: string;
  };
  oidcIssuer: string;
  oidcClientId: string;
  oidcClientSecretRef: string;
  oidcAdminGroup: string;
}

export interface IngressConfig {
  domainName: string;
  subjectAlternativeNames: string[];
  hostedZoneId?: string;
  internalNlbArn: string;
  originDomainName: string;
  webAclArn?: string;
  priceClass: "PriceClass_100" | "PriceClass_200" | "PriceClass_All";
  minimumTlsVersion:
    | "TLSv1.2_2018"
    | "TLSv1.2_2019"
    | "TLSv1.2_2021"
    | "TLSv1.3_2021";
  geoRestrictionType: "none" | "whitelist" | "blacklist";
  geoRestrictionLocations: string[];
  modelGatewayPathPrefixes: string[];
  contentSecurityPolicy: string;
  logRetentionDays: number;
}

export interface AgenticAiConfig {
  modelGatewayHostnames: string[];
  permittedModelProviders: string[];
  brokerEgressNamespaces: string[];
  requirePromptAuditLog: boolean;
  requireToolCallAuditLog: boolean;
  requireOutputFiltering: boolean;
  perTenantTokenBudget: number;
  perTenantInferenceTimeoutSeconds: number;
}

const projectConfig = new pulumi.Config();
const awsConfig = new pulumi.Config("aws");

export const projectName = pulumi.getProject();
export const stackName = pulumi.getStack();
export const deploymentMode = (projectConfig.get("deploymentMode") ??
  "workload") as DeploymentMode;
export const stackKind =
  (projectConfig.get("stackKind") as StackKind | undefined) ??
  stackKindFromDeploymentMode(deploymentMode);
export const awsRegion = awsConfig.get("region") ?? "us-east-1";
export const awsAllowedAccountIds =
  awsConfig.getObject<string[]>("allowedAccountIds") ?? [];
export const organizationName = projectConfig.get("organizationName") ?? "deus";
export const awsOrganizationId = projectConfig.get("awsOrganizationId");
export const environment = projectConfig.get("environment") ?? stackName;
const rawPlatformBlueprint =
  projectConfig.getObject<unknown>("platformBlueprint");
const rawPlatformBlueprintPreset = projectConfig.getObject<unknown>(
  "platformBlueprintPreset",
);
const loadedPlatformBlueprint = resolvePlatformBlueprintConfig(
  rawPlatformBlueprint,
  rawPlatformBlueprintPreset,
);
export const platformBlueprint: PlatformBlueprint | undefined =
  loadedPlatformBlueprint?.blueprint;
export const platformBlueprintMigrationReport:
  | BlueprintMigrationReport
  | undefined = loadedPlatformBlueprint?.migrationReport;
export const managedPostgresContractPath = projectConfig.get(
  "managedPostgresContractPath",
);
export const managedPostgresEnvironment = projectConfig.get(
  "managedPostgresEnvironment",
) as ManagedPostgresEnvironment | undefined;
const awsBootstrapAccessPlanObject = projectConfig.getObject<unknown>(
  "awsBootstrapAccessPlan",
);
const awsBootstrapAccessPlanJson = projectConfig.get(
  "awsBootstrapAccessPlanJson",
);
const awsBootstrapAccessPlanPath = projectConfig.get(
  "awsBootstrapAccessPlanPath",
);
if (
  [
    awsBootstrapAccessPlanObject,
    awsBootstrapAccessPlanJson,
    awsBootstrapAccessPlanPath,
  ].filter((value) => value !== undefined).length > 1
) {
  throw new Error(
    "Configure exactly one of awsBootstrapAccessPlan, awsBootstrapAccessPlanJson, or awsBootstrapAccessPlanPath.",
  );
}
export const awsBootstrapAccessPlan =
  awsBootstrapAccessPlanObject ??
  (awsBootstrapAccessPlanJson
    ? parseJsonConfig(awsBootstrapAccessPlanJson, "awsBootstrapAccessPlanJson")
    : awsBootstrapAccessPlanPath
      ? loadAwsBootstrapAccessPlan(awsBootstrapAccessPlanPath)
      : undefined);
export const awsBootstrapAccessAccountName = projectConfig.get(
  "awsBootstrapAccessAccountName",
);

export const organizationConfig =
  projectConfig.getObject<OrganizationConfig>("organization") ??
  ({
    createOrganization: false,
    defaultAccountRoleName: "DeusOrganizationBootstrap",
    enableRamSharing: true,
    enableSecurityDelegatedAdmin: true,
    securityDelegatedAdminAccountName: "security-tooling",
    serviceAccessPrincipals: [
      "cloudtrail.amazonaws.com",
      "config.amazonaws.com",
      "guardduty.amazonaws.com",
      "securityhub.amazonaws.com",
      "inspector2.amazonaws.com",
    ],
    enabledPolicyTypes: ["SERVICE_CONTROL_POLICY"],
    organizationalUnits: [
      { name: "Security" },
      { name: "Infrastructure" },
      { name: "Workloads" },
      { name: "NonProd", parent: "Workloads" },
      { name: "PreProd", parent: "Workloads" },
      { name: "Prod", parent: "Workloads" },
      { name: "Suspended" },
    ],
    accounts: [],
    guardrailScpsEnabled: true,
    guardrailTargetOuNames: ["Security", "Infrastructure", "Workloads"],
  } satisfies OrganizationConfig);

export const networkConfig =
  projectConfig.getObject<NetworkConfig>("network") ??
  ({
    egress: {
      cidr: "10.0.0.0/16",
      azCount: 3,
      networkFirewallEnabled: true,
      shareTransitGatewayWithOrganization: false,
      allowedDomains: [
        "github.com",
        "api.github.com",
        "registry.npmjs.org",
        "pypi.org",
        "files.pythonhosted.org",
      ],
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
  } satisfies NetworkConfig);

export const eksConfig =
  projectConfig.getObject<EksConfig>("eks") ??
  ({
    version: "1.33",
    endpointPublicAccess: false,
    autoModeNodePools: ["system", "general-purpose"],
    networkPolicyMode: "strict",
    accessGrants: [],
  } satisfies EksConfig);

export const securityConfig =
  projectConfig.getObject<SecurityConfig>("security") ??
  ({
    enableGuardDuty: false,
    enableSecurityHub: false,
  } satisfies SecurityConfig);

export const codeflyRegistryConfig =
  projectConfig.getObject<CodeflyRegistryConfig>("codeflyRegistry") ??
  ({
    enabled: false,
    repositories: [],
    retainImageCount: 100,
    untaggedRetentionDays: 14,
  } satisfies CodeflyRegistryConfig);

export const spokeStackConfig =
  projectConfig.getObject<SpokeStackConfig>("spoke") ??
  ({
    name: "platform",
    kind: "platform",
    cidr: "10.10.0.0/16",
    azCount: 3,
    createEks: true,
    networkStackRef: "",
  } satisfies SpokeStackConfig);

export const networkRoutingConfig =
  projectConfig.getObject<NetworkRoutingConfig>("networkRouting") ??
  ({
    networkStackRef: "",
    spokeStackRefs: [],
    azCount: 3,
    networkFirewallEnabled: true,
  } satisfies NetworkRoutingConfig);

export const logArchiveConfig =
  projectConfig.getObject<LogArchiveConfig>("logArchive") ??
  ({
    objectLockRetentionDays: 2555,
    transitionToGlacierDays: 90,
    cloudTrailPrefix: "cloudtrail",
    createOrganizationTrail: false,
    organizationTrailName: "deus-organization-trail",
    s3DataEventBucketArns: [],
  } satisfies LogArchiveConfig);

export const organizationAuditConfig =
  projectConfig.getObject<OrganizationAuditConfig>("organizationAudit") ??
  ({
    logArchiveStackRef: "",
    organizationTrailName: "deus-organization-trail",
    cloudTrailPrefix: "cloudtrail",
    s3DataEventBucketArns: [],
  } satisfies OrganizationAuditConfig);

export const securityToolingConfig =
  projectConfig.getObject<SecurityToolingConfig>("securityTooling") ??
  ({
    enableGuardDutyOrganization: true,
    enableSecurityHubOrganization: true,
    enableInspectorOrganization: true,
    enableConfigAggregator: true,
    configAggregatorAllRegions: true,
    inspectorAccountIds: [],
  } satisfies SecurityToolingConfig);

export const sharedServicesConfig =
  projectConfig.getObject<SharedServicesConfig>("sharedServices") ??
  ({
    createVaultAutoUnsealKey: true,
    createVaultBackupBucket: true,
    vaultBackupRetentionDays: 90,
    createTailscaleBootstrapSecrets: true,
  } satisfies SharedServicesConfig);

export const identityCenterConfig =
  projectConfig.getObject<IdentityCenterConfig>("identityCenter") ??
  ({
    organizationStackRef: "",
    groups: [
      {
        name: "security-admins",
        displayName: "AWS Security Admins",
        create: true,
      },
      {
        name: "platform-admins",
        displayName: "AWS Platform Admins",
        create: true,
      },
      { name: "developers", displayName: "AWS Developers", create: true },
      { name: "readonly", displayName: "AWS ReadOnly", create: true },
      { name: "breakglass", displayName: "AWS BreakGlass", create: true },
    ],
    permissionSets: [
      {
        name: "SecurityAuditReadOnly",
        description: "Read-only security visibility across accounts.",
        sessionDuration: "PT4H",
        managedPolicyArns: [
          "arn:aws:iam::aws:policy/SecurityAudit",
          "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
        ],
      },
      {
        name: "PlatformOperationsReadOnly",
        description:
          "Read-only platform visibility; mutations use separately approved deploy roles.",
        sessionDuration: "PT2H",
        managedPolicyArns: [
          "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
        ],
      },
      {
        name: "DeveloperReadOnly",
        description: "Read-only developer access.",
        sessionDuration: "PT4H",
        managedPolicyArns: ["arn:aws:iam::aws:policy/ReadOnlyAccess"],
      },
    ],
    assignments: [
      {
        groupName: "security-admins",
        permissionSetName: "SecurityAuditReadOnly",
        accountNames: [
          "security-tooling",
          "log-archive",
          "network",
          "shared-services",
        ],
      },
      {
        groupName: "platform-admins",
        permissionSetName: "PlatformOperationsReadOnly",
        accountNames: ["platform-dev", "platform-prod"],
      },
      {
        groupName: "developers",
        permissionSetName: "DeveloperReadOnly",
        accountNames: ["platform-dev", "execution-dev"],
      },
    ],
  } satisfies IdentityCenterConfig);

export const githubOidcConfig =
  projectConfig.getObject<GithubOidcConfig>("githubOidc") ??
  ({
    enabled: false,
    repositories: [],
  } satisfies GithubOidcConfig);

export const githubGovernanceConfig =
  projectConfig.getObject<GithubGovernanceConfig>("githubGovernance") ??
  ({
    enabled: false,
    owner: "",
    repository: "",
    defaultBranch: "main",
    requiredStatusChecks: ["npm test"],
    protectedEnvironments: [{ name: "production" }],
    allowedActionsPatterns: [
      "actions/*",
      "github/codeql-action/*",
      "sigstore/*",
      "slsa-framework/*",
    ],
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
  } satisfies GithubGovernanceConfig);

export const executionSandboxConfig =
  projectConfig.getObject<ExecutionSandboxConfig>("executionSandbox") ??
  ({
    provider: "e2b-byoc",
    dedicatedAccountRequired: true,
    privateLoadBalancerRequired: true,
    centralizedEgressRequired: true,
    maxSandboxDurationMinutes: 1440,
    allowExternalControlPlane: true,
    allowAnonymizedMetricsExport: true,
    requirePerJobAuditMetadata: true,
    requireBrokeredCredentials: true,
  } satisfies ExecutionSandboxConfig);

export const e2bByocAccessConfig =
  projectConfig.getObject<E2bByocAccessConfig>("e2bByocAccess") ??
  ({
    createVendorRole: false,
    vendorPrincipalArns: [],
    managedPolicyArns: [],
    maxSessionDurationSeconds: 3600,
  } satisfies E2bByocAccessConfig);

export const customerDataConfig =
  projectConfig.getObject<CustomerDataConfig>("customerData") ??
  ({
    createArtifactStore: true,
    artifactRetentionDays: 90,
    noncurrentVersionExpirationDays: 30,
    requireTenantScopedPrefixes: true,
    requireDeletionManifests: true,
    requireExportManifests: true,
    enterpriseDedicatedKmsRequired: true,
  } satisfies CustomerDataConfig);

export const backupConfig =
  projectConfig.getObject<BackupConfig>("backup") ??
  ({
    replicaRegion: undefined,
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
  } satisfies BackupConfig);

export const databaseConfig =
  projectConfig.getObject<DatabaseConfig>("database");

export const wafConfig = projectConfig.getObject<WafConfig>("waf") ?? {
  name: "public-ingress",
  scope: "REGIONAL" as const,
  rateLimitPer5Minutes: 2000,
  enableBotControl: true,
  modelGatewayPathPrefixes: ["/v1/models", "/v1/agents"],
  modelGatewayRateLimitPer5Minutes: 200,
};

export const macieConfig =
  projectConfig.getObject<MacieConfig>("macie") ??
  ({
    classificationJobs: [],
  } satisfies MacieConfig);

export const detectionConfig =
  projectConfig.getObject<DetectionConfig>("detection") ??
  ({
    emailSubscriptions: [],
  } satisfies DetectionConfig);

export const complianceConfig =
  projectConfig.getObject<ComplianceConfig>("compliance") ??
  ({
    deployConformancePack: true,
    createAuditManagerAssessment: false,
    auditManagerAccountIds: [],
    auditManagerRoleArns: [],
  } satisfies ComplianceConfig);

export const costControlsConfig =
  projectConfig.getObject<CostControlsConfig>("costControls") ??
  ({
    notificationEmails: [],
    tenantBudgets: [],
    enableAnomalyDetection: true,
    anomalyMinImpactUsd: 100,
  } satisfies CostControlsConfig);

export const ingressConfig = projectConfig.getObject<IngressConfig>("ingress");

export const dnsConfig = projectConfig.getObject<DnsConfig>("dns");

export const argocdConfig = projectConfig.getObject<ArgocdConfig>("argocd");

export const agenticAiConfig =
  projectConfig.getObject<AgenticAiConfig>("agenticAi") ??
  ({
    modelGatewayHostnames: ["api.openai.com", "api.anthropic.com"],
    permittedModelProviders: ["openai", "anthropic", "bedrock"],
    brokerEgressNamespaces: ["agent-broker", "agent-egress"],
    requirePromptAuditLog: true,
    requireToolCallAuditLog: true,
    requireOutputFiltering: true,
    perTenantTokenBudget: 1_000_000,
    perTenantInferenceTimeoutSeconds: 60,
  } satisfies AgenticAiConfig);

export const baseTags: Record<string, string> = {
  Project: projectName,
  Stack: stackName,
  Organization: organizationName,
  Environment: environment,
  ManagedBy: "pulumi",
};

export function named(name: string) {
  return `${organizationName}-${environment}-${name}`;
}

export function resolvePlatformBlueprintConfig(
  rawBlueprint: unknown,
  rawPreset: unknown,
): LoadedPlatformBlueprint | undefined {
  if (rawBlueprint !== undefined && rawPreset !== undefined) {
    throw new Error(
      "Configure either platformBlueprint or platformBlueprintPreset, not both.",
    );
  }
  if (rawBlueprint !== undefined) return loadPlatformBlueprint(rawBlueprint);
  if (rawPreset === undefined) return undefined;

  const preset = strictConfigObject(
    rawPreset,
    "platformBlueprintPreset",
    new Set(["name", "networkCidrs"]),
  );
  if (preset.name !== "warden-mind-v1") {
    throw new Error("platformBlueprintPreset.name must be 'warden-mind-v1'.");
  }
  const rawNetworkCidrs = strictConfigObject(
    preset.networkCidrs,
    "platformBlueprintPreset.networkCidrs",
    new Set<string>(wardenMindNetworkDomainIds),
  );
  const networkCidrs = Object.fromEntries(
    wardenMindNetworkDomainIds.map((networkDomainId) => {
      const cidr = rawNetworkCidrs[networkDomainId];
      if (typeof cidr !== "string" || cidr.length === 0) {
        throw new Error(
          `platformBlueprintPreset.networkCidrs.${networkDomainId} must be a non-empty CIDR string.`,
        );
      }
      return [networkDomainId, cidr];
    }),
  ) as Record<WardenMindNetworkDomainId, string>;
  const blueprint = createWardenMindBlueprint({ networkCidrs });
  assertBlueprint(blueprint);
  return {
    blueprint,
    migrationReport: {
      sourceVersion: currentBlueprintApiVersion,
      targetVersion: currentBlueprintApiVersion,
      migrated: false,
      changes: [],
    },
  };
}

function strictConfigObject(
  value: unknown,
  path: string,
  allowedKeys: ReadonlySet<string>,
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object.`);
  }
  const result = value as Record<string, unknown>;
  for (const key of Object.keys(result)) {
    if (!allowedKeys.has(key)) {
      throw new Error(`${path} contains unknown field '${key}'.`);
    }
  }
  return result;
}

function parseJsonConfig(value: string, path: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    throw new Error(`${path} must contain valid JSON.`);
  }
}

function loadAwsBootstrapAccessPlan(path: string): unknown {
  if (!/^contracts\/[a-z0-9][a-z0-9.-]*\.json$/.test(path)) {
    throw new Error(
      "awsBootstrapAccessPlanPath must name an exact JSON file under contracts/.",
    );
  }
  try {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || !stat.isFile()) {
      throw new Error("not a regular file");
    }
    return parseJsonConfig(readFileSync(path, "utf8"), path);
  } catch (error) {
    if (error instanceof Error && error.message.includes("valid JSON")) {
      throw error;
    }
    throw new Error(`Unable to read awsBootstrapAccessPlanPath '${path}'.`);
  }
}

export function validateConfig() {
  compileAwsEksAccessGrants(eksConfig.accessGrants);
  if (platformBlueprint) {
    assertBlueprint(platformBlueprint);
  }
  if (
    managedPostgresContractPath &&
    !/^contracts\/[a-z0-9][a-z0-9.-]*\.json$/.test(managedPostgresContractPath)
  ) {
    throw new Error(
      "managedPostgresContractPath must name an exact JSON file under contracts/.",
    );
  }
  if (managedPostgresContractPath && !platformBlueprint) {
    throw new Error(
      "managedPostgresContractPath requires a versioned platformBlueprint.",
    );
  }
  if (
    managedPostgresContractPath &&
    !new Set(["development", "staging", "production"]).has(
      managedPostgresEnvironment ?? "",
    )
  ) {
    throw new Error(
      "managedPostgresContractPath requires managedPostgresEnvironment to be development, staging, or production.",
    );
  }
  if (
    managedPostgresContractPath &&
    deploymentStageForEnvironment(environment) !== managedPostgresEnvironment
  ) {
    throw new Error(
      "managedPostgresEnvironment must exactly match the development, staging, or production token in environment.",
    );
  }
  if (
    managedPostgresContractPath &&
    !/^o-[a-z0-9]{10,32}$/.test(awsOrganizationId ?? "")
  ) {
    throw new Error(
      "managedPostgresContractPath requires one exact awsOrganizationId for EKS Pod Identity trust.",
    );
  }
  if (
    managedPostgresContractPath &&
    (awsAllowedAccountIds.length !== 1 ||
      !/^\d{12}$/.test(awsAllowedAccountIds[0] ?? ""))
  ) {
    throw new Error(
      "managedPostgresContractPath requires exactly one 12-digit aws:allowedAccountIds entry so canonical plans cannot target the wrong account.",
    );
  }
  if (stackKind === "account-access") {
    if (!awsBootstrapAccessPlan || !awsBootstrapAccessAccountName) {
      throw new Error(
        "account-access stacks require awsBootstrapAccessPlan and awsBootstrapAccessAccountName.",
      );
    }
    const accessPlan = parseAwsBootstrapAccessPlan(awsBootstrapAccessPlan);
    if (
      !accessPlan.accounts.some(
        (account) => account.accountName === awsBootstrapAccessAccountName,
      )
    ) {
      throw new Error(
        `awsBootstrapAccessAccountName '${awsBootstrapAccessAccountName}' is not declared in awsBootstrapAccessPlan.`,
      );
    }
  }
  validateConfigValues(
    deploymentMode,
    networkConfig,
    organizationConfig,
    platformBlueprint !== undefined,
  );
  validateStackKindValues(
    stackKind,
    spokeStackConfig,
    networkRoutingConfig,
    organizationAuditConfig,
    identityCenterConfig,
    githubOidcConfig,
    githubGovernanceConfig,
    executionSandboxConfig,
    e2bByocAccessConfig,
    customerDataConfig,
    platformBlueprint,
  );
  validateOperationalConfigValues(
    stackKind,
    logArchiveConfig,
    sharedServicesConfig,
  );
  if (platformBlueprint) {
    validateBlueprintAwsCompilation(platformBlueprint);
  } else {
    validateProductionPostureValues(
      stackKind,
      environment,
      networkConfig,
      eksConfig,
      spokeStackConfig,
    );
    validateAndCompileAwsNetwork(networkConfig, {
      name: `${organizationName}-${environment}-network`,
      environment,
      requireInspectedEgress:
        isProductionLikeEnvironment(environment) &&
        (stackKind === "network-hub" || stackKind === "single-account"),
    });
  }

  if (stackKind === "backup") {
    validateBackupConfig(backupConfig);
  }

  if (stackKind === "waf") {
    validateWafConfig(wafConfig);
  }

  if (stackKind === "platform" || stackKind === "execution") {
    validateAgenticAiConfig(agenticAiConfig);
    if (databaseConfig) {
      validateDatabaseConfig(databaseConfig);
    }
  }

  if (stackKind === "platform" || stackKind === "single-account") {
    validateCodeflyRegistryConfig(codeflyRegistryConfig);
  }

  if (stackKind === "ingress") {
    if (!ingressConfig) {
      throw new Error(
        "ingress stacks require secure-saas-infra:ingress configuration.",
      );
    }
    validateIngressConfig(ingressConfig);
  }

  if (stackKind === "dns") {
    if (!dnsConfig) {
      throw new Error(
        "dns stacks require secure-saas-infra:dns configuration.",
      );
    }
    validateDnsConfig(dnsConfig);
  }

  if (stackKind === "argocd") {
    if (!argocdConfig) {
      throw new Error(
        "argocd stacks require secure-saas-infra:argocd configuration.",
      );
    }
    validateArgocdConfig(argocdConfig);
  }
}

function validateBlueprintAwsCompilation(blueprint: PlatformBlueprint) {
  if (
    [
      "network-hub",
      "network-routing",
      "platform",
      "execution",
      "single-account",
    ].includes(stackKind)
  ) {
    compileAwsNetworkBlueprint(blueprint, {
      shareTransitGatewayWithOrganization:
        networkConfig.egress.shareTransitGatewayWithOrganization ?? false,
      createEksByZoneId: {},
      spokeKindByZoneId: {},
    });
  }

  if (["platform", "execution", "single-account"].includes(stackKind)) {
    const workloadPlan = compileAwsWorkloads(
      blueprint,
      awsWorkloadProviderExtensionsFromConfig(eksConfig, e2bByocAccessConfig),
    );
    const relevantPlanes =
      stackKind === "single-account"
        ? workloadPlan.planes
        : workloadPlan.planes.filter(
            (plane) => plane.zoneId === spokeStackConfig.zoneId,
          );
    const relevantRelational = blueprint.dataBoundaries.filter(
      (boundary) =>
        boundary.services.includes("relational") &&
        (stackKind === "single-account" ||
          boundary.zoneId === spokeStackConfig.zoneId),
    );
    if (relevantPlanes.length === 0 && relevantRelational.length === 0) {
      throw new Error(
        `${stackKind} stack has no workload or relational data plane bound to its neutral spoke zone.`,
      );
    }
    if (
      relevantPlanes.some((plane) =>
        plane.deploymentKind.startsWith("private-eks"),
      ) &&
      !hasClusterAdministrator(eksConfig.accessGrants)
    ) {
      throw new Error(
        `${stackKind} stack compiles private EKS and must declare at least one secure-saas-infra:eks.accessGrants cluster-admin entry.`,
      );
    }
    if (relevantRelational.length > 0) {
      if (!databaseConfig) {
        throw new Error(
          `${stackKind} stack requires database configuration for its relational data boundaries.`,
        );
      }
      if (!awsBootstrapAccessPlan || !awsBootstrapAccessAccountName) {
        throw new Error(
          `${stackKind} relational infrastructure requires awsBootstrapAccessPlan and awsBootstrapAccessAccountName so every IAM role is name- and boundary-constrained.`,
        );
      }
      compileAwsApplyLaneIamConstraint(
        awsBootstrapAccessPlan,
        awsBootstrapAccessAccountName,
        "database",
      );
      compileAwsDatabases(blueprint, {
        engine: databaseConfig.engine,
        engineVersion: databaseConfig.engineVersion,
        instanceClass: databaseConfig.instanceClass,
        instanceCount: databaseConfig.instanceCount,
        backupRetentionDays: databaseConfig.backupRetentionDays,
        continuousPointInTimeRecovery: true,
        replicaRegion: databaseConfig.replicaRegion,
      });
    }
  }

  if (stackKind === "execution") {
    const dataPlan = compileAwsDataBoundaries(blueprint, {
      noncurrentVersionExpirationDays:
        customerDataConfig.noncurrentVersionExpirationDays,
      replicationRegion: customerDataConfig.replicationRegion,
      replicationAccountId: customerDataConfig.replicationAccountId,
    });
    if (dataPlan.artifactStores.length === 0) {
      throw new Error(
        "execution stack blueprint must declare at least one artifact data boundary.",
      );
    }
  }

  if (stackKind === "backup") {
    compileAwsBackups(blueprint, {
      vaultLockEnabled: backupConfig.vaultLockEnabled,
      backupIntervalMinutes: backupConfig.backupIntervalMinutes,
      coldStorageAfterDays: backupConfig.coldStorageAfterDays,
      deleteAfterDays: backupConfig.deleteAfterDays,
      replicaRegion: backupConfig.replicaRegion,
    });
  }
}

export function validateCodeflyRegistryConfig(config: CodeflyRegistryConfig) {
  if (
    !Number.isInteger(config.retainImageCount) ||
    config.retainImageCount < 10 ||
    config.retainImageCount > 1000
  ) {
    throw new Error(
      "codeflyRegistry.retainImageCount must be between 10 and 1000.",
    );
  }
  if (
    !Number.isInteger(config.untaggedRetentionDays) ||
    config.untaggedRetentionDays < 1 ||
    config.untaggedRetentionDays > 90
  ) {
    throw new Error(
      "codeflyRegistry.untaggedRetentionDays must be between 1 and 90.",
    );
  }
  if (!config.enabled) {
    if (config.repositories.length > 0) {
      throw new Error(
        "codeflyRegistry.repositories must be empty when the registry is disabled.",
      );
    }
    return;
  }
  if (config.repositories.length === 0) {
    throw new Error(
      "enabled codeflyRegistry requires at least one repository.",
    );
  }
  if (new Set(config.repositories).size !== config.repositories.length) {
    throw new Error("codeflyRegistry.repositories must be unique.");
  }
  for (const repository of config.repositories) {
    if (
      repository.length > 128 ||
      !/^[a-z0-9]+(?:[._/-][a-z0-9]+)*$/.test(repository) ||
      repository.includes("..") ||
      repository.includes("//")
    ) {
      throw new Error(
        `codeflyRegistry repository '${repository}' is not a safe exact name.`,
      );
    }
  }
}

export function validateDnsConfig(config: DnsConfig) {
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?\.[a-z]{2,}$/i.test(config.rootDomain)) {
    throw new Error(
      `dns.rootDomain '${config.rootDomain}' is not a valid DNS apex.`,
    );
  }

  for (const env of config.environmentSubdomains) {
    if (!/^[a-z0-9-]+$/.test(env)) {
      throw new Error(
        `dns.environmentSubdomains entry '${env}' must be a DNS-safe slug.`,
      );
    }
  }

  const seen = new Set<string>();
  for (const env of config.environmentSubdomains) {
    if (seen.has(env)) {
      throw new Error(
        `dns.environmentSubdomains has duplicate entry '${env}'.`,
      );
    }
    seen.add(env);
  }
}

export function validateArgocdConfig(config: ArgocdConfig) {
  if (!config.clusterStackRef) {
    throw new Error(
      "argocd.clusterStackRef is required (Pulumi stack name for the cluster).",
    );
  }

  if (!config.clusterName) {
    throw new Error(
      "argocd.clusterName must match a key in the cluster stack's eksClusters output.",
    );
  }

  if (
    !/^arn:aws(?:-[a-z]+)?:iam::\d{12}:role\/[A-Za-z0-9+=,.@_/-]+$/.test(
      config.clusterAccessRoleArn,
    ) ||
    config.clusterAccessRoleArn.includes("*")
  ) {
    throw new Error(
      "argocd.clusterAccessRoleArn must be one exact IAM role ARN authorized by an EKS access entry.",
    );
  }

  if (
    !/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i.test(config.argocdHostname)
  ) {
    throw new Error(
      `argocd.argocdHostname '${config.argocdHostname}' is not a valid hostname.`,
    );
  }

  if (config.chartVersion !== ARGOCD_CHART_VERSION) {
    throw new Error(
      `argocd.chartVersion must equal the qualified release '${ARGOCD_CHART_VERSION}'.`,
    );
  }

  if (
    config.bootstrap.repository !==
    "https://github.com/codefly-dev/secure-saas-infra.git"
  ) {
    throw new Error(
      "argocd.bootstrap.repository must select the exact credential-free GitOps repository.",
    );
  }
  if (!/^[a-f0-9]{40}$/.test(config.bootstrap.revision)) {
    throw new Error(
      "argocd.bootstrap.revision must pin one full Git commit SHA.",
    );
  }
  if (!["platform", "execution"].includes(config.clusterRole)) {
    throw new Error(
      "argocd.clusterRole must be exactly 'platform' or 'execution'.",
    );
  }
  const bootstrapMatch =
    /^gitops\/bootstrap\/argocd\/overlays\/(dev|staging|production)\/(platform|execution)$/.exec(
      config.bootstrap.entrypoint,
    );
  const clusterEnvironment =
    bootstrapMatch?.[1] === "production" ? "prod" : bootstrapMatch?.[1];
  if (
    !bootstrapMatch ||
    bootstrapMatch[2] !== config.clusterRole ||
    config.clusterName !== `${config.clusterRole}-${clusterEnvironment}`
  ) {
    throw new Error(
      "argocd bootstrap handoff must bind one matching cluster role, cluster name, and environment/role entrypoint.",
    );
  }
  let issuer: URL;
  try {
    issuer = new URL(config.oidcIssuer);
  } catch {
    throw new Error("argocd.oidcIssuer must be an exact HTTPS URL.");
  }
  if (
    issuer.protocol !== "https:" ||
    issuer.username ||
    issuer.password ||
    issuer.search ||
    issuer.hash
  ) {
    throw new Error(
      "argocd.oidcIssuer must be a credential-free exact HTTPS URL.",
    );
  }
  if (
    !config.oidcClientId ||
    config.oidcClientId.length > 128 ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(config.oidcClientId)
  ) {
    throw new Error("argocd.oidcClientId must be an exact OIDC client ID.");
  }
  if (!/^\$[A-Za-z0-9][A-Za-z0-9._:-]*$/.test(config.oidcClientSecretRef)) {
    throw new Error(
      "argocd.oidcClientSecretRef must be an Argo secret-key reference, never a secret value.",
    );
  }
  if (
    !/^[A-Za-z0-9][A-Za-z0-9:_-]*$/.test(config.oidcAdminGroup) ||
    config.oidcAdminGroup.includes("*")
  ) {
    throw new Error("argocd.oidcAdminGroup must be one exact OIDC group.");
  }
}

export function argocdBootstrapHandoff(config: ArgocdConfig) {
  return {
    clusterRole: config.clusterRole,
    clusterName: config.clusterName,
    repository: config.bootstrap.repository,
    revision: config.bootstrap.revision,
    bootstrapEntrypoint: config.bootstrap.entrypoint,
  };
}

export function argocdBootstrapDirectory(config: ArgocdConfig) {
  const repository = config.bootstrap.repository.replace(/\.git$/, "");
  return `${repository}//${config.bootstrap.entrypoint}?ref=${config.bootstrap.revision}`;
}

export function validateConfigValues(
  mode: DeploymentMode,
  network: NetworkConfig,
  organization: OrganizationConfig,
  blueprintAuthoritative = false,
) {
  const validModes: DeploymentMode[] = [
    "organization",
    "workload",
    "all",
    "disabled",
  ];
  if (!validModes.includes(mode)) {
    throw new Error(
      `Invalid deploymentMode '${mode}'. Use one of: ${validModes.join(", ")}`,
    );
  }

  if (!blueprintAuthoritative) {
    if (network.egress.azCount < 2 || network.egress.azCount > 4) {
      throw new Error(
        "network.egress.azCount must be between 2 and 4 for this baseline.",
      );
    }

    const spokeNames = new Set<string>();
    for (const spoke of network.spokes) {
      if (spokeNames.has(spoke.name)) {
        throw new Error(`Duplicate network spoke name '${spoke.name}'.`);
      }
      spokeNames.add(spoke.name);
    }

    validateAndCompileAwsNetwork(network, {
      name: "configuration-network",
      environment: "validation",
      requireInspectedEgress: false,
    });
  }

  if (["organization", "all"].includes(mode)) {
    const ouNames = new Set<string>();
    for (const unit of organization.organizationalUnits) {
      if (ouNames.has(unit.name)) {
        throw new Error(`Duplicate organization OU name '${unit.name}'.`);
      }
      if (unit.parent && !ouNames.has(unit.parent)) {
        throw new Error(
          `Organization OU '${unit.name}' references unknown or later parent OU '${unit.parent}'.`,
        );
      }
      ouNames.add(unit.name);
    }

    const accountNames = new Set<string>();
    const accountEmails = new Set<string>();
    for (const account of organization.accounts) {
      if (accountNames.has(account.name)) {
        throw new Error(
          `Duplicate organization account name '${account.name}'.`,
        );
      }
      if (accountEmails.has(account.email.toLowerCase())) {
        throw new Error(
          `Duplicate organization account email '${account.email}'.`,
        );
      }
      accountNames.add(account.name);
      accountEmails.add(account.email.toLowerCase());
      if (!ouNames.has(account.ou)) {
        throw new Error(
          `Organization account '${account.name}' references unknown OU '${account.ou}'.`,
        );
      }
    }

    for (const environment of ["dev", "staging", "prod"] as const) {
      const platform = organization.accounts.find(
        (account) => account.name === `platform-${environment}`,
      );
      const execution = organization.accounts.find(
        (account) => account.name === `execution-${environment}`,
      );
      if (!platform && !execution) {
        continue;
      }
      if (!platform || !execution) {
        throw new Error(
          `Organization environment '${environment}' requires paired platform and execution accounts.`,
        );
      }
      if (platform.kind !== "workload" || execution.kind !== "execution") {
        throw new Error(
          `Organization environment '${environment}' has invalid platform or execution account kinds.`,
        );
      }
      if (platform.ou !== execution.ou) {
        throw new Error(
          `Organization environment '${environment}' platform and execution accounts must share an environment OU.`,
        );
      }
      if ((platform.create !== false) !== (execution.create !== false)) {
        throw new Error(
          `Organization environment '${environment}' platform and execution accounts must be enabled or disabled together.`,
        );
      }
    }

    if (organization.enableSecurityDelegatedAdmin) {
      const delegatedAdminAccountName =
        organization.securityDelegatedAdminAccountName ?? "security-tooling";
      if (
        !organization.accounts.some(
          (account) =>
            account.name === delegatedAdminAccountName &&
            account.create !== false,
        )
      ) {
        throw new Error(
          `security delegated admin account '${delegatedAdminAccountName}' is not defined.`,
        );
      }
    }

    for (const targetOu of organization.guardrailTargetOuNames) {
      if (!ouNames.has(targetOu)) {
        throw new Error(
          `guardrailTargetOuNames references unknown OU '${targetOu}'.`,
        );
      }
    }
  }
}

export function validateOperationalConfigValues(
  kind: StackKind,
  logArchive: LogArchiveConfig,
  sharedServices: SharedServicesConfig,
) {
  if (kind === "log-archive") {
    if (logArchive.objectLockRetentionDays < 365) {
      throw new Error(
        "logArchive.objectLockRetentionDays must be at least 365.",
      );
    }

    if (logArchive.transitionToGlacierDays < 30) {
      throw new Error(
        "logArchive.transitionToGlacierDays must be at least 30.",
      );
    }
  }

  if (kind === "shared-services") {
    if (sharedServices.vaultBackupRetentionDays < 30) {
      throw new Error(
        "sharedServices.vaultBackupRetentionDays must be at least 30.",
      );
    }

    if (
      !sharedServices.createVaultAutoUnsealKey &&
      sharedServices.createVaultBackupBucket
    ) {
      throw new Error(
        "sharedServices.createVaultBackupBucket requires createVaultAutoUnsealKey: true so the bucket can use customer-managed KMS.",
      );
    }

    if (
      !sharedServices.createVaultAutoUnsealKey &&
      sharedServices.createTailscaleBootstrapSecrets
    ) {
      throw new Error(
        "sharedServices.createTailscaleBootstrapSecrets requires createVaultAutoUnsealKey: true so the Secrets Manager secrets use customer-managed KMS.",
      );
    }
  }
}

const productionEnvironmentNames = new Set([
  "prod",
  "production",
  "prd",
  "platform-prod",
  "execution-prod",
  "staging",
  "stage",
  "platform-staging",
  "execution-staging",
]);

export function isProductionLikeEnvironment(value: string) {
  const normalized = value.toLowerCase();
  return (
    productionEnvironmentNames.has(normalized) ||
    /(^|[-_])(prod|production|prd|staging|stage)([-_]|$)/.test(normalized)
  );
}

export function deploymentStageForEnvironment(
  value: string,
): ManagedPostgresEnvironment | undefined {
  const tokens = value.toLowerCase().split(/[-_]/).filter(Boolean);
  const matches = new Set<ManagedPostgresEnvironment>();
  if (tokens.some((token) => ["prod", "production", "prd"].includes(token))) {
    matches.add("production");
  }
  if (
    tokens.some((token) =>
      ["staging", "stage", "stg", "preprod"].includes(token),
    )
  ) {
    matches.add("staging");
  }
  if (tokens.some((token) => ["dev", "development"].includes(token))) {
    matches.add("development");
  }
  return matches.size === 1 ? [...matches][0] : undefined;
}

export function validateProductionPostureValues(
  kind: StackKind,
  environment: string,
  network: NetworkConfig,
  eks: EksConfig,
  spoke: SpokeStackConfig,
) {
  const productionLike = isProductionLikeEnvironment(environment);

  if (
    productionLike &&
    (kind === "network-hub" || kind === "single-account") &&
    !network.egress.networkFirewallEnabled
  ) {
    throw new Error(
      `network.egress.networkFirewallEnabled must be true in production-like environments (got environment '${environment}').`,
    );
  }

  if (
    (kind === "platform" || kind === "execution") &&
    spoke.createEks &&
    !eks.endpointPublicAccess &&
    !hasClusterAdministrator(eks.accessGrants)
  ) {
    throw new Error(
      `${kind} stacks with private EKS endpoints must declare at least one secure-saas-infra:eks.accessGrants cluster-admin entry. Without it the cluster cannot be administered after deploy.`,
    );
  }

  if (
    kind === "single-account" &&
    eks &&
    !eks.endpointPublicAccess &&
    !hasClusterAdministrator(eks.accessGrants) &&
    network.spokes.some((entry) => entry.createEks)
  ) {
    throw new Error(
      "single-account stacks with private EKS endpoints must declare at least one secure-saas-infra:eks.accessGrants cluster-admin entry.",
    );
  }
}

function hasClusterAdministrator(grants: AwsEksAccessGrantConfig[]): boolean {
  return compileAwsEksAccessGrants(grants).some(
    (grant) =>
      grant.accessPolicy === "cluster-admin" && grant.scope.type === "cluster",
  );
}

export function stackKindFromDeploymentMode(mode: DeploymentMode): StackKind {
  switch (mode) {
    case "organization":
      return "management";
    case "workload":
    case "all":
      return "single-account";
    case "disabled":
      return "disabled";
    default:
      return "disabled";
  }
}

export function validateStackKindValues(
  kind: StackKind,
  spoke: SpokeStackConfig,
  routing: NetworkRoutingConfig,
  organizationAudit: OrganizationAuditConfig = {
    logArchiveStackRef: "",
    organizationTrailName: "deus-organization-trail",
    cloudTrailPrefix: "cloudtrail",
    s3DataEventBucketArns: [],
  },
  identityCenter: IdentityCenterConfig = identityCenterConfig,
  githubOidc: GithubOidcConfig = githubOidcConfig,
  githubGovernance: GithubGovernanceConfig = githubGovernanceConfig,
  executionSandbox: ExecutionSandboxConfig = executionSandboxConfig,
  e2bByocAccess: E2bByocAccessConfig = e2bByocAccessConfig,
  customerData: CustomerDataConfig = customerDataConfig,
  blueprint?: PlatformBlueprint,
) {
  const validKinds: StackKind[] = [
    "management",
    "account-access",
    "network-hub",
    "network-routing",
    "organization-audit",
    "identity",
    "github-oidc",
    "github-governance",
    "platform",
    "execution",
    "single-account",
    "security-tooling",
    "log-archive",
    "shared-services",
    "backup",
    "detection",
    "compliance",
    "cost-controls",
    "macie",
    "waf",
    "ingress",
    "dns",
    "argocd",
    "disabled",
  ];

  if (!validKinds.includes(kind)) {
    throw new Error(
      `Invalid stackKind '${kind}'. Use one of: ${validKinds.join(", ")}`,
    );
  }

  if (["platform", "execution"].includes(kind)) {
    if (!spoke.networkStackRef && !spoke.transitGatewayId) {
      throw new Error(
        `${kind} stacks require either spoke.networkStackRef or spoke.transitGatewayId.`,
      );
    }

    if (spoke.azCount < 2 || spoke.azCount > 4) {
      throw new Error(
        "spoke.azCount must be between 2 and 4 for this baseline.",
      );
    }

    if (kind === "platform" && spoke.kind !== "platform") {
      throw new Error("platform stacks must use spoke.kind: platform.");
    }

    if (kind === "execution" && spoke.kind !== "execution") {
      throw new Error("execution stacks must use spoke.kind: execution.");
    }

    if (kind === "execution") {
      if (!blueprint) {
        validateExecutionSandboxConfig(executionSandbox);
        validateCustomerDataConfig(customerData);
      }
      validateE2bByocAccessConfig(e2bByocAccess);
    }
  }

  if (kind === "network-routing") {
    if (!routing.networkStackRef) {
      throw new Error(
        "network-routing stacks require networkRouting.networkStackRef.",
      );
    }

    if (routing.spokeStackRefs.length === 0) {
      throw new Error(
        "network-routing stacks require at least one networkRouting.spokeStackRefs entry.",
      );
    }

    if (routing.azCount < 2 || routing.azCount > 4) {
      throw new Error(
        "networkRouting.azCount must be between 2 and 4 for this baseline.",
      );
    }
  }

  if (kind === "organization-audit") {
    if (!organizationAudit.logArchiveStackRef) {
      throw new Error(
        "organization-audit stacks require organizationAudit.logArchiveStackRef.",
      );
    }
  }

  if (kind === "identity") {
    const groupNames = new Set(
      identityCenter.groups.map((group) => group.name),
    );
    const permissionSetNames = new Set(
      identityCenter.permissionSets.map((permissionSet) => permissionSet.name),
    );

    for (const permissionSet of identityCenter.permissionSets) {
      if (
        permissionSet.managedPolicyArns.some((policyArn) =>
          isHighRiskAwsManagedPolicy(policyArn),
        )
      ) {
        throw new Error(
          `identity permission set '${permissionSet.name}' must not attach AdministratorAccess, PowerUserAccess, or IAMFullAccess; use a separately approved deploy role.`,
        );
      }
    }

    for (const assignment of identityCenter.assignments) {
      if (!groupNames.has(assignment.groupName)) {
        throw new Error(
          `identity assignment references unknown group '${assignment.groupName}'.`,
        );
      }

      if (!permissionSetNames.has(assignment.permissionSetName)) {
        throw new Error(
          `identity assignment references unknown permission set '${assignment.permissionSetName}'.`,
        );
      }
    }
  }

  if (kind === "github-oidc") {
    if (!githubOidc.enabled) {
      throw new Error("github-oidc stacks require githubOidc.enabled: true.");
    }

    if (githubOidc.repositories.length === 0) {
      throw new Error(
        "github-oidc stacks require at least one githubOidc.repositories entry.",
      );
    }

    const repositoryNames = new Set<string>();
    for (const repository of githubOidc.repositories) {
      if (!repository.owner || !repository.repo) {
        throw new Error("githubOidc repositories require owner and repo.");
      }

      const repositoryName =
        repository.name ?? `${repository.owner}/${repository.repo}`;
      if (repositoryNames.has(repositoryName)) {
        throw new Error(
          `githubOidc repository role '${repositoryName}' is duplicated.`,
        );
      }
      repositoryNames.add(repositoryName);

      if (
        repository.allowedRefs.length +
          repository.allowedEnvironments.length ===
        0
      ) {
        throw new Error(
          `githubOidc repository '${repository.owner}/${repository.repo}' requires an allowed ref or environment.`,
        );
      }

      const maxSessionDuration = repository.maxSessionDurationSeconds ?? 3600;
      if (maxSessionDuration < 900 || maxSessionDuration > 43200) {
        throw new Error(
          `githubOidc repository '${repository.owner}/${repository.repo}' has an invalid session duration.`,
        );
      }
    }
  }

  if (kind === "github-governance") {
    validateGithubGovernanceConfig(githubGovernance);
  }
}

export function validateExecutionSandboxConfig(config: ExecutionSandboxConfig) {
  const validProviders: ExecutionSandboxProvider[] = [
    "e2b-byoc",
    "e2b-self-hosted",
    "microvm-runtimeclass",
    "disabled",
  ];

  if (!validProviders.includes(config.provider)) {
    throw new Error(
      `Invalid executionSandbox.provider '${config.provider}'. Use one of: ${validProviders.join(", ")}`,
    );
  }

  if (config.provider === "disabled") {
    throw new Error(
      "execution stacks must not disable the execution sandbox provider.",
    );
  }

  const isolatedProviders: ExecutionSandboxProvider[] = [
    "e2b-byoc",
    "e2b-self-hosted",
    "microvm-runtimeclass",
  ];

  if (isolatedProviders.includes(config.provider)) {
    if (!config.dedicatedAccountRequired) {
      throw new Error(
        `${config.provider} execution sandboxes require a dedicated execution account boundary.`,
      );
    }

    if (!config.privateLoadBalancerRequired) {
      throw new Error(
        `${config.provider} execution sandboxes require private load balancers or private connectivity.`,
      );
    }

    if (!config.centralizedEgressRequired) {
      throw new Error(
        `${config.provider} execution sandboxes require centralized inspected egress.`,
      );
    }
  }

  if (
    config.maxSandboxDurationMinutes < 1 ||
    config.maxSandboxDurationMinutes > 1440
  ) {
    throw new Error(
      "executionSandbox.maxSandboxDurationMinutes must be between 1 and 1440.",
    );
  }

  if (!config.requirePerJobAuditMetadata) {
    throw new Error("execution sandboxes must require per-job audit metadata.");
  }

  if (!config.requireBrokeredCredentials) {
    throw new Error(
      "execution sandboxes must use brokered, scoped credentials.",
    );
  }
}

export function validateE2bByocAccessConfig(config: E2bByocAccessConfig) {
  if (!config.createVendorRole) return;

  if (config.vendorPrincipalArns.length === 0) {
    throw new Error(
      "e2bByocAccess vendor role creation requires vendorPrincipalArns.",
    );
  }

  for (const principalArn of config.vendorPrincipalArns) {
    if (!/^arn:[^:]+:iam::[0-9]{12}:role\/.+/.test(principalArn)) {
      throw new Error("e2bByocAccess vendor principals must be IAM role ARNs.");
    }
  }

  if (!config.externalId || config.externalId.length < 16) {
    throw new Error("e2bByocAccess externalId must be at least 16 characters.");
  }

  const maxSessionDuration = config.maxSessionDurationSeconds ?? 3600;
  if (maxSessionDuration < 900 || maxSessionDuration > 3600) {
    throw new Error(
      "e2bByocAccess maxSessionDurationSeconds must be between 900 and 3600.",
    );
  }

  if (
    config.managedPolicyArns.some((policyArn) =>
      isHighRiskAwsManagedPolicy(policyArn),
    )
  ) {
    throw new Error(
      "e2bByocAccess must not attach AWS administrator managed policies.",
    );
  }
}

function isHighRiskAwsManagedPolicy(policyArn: string) {
  return /^arn:[^:]+:iam::aws:policy\/(AdministratorAccess|PowerUserAccess|IAMFullAccess)$/.test(
    policyArn,
  );
}

export function validateGithubGovernanceConfig(config: GithubGovernanceConfig) {
  if (!config.enabled) {
    throw new Error(
      "github-governance stacks require githubGovernance.enabled: true.",
    );
  }

  if (hasPlaceholder(config.owner) || hasPlaceholder(config.repository)) {
    throw new Error(
      "githubGovernance owner and repository must be real GitHub values.",
    );
  }

  if (config.defaultBranch !== "main") {
    throw new Error(
      "githubGovernance.defaultBranch must be main for this baseline.",
    );
  }

  if (!config.requiredStatusChecks.includes("npm test")) {
    throw new Error(
      "githubGovernance.requiredStatusChecks must include npm test.",
    );
  }

  if (
    !config.protectedEnvironments.some(
      (environment) => environment.name === "production",
    )
  ) {
    throw new Error(
      "githubGovernance.protectedEnvironments must include production.",
    );
  }

  if (!config.requireShaPinnedActions) {
    throw new Error("githubGovernance must require SHA-pinned Actions.");
  }

  if (!config.requireCodeOwnerReview) {
    throw new Error("githubGovernance must require CODEOWNERS review.");
  }

  if (!config.requireSignedCommits) {
    throw new Error("githubGovernance must require signed commits.");
  }

  if (config.requiredApprovingReviewCount < 1) {
    throw new Error("githubGovernance requires at least one approving review.");
  }

  if (config.requireCodeScanning && !config.codeScanningTool) {
    throw new Error(
      "githubGovernance.codeScanningTool is required when code scanning is required.",
    );
  }

  if (config.manageOrganizationSettings && !config.organizationBillingEmail) {
    throw new Error(
      "githubGovernance.organizationBillingEmail is required when managing organization settings.",
    );
  }
}

function hasPlaceholder(value: string) {
  return (
    value.trim().length === 0 ||
    value.includes("your-") ||
    value.includes("example.com") ||
    value.includes("123456789012")
  );
}

export function validateBackupConfig(config: BackupConfig) {
  if (!config.vaultLockEnabled) {
    throw new Error(
      "backup.vaultLockEnabled must be true so backup vaults are immutable.",
    );
  }

  if (config.vaultLockMinRetentionDays < 35) {
    throw new Error(
      "backup.vaultLockMinRetentionDays must be at least 35 to satisfy the recovery RPO baseline.",
    );
  }

  if (config.vaultLockMaxRetentionDays < config.vaultLockMinRetentionDays) {
    throw new Error(
      "backup.vaultLockMaxRetentionDays must be greater than or equal to vaultLockMinRetentionDays.",
    );
  }

  if (config.vaultLockChangeableForDays < 3) {
    throw new Error(
      "backup.vaultLockChangeableForDays must be at least 3 so that operators retain a cooling-off period.",
    );
  }

  if (config.createPlan) {
    if (config.backupIntervalMinutes < 1) {
      throw new Error("backup.backupIntervalMinutes must be positive.");
    }
    if (config.restoreTestIntervalDays < 1) {
      throw new Error(
        "backup.restoreTestIntervalDays must be positive; backups without tested restores are prohibited.",
      );
    }
    if (config.deleteAfterDays < config.vaultLockMinRetentionDays) {
      throw new Error(
        "backup plan deleteAfterDays must be greater than or equal to vault lock min retention.",
      );
    }

    if (config.coldStorageAfterDays < 30) {
      throw new Error(
        "backup plan coldStorageAfterDays must be at least 30 to amortise restore cost.",
      );
    }
  }
}

export function validateDatabaseConfig(config: DatabaseConfig) {
  const validEngines: DatabaseEngine[] = ["aurora-postgresql", "aurora-mysql"];
  if (!validEngines.includes(config.engine)) {
    throw new Error(
      `database.engine must be one of: ${validEngines.join(", ")}.`,
    );
  }

  if (!config.deletionProtection) {
    throw new Error(
      "database.deletionProtection must be true; production databases cannot be casually deleted.",
    );
  }

  if (config.backupRetentionDays < 14) {
    throw new Error(
      "database.backupRetentionDays must be at least 14 to satisfy the platform RPO baseline.",
    );
  }

  if (config.instanceCount < 2) {
    throw new Error(
      "database.instanceCount must be at least 2 for HA across AZs.",
    );
  }

  if (config.port <= 0 || config.port > 65535) {
    throw new Error("database.port must be a valid TCP port.");
  }
}

export function validateWafConfig(config: WafConfig) {
  if (config.rateLimitPer5Minutes <= 0) {
    throw new Error("waf.rateLimitPer5Minutes must be a positive integer.");
  }

  if (
    config.modelGatewayPathPrefixes.length > 0 &&
    config.modelGatewayRateLimitPer5Minutes <= 0
  ) {
    throw new Error(
      "waf.modelGatewayRateLimitPer5Minutes must be a positive integer when modelGatewayPathPrefixes is set.",
    );
  }

  if (!["REGIONAL", "CLOUDFRONT"].includes(config.scope)) {
    throw new Error("waf.scope must be REGIONAL or CLOUDFRONT.");
  }
}

export function validateIngressConfig(config: IngressConfig) {
  if (!config.domainName) {
    throw new Error(
      "ingress.domainName is required and must be the public hostname.",
    );
  }

  if (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$/i.test(config.domainName)) {
    throw new Error(
      `ingress.domainName '${config.domainName}' is not a valid DNS hostname.`,
    );
  }

  if (!config.internalNlbArn) {
    throw new Error(
      "ingress.internalNlbArn is required. Wire this from the observed EKS Auto Mode Istio gateway Service handoff.",
    );
  }

  if (
    !/^arn:[^:]+:elasticloadbalancing:[a-z0-9-]+:[0-9]{12}:loadbalancer\/net\/[^/]+\/[a-f0-9]+$/.test(
      config.internalNlbArn,
    )
  ) {
    throw new Error(
      "ingress.internalNlbArn must be a Network Load Balancer ARN (no ALB origins).",
    );
  }

  const validTls = [
    "TLSv1.2_2018",
    "TLSv1.2_2019",
    "TLSv1.2_2021",
    "TLSv1.3_2021",
  ];
  if (!validTls.includes(config.minimumTlsVersion)) {
    throw new Error(
      `ingress.minimumTlsVersion must be one of: ${validTls.join(", ")}.`,
    );
  }

  if (
    config.minimumTlsVersion !== "TLSv1.3_2021" &&
    config.minimumTlsVersion !== "TLSv1.2_2021"
  ) {
    throw new Error(
      "ingress.minimumTlsVersion must be TLSv1.2_2021 or stronger. Older 2018/2019 viewer policies allow weak ciphers.",
    );
  }

  if (
    config.geoRestrictionType !== "none" &&
    config.geoRestrictionLocations.length === 0
  ) {
    throw new Error(
      "ingress.geoRestrictionLocations must be non-empty when geoRestrictionType is whitelist or blacklist.",
    );
  }

  if (config.logRetentionDays < 365) {
    throw new Error(
      "ingress.logRetentionDays must be at least 365 to align with the security log retention baseline.",
    );
  }

  if (!config.contentSecurityPolicy) {
    throw new Error(
      "ingress.contentSecurityPolicy must be set; default-src 'none' is the secure starting point.",
    );
  }
}

export function validateAgenticAiConfig(config: AgenticAiConfig) {
  if (config.brokerEgressNamespaces.length === 0) {
    throw new Error(
      "agenticAi.brokerEgressNamespaces must list the namespaces that route model traffic.",
    );
  }

  if (!config.requirePromptAuditLog || !config.requireToolCallAuditLog) {
    throw new Error(
      "agenticAi.requirePromptAuditLog and requireToolCallAuditLog must be true. Per-tenant agent replay is not optional.",
    );
  }

  if (!config.requireOutputFiltering) {
    throw new Error(
      "agenticAi.requireOutputFiltering must be true so completions are scanned for tenant data and secret leaks.",
    );
  }

  if (config.perTenantTokenBudget <= 0) {
    throw new Error(
      "agenticAi.perTenantTokenBudget must be a positive integer.",
    );
  }

  if (
    config.perTenantInferenceTimeoutSeconds < 1 ||
    config.perTenantInferenceTimeoutSeconds > 600
  ) {
    throw new Error(
      "agenticAi.perTenantInferenceTimeoutSeconds must be between 1 and 600.",
    );
  }
}

export function validateCustomerDataConfig(config: CustomerDataConfig) {
  if (!config.createArtifactStore) {
    throw new Error(
      "execution stacks must create the customer artifact store.",
    );
  }

  if (config.artifactRetentionDays < 1 || config.artifactRetentionDays > 2555) {
    throw new Error(
      "customerData.artifactRetentionDays must be between 1 and 2555.",
    );
  }

  if (
    config.noncurrentVersionExpirationDays < 1 ||
    config.noncurrentVersionExpirationDays > config.artifactRetentionDays
  ) {
    throw new Error(
      "customerData.noncurrentVersionExpirationDays must be at least 1 and no greater than artifactRetentionDays.",
    );
  }

  if (!config.requireTenantScopedPrefixes) {
    throw new Error(
      "customer data must require tenant-scoped storage prefixes.",
    );
  }

  if (!config.requireDeletionManifests) {
    throw new Error(
      "customer data deletion must require tracked deletion manifests.",
    );
  }

  if (!config.requireExportManifests) {
    throw new Error(
      "customer data export must require tracked export manifests.",
    );
  }

  if (!config.enterpriseDedicatedKmsRequired) {
    throw new Error("enterprise tenant tiers must require dedicated KMS keys.");
  }
}
