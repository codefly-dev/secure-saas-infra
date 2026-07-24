import * as pulumi from "@pulumi/pulumi";

const seedModel = require("../scripts/management-seed-model.cjs") as {
  managementSeedOrganizationFailures: (
    config: unknown,
    options?: { accountEmailDomain?: string },
  ) => string[];
};

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

export type ManagementSeedWave = "organization-only" | "full";

const projectConfig = new pulumi.Config();

export const projectName = pulumi.getProject();
export const stackName = pulumi.getStack();
export const organizationName = projectConfig.get("organizationName") ?? "deus";
export const environment = projectConfig.get("environment") ?? stackName;
export const deploymentMode = projectConfig.get("deploymentMode") ?? "workload";
export const stackKind = projectConfig.get("stackKind") ?? "disabled";
export const seedWave = (projectConfig.get("seedWave") ??
  "organization-only") as ManagementSeedWave;

export const organizationConfig =
  projectConfig.getObject<OrganizationConfig>("organization") ??
  ({
    createOrganization: false,
    defaultAccountRoleName: "DeusOrganizationBootstrap",
    enableRamSharing: true,
    enableSecurityDelegatedAdmin: false,
    serviceAccessPrincipals: [
      "cloudtrail.amazonaws.com",
      "config.amazonaws.com",
      "config-multiaccountsetup.amazonaws.com",
      "guardduty.amazonaws.com",
      "securityhub.amazonaws.com",
      "inspector2.amazonaws.com",
    ],
    enabledPolicyTypes: ["SERVICE_CONTROL_POLICY", "S3_POLICY"],
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

export function validateManagementSeedConfig(config = organizationConfig) {
  if (
    stackKind !== "management" ||
    deploymentMode !== "organization" ||
    environment !== "management"
  ) {
    throw new Error(
      "The management-seed program only admits stackKind=management, deploymentMode=organization, and environment=management.",
    );
  }
  if (seedWave !== "organization-only" && seedWave !== "full") {
    throw new Error(
      "The management-seed program only admits seedWave=organization-only or seedWave=full.",
    );
  }
  validateOrganizationTopology(config);
}

export function validateOrganizationTopology(config: OrganizationConfig) {
  const failures = seedModel.managementSeedOrganizationFailures(config);
  if (failures.length > 0) {
    throw new Error(`Management seed topology denied: ${failures.join("; ")}.`);
  }
}
