import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { OrganizationConfig, baseTags, named } from "./managementSeedConfig";

const {
  BASELINE_SCP_DOCUMENT,
  S3_PUBLIC_ACCESS_BLOCK_DOCUMENT,
  SUSPENDED_SCP_DOCUMENT,
} = require("../scripts/management-seed-policy-model.cjs") as {
  BASELINE_SCP_DOCUMENT: object;
  S3_PUBLIC_ACCESS_BLOCK_DOCUMENT: object;
  SUSPENDED_SCP_DOCUMENT: object;
};

export interface OrganizationFoundationResult {
  organizationArn: pulumi.Output<string>;
  rootId: pulumi.Output<string>;
  organizationalUnitIds: pulumi.Output<Record<string, string>>;
  accountIds: pulumi.Output<Record<string, string>>;
}

export function createOrganizationFoundation(
  config: OrganizationConfig,
  seedWave: "organization-only" | "full" = "full",
): OrganizationFoundationResult {
  if (config.createOrganization !== true) {
    throw new Error(
      "The exact management seed supports only a new organization.",
    );
  }
  const organization = new aws.organizations.Organization(
    named("organization"),
    {
      featureSet: "ALL",
      enabledPolicyTypes: config.enabledPolicyTypes,
    },
    { protect: true },
  );

  const organizationArn = organization.arn;
  const rootId = organization.roots.apply((roots) => roots[0].id);

  if (seedWave === "organization-only") {
    return {
      organizationArn,
      rootId,
      organizationalUnitIds: pulumi.output<Record<string, string>>({}),
      accountIds: pulumi.output<Record<string, string>>({}),
    };
  }

  if (config.enableRamSharing) {
    new aws.ram.SharingWithOrganization(
      named("ram-sharing-with-organization"),
      {},
      { dependsOn: organization, protect: true },
    );
  }

  // Keep one Pulumi owner for Organizations trusted access. The aggregate
  // Organization property is intentionally absent because the provider marks
  // it exclusive with these standalone resources. RAM is separately and
  // exclusively owned by SharingWithOrganization above.
  for (const servicePrincipal of config.serviceAccessPrincipals) {
    new aws.organizations.AwsServiceAccess(
      named(`service-access-${slug(servicePrincipal)}`),
      {
        servicePrincipal,
      },
      { dependsOn: organization, protect: true },
    );
  }

  const organizationalUnits: Record<
    string,
    aws.organizations.OrganizationalUnit
  > = {};
  for (const unit of config.organizationalUnits) {
    const parentId = unit.parent
      ? organizationalUnits[unit.parent]?.id
      : rootId;

    if (!parentId) {
      throw new Error(
        `OU '${unit.name}' references unknown parent OU '${unit.parent}'.`,
      );
    }

    organizationalUnits[unit.name] = new aws.organizations.OrganizationalUnit(
      named(`ou-${slug(unit.name)}`),
      {
        name: unit.name,
        parentId,
        tags: tag(`ou-${slug(unit.name)}`),
      },
      { protect: true },
    );
  }

  const accounts: Record<string, aws.organizations.Account> = {};
  const accountCreationLanes: aws.organizations.Account[] = [];
  for (const account of config.accounts) {
    if (account.create === false) {
      continue;
    }

    const parentOu = organizationalUnits[account.ou];
    if (!parentOu) {
      throw new Error(
        `Account '${account.name}' references unknown OU '${account.ou}'.`,
      );
    }

    const lanePredecessor =
      boundedAccountCreationPredecessor(accountCreationLanes);
    accounts[account.name] = new aws.organizations.Account(
      named(`account-${slug(account.name)}`),
      {
        name: account.name,
        email: account.email,
        parentId: parentOu.id,
        roleName: account.roleName ?? config.defaultAccountRoleName,
        closeOnDeletion: account.closeOnDeletion ?? false,
        iamUserAccessToBilling: "DENY",
        tags: {
          ...tag(`account-${slug(account.name)}`, {
            AccountKind: account.kind,
            OrganizationalUnit: account.ou,
          }),
        },
      },
      {
        protect: true,
        ignoreChanges: ["roleName"],
        dependsOn: lanePredecessor ? [lanePredecessor] : undefined,
      },
    );
    accountCreationLanes.push(accounts[account.name]);
  }

  if (config.guardrailScpsEnabled) {
    createGuardrailScps(config, organizationalUnits, rootId, organization);
  }

  return {
    organizationArn,
    rootId,
    organizationalUnitIds: pulumi.output(
      Object.fromEntries(
        Object.entries(organizationalUnits).map(([name, ou]) => [name, ou.id]),
      ),
    ),
    accountIds: pulumi.output(
      Object.fromEntries(
        Object.entries(accounts).map(([name, account]) => [name, account.id]),
      ),
    ),
  };
}

export function boundedAccountCreationPredecessor<T>(
  created: readonly T[],
): T | undefined {
  return created.length >= 3 ? created[created.length - 3] : undefined;
}

function createGuardrailScps(
  config: OrganizationConfig,
  organizationalUnits: Record<string, aws.organizations.OrganizationalUnit>,
  rootId: pulumi.Output<string>,
  organization: aws.organizations.Organization,
) {
  const baselineDenyGuardrails = new aws.organizations.Policy(
    named("scp-baseline-deny-guardrails"),
    {
      name: named("baseline-deny-guardrails"),
      description:
        "Consolidated deny-only baseline for governed member-account OUs.",
      type: "SERVICE_CONTROL_POLICY",
      content: JSON.stringify(BASELINE_SCP_DOCUMENT),
      tags: tag("scp-baseline-deny-guardrails"),
    },
    { dependsOn: organization, protect: true },
  );

  const enforceS3PublicAccessBlock = new aws.organizations.Policy(
    named("s3-policy-enforce-public-access-block"),
    {
      name: named("enforce-s3-public-access-block"),
      description:
        "Enforces all four S3 Block Public Access settings through the native Organizations policy type.",
      type: "S3_POLICY",
      content: JSON.stringify(S3_PUBLIC_ACCESS_BLOCK_DOCUMENT),
      tags: tag("s3-policy-enforce-public-access-block"),
    },
    { dependsOn: organization, protect: true },
  );

  const suspendedDenyAll = new aws.organizations.Policy(
    named("scp-suspended-deny-all"),
    {
      name: named("suspended-deny-all"),
      description: "Denies every member-account action in the Suspended OU.",
      type: "SERVICE_CONTROL_POLICY",
      content: JSON.stringify(SUSPENDED_SCP_DOCUMENT),
      tags: tag("scp-suspended-deny-all"),
    },
    { dependsOn: organization, protect: true },
  );

  const plannedAttachments: OrganizationPolicyAttachmentPlan[] = [];

  for (const ouName of config.guardrailTargetOuNames) {
    const ou = organizationalUnits[ouName];
    if (!ou) {
      throw new Error(`Guardrail SCP target OU '${ouName}' was not created.`);
    }

    plannedAttachments.push({
      target: ouName,
      policyType: "SERVICE_CONTROL_POLICY",
    });
  }

  plannedAttachments.push({ target: "Root", policyType: "S3_POLICY" });

  const suspendedOu = organizationalUnits.Suspended;
  if (!suspendedOu) {
    throw new Error(
      "Suspended OU must exist when seed guardrails are enabled.",
    );
  }
  plannedAttachments.push({
    target: "Suspended",
    policyType: "SERVICE_CONTROL_POLICY",
  });
  assertOrganizationPolicyAttachmentQuotas(plannedAttachments);

  for (const ouName of config.guardrailTargetOuNames) {
    const ou = organizationalUnits[ouName];
    new aws.organizations.PolicyAttachment(
      named(`policy-baseline-deny-guardrails-${slug(ouName)}-attachment`),
      { policyId: baselineDenyGuardrails.id, targetId: ou.id },
      { protect: true },
    );
  }

  new aws.organizations.PolicyAttachment(
    named("policy-enforce-s3-public-access-block-root-attachment"),
    { policyId: enforceS3PublicAccessBlock.id, targetId: rootId },
    { protect: true },
  );

  new aws.organizations.PolicyAttachment(
    named("policy-suspended-deny-all-suspended-attachment"),
    { policyId: suspendedDenyAll.id, targetId: suspendedOu.id },
    { protect: true },
  );
}

type OrganizationPolicyType = "SERVICE_CONTROL_POLICY" | "S3_POLICY";

export interface OrganizationPolicyAttachmentPlan {
  target: string;
  policyType: OrganizationPolicyType;
}

const organizationPolicyAttachmentCaps: Record<OrganizationPolicyType, number> =
  {
    SERVICE_CONTROL_POLICY: 5,
    S3_POLICY: 10,
  };

export function assertOrganizationPolicyAttachmentQuotas(
  attachments: readonly OrganizationPolicyAttachmentPlan[],
): void {
  const counts = new Map<string, number>();
  for (const attachment of attachments) {
    const key = `${attachment.target}\u0000${attachment.policyType}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  for (const [key, customCount] of counts) {
    const [target, policyType] = key.split("\u0000") as [
      string,
      OrganizationPolicyType,
    ];
    // SCPs automatically receive an AWS-managed full-access policy. Reserve
    // that slot and use the lower published AWS limit while its documentation
    // is inconsistent across Organizations pages.
    const awsManagedReserve = policyType === "SERVICE_CONTROL_POLICY" ? 1 : 0;
    if (
      customCount + awsManagedReserve >
      organizationPolicyAttachmentCaps[policyType]
    ) {
      throw new Error(
        `${policyType} attachments for '${target}' exceed the conservative Organizations quota.`,
      );
    }
  }
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}

function slug(value: string) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}
