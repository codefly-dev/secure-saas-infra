import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { OrganizationConfig, baseTags, named } from "./config";

export interface OrganizationFoundationResult {
  organizationArn: pulumi.Output<string>;
  rootId: pulumi.Output<string>;
  organizationalUnitIds: pulumi.Output<Record<string, string>>;
  accountIds: pulumi.Output<Record<string, string>>;
}

export function createOrganizationFoundation(config: OrganizationConfig): OrganizationFoundationResult {
  const organization = config.createOrganization
    ? new aws.organizations.Organization(named("organization"), {
        featureSet: "ALL",
        awsServiceAccessPrincipals: config.serviceAccessPrincipals,
        enabledPolicyTypes: config.enabledPolicyTypes,
      })
    : undefined;

  const existingOrganization = organization
    ? undefined
    : aws.organizations.getOrganizationOutput({
        returnOrganizationOnly: false,
      });

  const organizationArn = organization ? organization.arn : existingOrganization!.arn;
  const rootId = organization
    ? organization.roots.apply((roots) => roots[0].id)
    : existingOrganization!.roots.apply((roots) => roots[0].id);

  if (config.enableRamSharing) {
    new aws.ram.SharingWithOrganization(
      named("ram-sharing-with-organization"),
      {},
      organization ? { dependsOn: organization } : undefined,
    );
  }

  // Service-access enablement so org-scoped resources work without a
  // console click. Each entry is required for at least one downstream
  // stack: backup ⇢ AWS Backup org plan; access-analyzer ⇢ Identity
  // Access Analyzer org-wide findings; sso ⇢ IAM Identity Center
  // (Identity Center itself still has to be enabled once via the
  // console — there is no API for the initial flip — but trusted
  // access for SSO and AccessAnalyzer can be set here so dependent
  // stacks deploy cleanly).
  for (const servicePrincipal of [
    "backup.amazonaws.com",
    "access-analyzer.amazonaws.com",
    "sso.amazonaws.com",
    "fms.amazonaws.com",
    "ram.amazonaws.com",
    "member.org.stacksets.cloudformation.amazonaws.com",
  ]) {
    new aws.organizations.AwsServiceAccess(
      named(`service-access-${slug(servicePrincipal)}`),
      {
        servicePrincipal,
      },
      organization ? { dependsOn: organization } : undefined,
    );
  }

  const organizationalUnits: Record<string, aws.organizations.OrganizationalUnit> = {};
  for (const unit of config.organizationalUnits) {
    const parentId = unit.parent ? organizationalUnits[unit.parent]?.id : rootId;

    if (!parentId) {
      throw new Error(`OU '${unit.name}' references unknown parent OU '${unit.parent}'.`);
    }

    organizationalUnits[unit.name] = new aws.organizations.OrganizationalUnit(named(`ou-${slug(unit.name)}`), {
      name: unit.name,
      parentId,
      tags: tag(`ou-${slug(unit.name)}`),
    });
  }

  const accounts: Record<string, aws.organizations.Account> = {};
  for (const account of config.accounts) {
    if (account.create === false) {
      continue;
    }

    const parentOu = organizationalUnits[account.ou];
    if (!parentOu) {
      throw new Error(`Account '${account.name}' references unknown OU '${account.ou}'.`);
    }

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
          ...(account.tags ?? {}),
        },
      },
      {
        protect: true,
        ignoreChanges: ["roleName"],
      },
    );
  }

  if (config.guardrailScpsEnabled) {
    createGuardrailScps(config, organizationalUnits);
  }

  if (config.enableSecurityDelegatedAdmin) {
    createSecurityDelegatedAdmin(config, accounts);
  }

  return {
    organizationArn,
    rootId,
    organizationalUnitIds: pulumi.output(
      Object.fromEntries(Object.entries(organizationalUnits).map(([name, ou]) => [name, ou.id])),
    ),
    accountIds: pulumi.output(Object.fromEntries(Object.entries(accounts).map(([name, account]) => [name, account.id]))),
  };
}

function createSecurityDelegatedAdmin(config: OrganizationConfig, accounts: Record<string, aws.organizations.Account>) {
  const accountName = config.securityDelegatedAdminAccountName ?? "security-tooling";
  const account = accounts[accountName];

  if (!account) {
    throw new Error(`Security delegated admin account '${accountName}' was not created.`);
  }

  new aws.guardduty.OrganizationAdminAccount(named("guardduty-org-admin"), {
    adminAccountId: account.id,
  });

  new aws.securityhub.OrganizationAdminAccount(named("securityhub-org-admin"), {
    adminAccountId: account.id,
  });

  new aws.inspector2.DelegatedAdminAccount(named("inspector-org-admin"), {
    accountId: account.id,
  });

  for (const servicePrincipal of ["config.amazonaws.com", "config-multiaccountsetup.amazonaws.com"]) {
    new aws.organizations.DelegatedAdministrator(named(`delegated-admin-${slug(servicePrincipal)}`), {
      accountId: account.id,
      servicePrincipal,
    });
  }
}

function createGuardrailScps(
  config: OrganizationConfig,
  organizationalUnits: Record<string, aws.organizations.OrganizationalUnit>,
) {
  const denyLeaveOrganization = new aws.organizations.Policy(named("scp-deny-leave-organization"), {
    name: named("deny-leave-organization"),
    description: "Prevents member accounts from leaving the AWS Organization.",
    type: "SERVICE_CONTROL_POLICY",
    content: JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "DenyLeaveOrganization",
          Effect: "Deny",
          Action: ["organizations:LeaveOrganization"],
          Resource: "*",
        },
      ],
    }),
    tags: tag("scp-deny-leave-organization"),
  });

  const denyDisableSecurity = new aws.organizations.Policy(named("scp-deny-disable-security-services"), {
    name: named("deny-disable-security-services"),
    description: "Prevents disabling core audit and detection services in member accounts.",
    type: "SERVICE_CONTROL_POLICY",
    content: JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "DenyDisableAuditAndDetection",
          Effect: "Deny",
          Action: [
            "cloudtrail:DeleteTrail",
            "cloudtrail:StopLogging",
            "cloudtrail:UpdateTrail",
            "config:DeleteConfigRule",
            "config:DeleteConfigurationRecorder",
            "config:DeleteDeliveryChannel",
            "config:StopConfigurationRecorder",
            "guardduty:DeleteDetector",
            "guardduty:DisassociateFromMasterAccount",
            "guardduty:DisassociateMembers",
            "guardduty:StopMonitoringMembers",
            "securityhub:DisableSecurityHub",
            "securityhub:DisassociateFromAdministratorAccount",
            "securityhub:DisassociateMembers",
            "inspector2:Disable",
          ],
          Resource: "*",
        },
      ],
    }),
    tags: tag("scp-deny-disable-security-services"),
  });

  const denyPublicAccessBlockChanges = new aws.organizations.Policy(named("scp-deny-s3-public-access-block-changes"), {
    name: named("deny-s3-public-access-block-changes"),
    description: "Prevents disabling S3 account public access block controls in member accounts.",
    type: "SERVICE_CONTROL_POLICY",
    content: JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Sid: "DenyS3PublicAccessBlockRemoval",
          Effect: "Deny",
          Action: ["s3:DeleteAccountPublicAccessBlock", "s3:PutAccountPublicAccessBlock"],
          Resource: "*",
          Condition: {
            BoolIfExists: {
              "s3:BlockPublicAcls": "false",
              "s3:BlockPublicPolicy": "false",
              "s3:IgnorePublicAcls": "false",
              "s3:RestrictPublicBuckets": "false",
            },
          },
        },
      ],
    }),
    tags: tag("scp-deny-s3-public-access-block-changes"),
  });

  const denyIamUserCreation = new aws.organizations.Policy(
    named("scp-deny-iam-users-and-keys"),
    {
      name: named("deny-iam-users-and-keys"),
      description:
        "Prevents creation of IAM users and long-lived IAM access keys in member accounts.",
      type: "SERVICE_CONTROL_POLICY",
      content: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "DenyIamUserAndAccessKeyCreation",
            Effect: "Deny",
            Action: [
              "iam:CreateUser",
              "iam:CreateAccessKey",
              "iam:UpdateAccessKey",
              "iam:CreateLoginProfile",
              "iam:UpdateLoginProfile",
            ],
            Resource: "*",
          },
        ],
      }),
      tags: tag("scp-deny-iam-users-and-keys"),
    },
  );

  const denyKmsRotationDisable = new aws.organizations.Policy(
    named("scp-deny-disable-kms-rotation"),
    {
      name: named("deny-disable-kms-rotation"),
      description:
        "Prevents disabling KMS key rotation or scheduling deletion of customer-managed keys without review.",
      type: "SERVICE_CONTROL_POLICY",
      content: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "DenyKmsRotationDisable",
            Effect: "Deny",
            Action: ["kms:DisableKeyRotation", "kms:ScheduleKeyDeletion"],
            Resource: "*",
          },
        ],
      }),
      tags: tag("scp-deny-disable-kms-rotation"),
    },
  );

  const denyEbsDefaultEncryptionChanges = new aws.organizations.Policy(
    named("scp-deny-disable-ebs-default-encryption"),
    {
      name: named("deny-disable-ebs-default-encryption"),
      description:
        "Prevents disabling EBS default encryption in member accounts.",
      type: "SERVICE_CONTROL_POLICY",
      content: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "DenyEbsDefaultEncryptionDisable",
            Effect: "Deny",
            Action: ["ec2:DisableEbsEncryptionByDefault"],
            Resource: "*",
          },
        ],
      }),
      tags: tag("scp-deny-disable-ebs-default-encryption"),
    },
  );

  const denyCloudTrailMutations = new aws.organizations.Policy(
    named("scp-deny-cloudtrail-mutations"),
    {
      name: named("deny-cloudtrail-mutations"),
      description:
        "Prevents member accounts from mutating organization CloudTrail trails.",
      type: "SERVICE_CONTROL_POLICY",
      content: JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "DenyCloudTrailMutations",
            Effect: "Deny",
            Action: [
              "cloudtrail:DeleteTrail",
              "cloudtrail:StopLogging",
              "cloudtrail:UpdateTrail",
              "cloudtrail:PutEventSelectors",
              "cloudtrail:PutInsightSelectors",
            ],
            Resource: "*",
          },
        ],
      }),
      tags: tag("scp-deny-cloudtrail-mutations"),
    },
  );

  const policies = [
    { name: "deny-leave-organization", policy: denyLeaveOrganization },
    { name: "deny-disable-security-services", policy: denyDisableSecurity },
    {
      name: "deny-s3-public-access-block-changes",
      policy: denyPublicAccessBlockChanges,
    },
    { name: "deny-iam-users-and-keys", policy: denyIamUserCreation },
    { name: "deny-disable-kms-rotation", policy: denyKmsRotationDisable },
    {
      name: "deny-disable-ebs-default-encryption",
      policy: denyEbsDefaultEncryptionChanges,
    },
    { name: "deny-cloudtrail-mutations", policy: denyCloudTrailMutations },
  ];

  for (const ouName of config.guardrailTargetOuNames) {
    const ou = organizationalUnits[ouName];
    if (!ou) {
      throw new Error(`Guardrail SCP target OU '${ouName}' was not created.`);
    }

    policies.forEach(({ name, policy }) => {
      new aws.organizations.PolicyAttachment(named(`scp-${slug(name)}-${slug(ouName)}-attachment`), {
        policyId: policy.id,
        targetId: ou.id,
      });
    });
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
  return value.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
}
