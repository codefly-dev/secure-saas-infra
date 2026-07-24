import type {
  PolicyResource,
  ResourceValidationPolicy,
  StackValidationPolicy,
} from "@pulumi/policy";

const seedModel = require("../scripts/management-seed-model.cjs") as {
  ACCOUNT_BASELINE: ReadonlyArray<{
    name: string;
    ou: string;
    kind: string;
    modular?: boolean;
  }>;
  ORGANIZATIONAL_UNITS: ReadonlyArray<{ name: string; parent?: string }>;
  SERVICE_ACCESS_PRINCIPALS: ReadonlyArray<string>;
};
const seedPolicyModel =
  require("../scripts/management-seed-policy-model.cjs") as {
    BASELINE_SCP_DOCUMENT: object;
    S3_PUBLIC_ACCESS_BLOCK_DOCUMENT: object;
    SUSPENDED_SCP_DOCUMENT: object;
  };

const admittedTypes = new Set([
  "aws:organizations/account:Account",
  "aws:organizations/awsServiceAccess:AwsServiceAccess",
  "aws:organizations/organization:Organization",
  "aws:organizations/organizationalUnit:OrganizationalUnit",
  "aws:organizations/policy:Policy",
  "aws:organizations/policyAttachment:PolicyAttachment",
  "aws:ram/sharingWithOrganization:SharingWithOrganization",
  "pulumi:providers:aws",
]);
const serviceAccessPrincipals = new Set([
  "cloudtrail.amazonaws.com",
  "config.amazonaws.com",
  "config-multiaccountsetup.amazonaws.com",
  "guardduty.amazonaws.com",
  "securityhub.amazonaws.com",
  "inspector2.amazonaws.com",
]);
const s3PublicAccessBlockPolicy = JSON.stringify({
  s3_attributes: {
    public_access_block_configuration: { "@@assign": "all" },
  },
});
const exactPolicyDocuments = new Map([
  [
    "scp-baseline-deny-guardrails",
    canonicalJson(seedPolicyModel.BASELINE_SCP_DOCUMENT),
  ],
  [
    "s3-policy-enforce-public-access-block",
    canonicalJson(seedPolicyModel.S3_PUBLIC_ACCESS_BLOCK_DOCUMENT),
  ],
  [
    "scp-suspended-deny-all",
    canonicalJson(seedPolicyModel.SUSPENDED_SCP_DOCUMENT),
  ],
]);

interface ExpectedSeedResource {
  type: string;
  props: Record<string, unknown>;
  allowedProps: string[];
  dependencies: string[];
  propertyDependencies: Record<string, string[]>;
}

export const managementSeedPolicies: Array<
  ResourceValidationPolicy | StackValidationPolicy
> = [
  {
    name: "management-seed-resource-type-allowlist",
    description:
      "The AWS Organizations seed can create only its reviewed organization, account, policy, trusted-access, and RAM resource types.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (!admittedTypes.has(args.type)) {
        reportViolation(
          `Resource type '${args.type}' is outside the management-seed allowlist.`,
        );
      }
    },
  },
  {
    name: "management-seed-resource-options",
    description:
      "Every seed resource is deletion-protected and only accounts ignore the immutable handoff role input.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (args.type === "pulumi:providers:aws") return;
      if (args.opts.protect !== true) {
        reportViolation(
          "Every management-seed resource must set protect=true.",
        );
      }
      const expectedIgnoreChanges =
        args.type === "aws:organizations/account:Account" ? ["roleName"] : [];
      if (
        canonicalJson([...(args.opts.ignoreChanges ?? [])].sort()) !==
        canonicalJson(expectedIgnoreChanges)
      ) {
        reportViolation(
          "Only management-seed accounts may ignore exactly roleName changes.",
        );
      }
    },
  } satisfies ResourceValidationPolicy,
  {
    name: "management-seed-organization-all-features",
    description:
      "A newly created AWS Organization must enable all features and only reviewed policy types.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:organizations/organization:Organization") return;
      if (args.props.featureSet !== "ALL") {
        reportViolation("AWS Organizations featureSet must equal ALL.");
      }
      const policyTypes = [...(args.props.enabledPolicyTypes ?? [])].sort();
      if (
        JSON.stringify(policyTypes) !== '["S3_POLICY","SERVICE_CONTROL_POLICY"]'
      ) {
        reportViolation(
          "The management seed must enable exactly SERVICE_CONTROL_POLICY and S3_POLICY.",
        );
      }
      if ((args.props.awsServiceAccessPrincipals ?? []).length !== 0) {
        reportViolation(
          "Organization aggregate service access must remain unset; standalone resources are the single owner.",
        );
      }
    },
  },
  {
    name: "management-seed-trusted-service-access",
    description:
      "Standalone trusted-access resources may enable only the exact reviewed non-RAM principals.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:organizations/awsServiceAccess:AwsServiceAccess") {
        return;
      }
      if (!serviceAccessPrincipals.has(String(args.props.servicePrincipal))) {
        reportViolation(
          "Organizations trusted access contains an unreviewed or RAM principal.",
        );
      }
    },
  },
  {
    name: "management-seed-account-rootless-handoff",
    description:
      "Created accounts must deny IAM-user billing access and use the reviewed transient handoff role without destructive deletion.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:organizations/account:Account") return;
      if (args.props.roleName !== "DeusOrganizationBootstrap") {
        reportViolation(
          "Organization accounts must use DeusOrganizationBootstrap.",
        );
      }
      if (args.props.iamUserAccessToBilling !== "DENY") {
        reportViolation(
          "Organization accounts must deny IAM-user billing access.",
        );
      }
      if (args.props.closeOnDeletion !== false) {
        reportViolation("Organization accounts must not close on deletion.");
      }
    },
  },
  {
    name: "management-seed-policy-document",
    description:
      "Seed policies must be deny-only SCPs or the one exact S3 Block Public Access policy.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:organizations/policy:Policy") return;
      if (
        args.props.type !== "SERVICE_CONTROL_POLICY" &&
        args.props.type !== "S3_POLICY"
      ) {
        reportViolation(
          "Organization policies must be SERVICE_CONTROL_POLICY or S3_POLICY.",
        );
      }
      let document: unknown;
      try {
        document =
          typeof args.props.content === "string"
            ? JSON.parse(args.props.content)
            : args.props.content;
      } catch {
        reportViolation("Organization policy content must be valid JSON.");
        return;
      }
      if (args.props.type === "S3_POLICY") {
        if (JSON.stringify(document) !== s3PublicAccessBlockPolicy) {
          reportViolation(
            "S3_POLICY must enforce all four Block Public Access settings.",
          );
        }
        return;
      }
      const identity = [...exactPolicyDocuments.keys()].find((suffix) =>
        args.name.endsWith(`-${suffix}`),
      );
      if (
        identity === undefined ||
        canonicalJson(document) !== exactPolicyDocuments.get(identity)
      ) {
        reportViolation(
          "Management-seed policies must match one exact canonical policy identity and document.",
        );
      }
    },
  },
  exactManagementSeedGraphPolicy(),
];

function exactManagementSeedGraphPolicy(): StackValidationPolicy {
  return {
    name: "management-seed-exact-resource-graph",
    description:
      "The seed stack must contain exactly the reviewed organization, OUs, active accounts, trusted services, policies, RAM owner, and attachment graph.",
    severity: "critical",
    validateStack: (args, reportViolation) => {
      const resources = args.resources.filter(
        (resource) => resource.type !== "pulumi:providers:aws",
      );
      const organization = resources.filter(
        (resource) =>
          resource.type === "aws:organizations/organization:Organization",
      );
      if (organization.length !== 1) {
        reportViolation(
          "The management seed must contain exactly one organization.",
        );
        return;
      }
      const prefix = stripSuffix(organization[0].name, "-organization");
      if (prefix === undefined) {
        reportViolation("The organization logical identity is not exact.");
        return;
      }
      const expectedNames =
        resources.length === 1
          ? [`${prefix}-organization`]
          : expectedResourceNames(prefix);
      const actualNames = resources.map((resource) => resource.name).sort();
      if (canonicalJson(actualNames) !== canonicalJson(expectedNames)) {
        reportViolation(
          "Management-seed resource identities or counts drifted.",
        );
      }

      const expectedGraph = expectedResourceGraph(prefix);
      for (const resource of resources) {
        const expected = expectedGraph.get(resource.name);
        if (!expected) continue;
        if (resource.type !== expected.type) {
          reportViolation(`Resource '${resource.name}' type drifted.`);
        }
        const unexpectedProps = Object.keys(resource.props)
          .filter((property) => !expected.allowedProps.includes(property))
          .sort();
        if (unexpectedProps.length > 0) {
          reportViolation(
            `Resource '${resource.name}' contains unreviewed input properties: ${unexpectedProps.join(", ")}.`,
          );
        }
        for (const [property, expectedValue] of Object.entries(
          expected.props,
        )) {
          if (
            property === "email" &&
            typeof expectedValue === "string" &&
            expectedValue.startsWith("__local-part-must-equal__:")
          ) {
            const expectedLocalPart = expectedValue.slice(
              "__local-part-must-equal__:".length,
            );
            if (
              !accountEmailMatches(resource.props[property], expectedLocalPart)
            ) {
              reportViolation(
                `Resource '${resource.name}' property '${property}' drifted.`,
              );
            }
            continue;
          }
          const actualValue =
            property === "content"
              ? canonicalPolicy(resource.props[property])
              : canonicalJson(resource.props[property]);
          const normalizedExpected =
            property === "content"
              ? canonicalPolicy(expectedValue)
              : canonicalJson(expectedValue);
          if (actualValue !== normalizedExpected) {
            reportViolation(
              `Resource '${resource.name}' property '${property}' drifted.`,
            );
          }
        }
        if (
          canonicalJson(resourceDependencyNames(resource)) !==
          canonicalJson(expected.dependencies)
        ) {
          reportViolation(`Resource '${resource.name}' dependencies drifted.`);
        }
        if (
          canonicalJson(resourcePropertyDependencyNames(resource)) !==
          canonicalJson(expected.propertyDependencies)
        ) {
          reportViolation(
            `Resource '${resource.name}' property dependencies drifted.`,
          );
        }
      }
    },
  };
}

function expectedResourceGraph(
  prefix: string,
): Map<string, ExpectedSeedResource> {
  const graph = new Map<string, ExpectedSeedResource>();
  const organization = `${prefix}-organization`;
  const add = (
    suffix: string,
    type: string,
    props: Record<string, unknown>,
    dependencies: string[] = [],
    propertyDependencies: Record<string, string[]> = {},
  ) => {
    graph.set(`${prefix}-${suffix}`, {
      type,
      props,
      allowedProps: [
        ...new Set([
          ...Object.keys(props),
          ...Object.keys(propertyDependencies),
        ]),
      ].sort(),
      dependencies: [...dependencies].sort(),
      propertyDependencies: normalizedDependencyMap(propertyDependencies),
    });
  };

  add("organization", "aws:organizations/organization:Organization", {
    featureSet: "ALL",
    enabledPolicyTypes: ["SERVICE_CONTROL_POLICY", "S3_POLICY"],
  });
  add(
    "ram-sharing-with-organization",
    "aws:ram/sharingWithOrganization:SharingWithOrganization",
    {},
    [organization],
  );
  for (const unit of seedModel.ORGANIZATIONAL_UNITS) {
    const suffix = `ou-${slug(unit.name)}`;
    const parent = unit.parent
      ? `${prefix}-ou-${slug(unit.parent)}`
      : organization;
    add(
      suffix,
      "aws:organizations/organizationalUnit:OrganizationalUnit",
      {
        name: unit.name,
        tags: seedTags(prefix, suffix),
      },
      [parent],
      { parentId: [parent] },
    );
  }

  const accounts = seedModel.ACCOUNT_BASELINE.filter(
    (account) => !account.modular,
  );
  for (const [index, account] of accounts.entries()) {
    const suffix = `account-${slug(account.name)}`;
    const parent = `${prefix}-ou-${slug(account.ou ?? "")}`;
    const lanePredecessor =
      index >= 3
        ? `${prefix}-account-${slug(accounts[index - 3].name)}`
        : undefined;
    add(
      suffix,
      "aws:organizations/account:Account",
      {
        name: account.name,
        email: expectedAccountEmail(account.name),
        roleName: "DeusOrganizationBootstrap",
        closeOnDeletion: false,
        iamUserAccessToBilling: "DENY",
        tags: seedTags(prefix, suffix, {
          AccountKind: account.kind ?? "",
          OrganizationalUnit: account.ou ?? "",
        }),
      },
      [parent, ...(lanePredecessor ? [lanePredecessor] : [])],
      { parentId: [parent] },
    );
  }

  for (const principal of seedModel.SERVICE_ACCESS_PRINCIPALS) {
    add(
      `service-access-${slug(principal)}`,
      "aws:organizations/awsServiceAccess:AwsServiceAccess",
      { servicePrincipal: principal },
      [organization],
    );
  }

  for (const [suffix, name, content] of [
    [
      "scp-baseline-deny-guardrails",
      "baseline-deny-guardrails",
      seedPolicyModel.BASELINE_SCP_DOCUMENT,
    ],
    [
      "s3-policy-enforce-public-access-block",
      "enforce-s3-public-access-block",
      seedPolicyModel.S3_PUBLIC_ACCESS_BLOCK_DOCUMENT,
    ],
    [
      "scp-suspended-deny-all",
      "suspended-deny-all",
      seedPolicyModel.SUSPENDED_SCP_DOCUMENT,
    ],
  ] as const) {
    const isS3 = suffix.startsWith("s3-policy-");
    add(
      suffix,
      "aws:organizations/policy:Policy",
      {
        name: `${prefix}-${name}`,
        description: policyDescription(suffix),
        type: isS3 ? "S3_POLICY" : "SERVICE_CONTROL_POLICY",
        content,
        tags: seedTags(prefix, suffix),
      },
      [organization],
    );
  }

  for (const [attachmentSuffix, policySuffix, targetSuffix] of [
    [
      "policy-baseline-deny-guardrails-security-attachment",
      "scp-baseline-deny-guardrails",
      "ou-security",
    ],
    [
      "policy-baseline-deny-guardrails-infrastructure-attachment",
      "scp-baseline-deny-guardrails",
      "ou-infrastructure",
    ],
    [
      "policy-baseline-deny-guardrails-workloads-attachment",
      "scp-baseline-deny-guardrails",
      "ou-workloads",
    ],
    [
      "policy-enforce-s3-public-access-block-root-attachment",
      "s3-policy-enforce-public-access-block",
      "organization",
    ],
    [
      "policy-suspended-deny-all-suspended-attachment",
      "scp-suspended-deny-all",
      "ou-suspended",
    ],
  ] as const) {
    const policy = `${prefix}-${policySuffix}`;
    const target = `${prefix}-${targetSuffix}`;
    add(
      attachmentSuffix,
      "aws:organizations/policyAttachment:PolicyAttachment",
      {},
      [policy, target],
      { policyId: [policy], targetId: [target] },
    );
  }
  return graph;
}

function seedTags(
  prefix: string,
  suffix: string,
  extra: Record<string, string> = {},
): Record<string, string> {
  const organization = stripSuffix(prefix, "-management") ?? "";
  return {
    Project: "secure-saas-infra",
    Stack: "management",
    Organization: organization,
    Environment: "management",
    ManagedBy: "pulumi",
    Name: `${prefix}-${suffix}`,
    ...extra,
  };
}

function expectedAccountEmail(name: string): string {
  return `__local-part-must-equal__:${name}`;
}

function accountEmailMatches(
  value: unknown,
  expectedLocalPart: string,
): boolean {
  if (typeof value !== "string") return false;
  const match = /^([^@]+)@([a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?)$/.exec(
    value.toLowerCase(),
  );
  return match?.[1] === expectedLocalPart;
}

function policyDescription(suffix: string): string {
  if (suffix === "scp-baseline-deny-guardrails") {
    return "Consolidated deny-only baseline for governed member-account OUs.";
  }
  if (suffix === "s3-policy-enforce-public-access-block") {
    return "Enforces all four S3 Block Public Access settings through the native Organizations policy type.";
  }
  return "Denies every member-account action in the Suspended OU.";
}

function resourceDependencyNames(resource: PolicyResource): string[] {
  return (resource.dependencies ?? []).map((entry) => entry.name).sort();
}

function resourcePropertyDependencyNames(
  resource: PolicyResource,
): Record<string, string[]> {
  return normalizedDependencyMap(
    Object.fromEntries(
      Object.entries(resource.propertyDependencies ?? {}).map(
        ([property, dependencies]) => [
          property,
          dependencies.map((entry) => entry.name),
        ],
      ),
    ),
  );
}

function normalizedDependencyMap(
  value: Record<string, string[]>,
): Record<string, string[]> {
  return Object.fromEntries(
    Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([property, dependencies]) => [property, [...dependencies].sort()]),
  );
}

function expectedResourceNames(prefix: string): string[] {
  return [
    `${prefix}-organization`,
    `${prefix}-ram-sharing-with-organization`,
    ...seedModel.ORGANIZATIONAL_UNITS.map(
      (unit) => `${prefix}-ou-${slug(unit.name)}`,
    ),
    ...seedModel.ACCOUNT_BASELINE.filter((account) => !account.modular).map(
      (account) => `${prefix}-account-${slug(account.name)}`,
    ),
    ...seedModel.SERVICE_ACCESS_PRINCIPALS.map(
      (principal) => `${prefix}-service-access-${slug(principal)}`,
    ),
    ...[...exactPolicyDocuments.keys()].map((suffix) => `${prefix}-${suffix}`),
    `${prefix}-policy-baseline-deny-guardrails-security-attachment`,
    `${prefix}-policy-baseline-deny-guardrails-infrastructure-attachment`,
    `${prefix}-policy-baseline-deny-guardrails-workloads-attachment`,
    `${prefix}-policy-enforce-s3-public-access-block-root-attachment`,
    `${prefix}-policy-suspended-deny-all-suspended-attachment`,
  ].sort();
}

function propertyDependsOn(
  resource: PolicyResource,
  property: string,
  dependencyName: string,
): boolean {
  return (resource.propertyDependencies?.[property] ?? []).some(
    (dependency) => dependency.name === dependencyName,
  );
}

function canonicalPolicy(value: unknown): string | undefined {
  try {
    return canonicalJson(typeof value === "string" ? JSON.parse(value) : value);
  } catch {
    return undefined;
  }
}

function stripSuffix(value: string, suffix: string): string | undefined {
  return value.endsWith(suffix) && value.length > suffix.length
    ? value.slice(0, -suffix.length)
    : undefined;
}

function slug(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}
