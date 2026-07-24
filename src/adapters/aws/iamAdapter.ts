import type {
  Identity,
  IdentityGrant,
  PlatformBlueprint,
  PlatformCapability,
} from "../../core";
import { CloudAdapter, compileBlueprint } from "../../core";
import {
  AwsPolicyDocument,
  AwsPolicyStatement,
  AwsPolicyValue,
  canonicalPolicyJson,
  policyDocument,
} from "./policyDocuments";

export interface AwsDataResourceBinding {
  kind: "data";
  bucketArn: string;
  keyArnByTenant: Readonly<Record<string, string>>;
  prefixByTenant: Readonly<Record<string, string>>;
}

export interface AwsGenericResourceBinding {
  kind: "generic";
  resourceArns: readonly string[];
  actionMap: Readonly<Record<string, readonly string[]>>;
}

export type AwsResourceBinding =
  | AwsDataResourceBinding
  | AwsGenericResourceBinding;

export interface AwsIdentityBinding {
  roleArn: string;
  principalArn?: string;
  externalId?: string;
  sourceAccount?: string;
  sourceArn?: string;
  maxSessionDurationSeconds?: number;
  oidcProviderArn?: string;
  oidcIssuerHost?: string;
  oidcSubject?: string;
  audience?: string;
  sourceIdentityPattern?: string;
  podIdentity?: {
    namespace: string;
    serviceAccount: string;
  };
}

export interface AwsIamProviderExtensions {
  accountId: string;
  organizationId: string;
  partition?: string;
  identities: Readonly<Record<string, AwsIdentityBinding>>;
  resources: Readonly<Record<string, AwsResourceBinding>>;
}

export interface AwsNamedPolicy {
  semanticId: string;
  document: AwsPolicyDocument;
  canonicalJson: string;
}

export interface AwsIdentityPolicyPlan extends AwsNamedPolicy {
  identityId: string;
  roleArn: string;
  resourceIds: readonly string[];
}

export interface AwsTrustPolicyPlan extends AwsNamedPolicy {
  identityId: string;
  maxSessionDurationSeconds: number;
}

export interface AwsWorkloadIdentityAssociation {
  mode: "eks-pod-identity";
  identityId: string;
  roleArn: string;
  namespace: string;
  serviceAccount: string;
  sessionTagsEnabled: true;
}

export interface AwsIamPlan {
  cloud: "aws";
  identityPolicies: readonly AwsIdentityPolicyPlan[];
  trustPolicies: readonly AwsTrustPolicyPlan[];
  s3ResourcePolicies: readonly AwsNamedPolicy[];
  kmsKeyPolicies: readonly AwsNamedPolicy[];
  workloadIdentityAssociations: readonly AwsWorkloadIdentityAssociation[];
}

const capabilities = new Set<PlatformCapability>([
  "private-network",
  "centralized-egress",
  "managed-firewall",
  "private-control-plane",
  "workload-identity",
  "customer-managed-encryption",
  "immutable-audit-log",
  "dedicated-account-boundary",
  "microvm-runtime",
  "external-sandbox",
]);

const privilegeEscalationActions = new Set([
  "iam:AttachRolePolicy",
  "iam:CreatePolicyVersion",
  "iam:PassRole",
  "iam:PutRolePolicy",
  "kms:PutKeyPolicy",
  "sts:AssumeRole",
]);

export class AwsIamAdapter implements CloudAdapter<AwsIamPlan> {
  readonly descriptor = {
    cloud: "aws" as const,
    name: "aws-iam",
    capabilities,
  };

  constructor(private readonly extensions: AwsIamProviderExtensions) {}

  compile(blueprint: PlatformBlueprint): AwsIamPlan {
    validateExtensions(blueprint, this.extensions);
    const identityPolicies = blueprint.identities
      .map((identity) =>
        compileIdentityPolicy(blueprint, identity, this.extensions),
      )
      .filter((plan): plan is AwsIdentityPolicyPlan => plan !== undefined)
      .sort(bySemanticId);
    const trustPolicies = blueprint.identities
      .map((identity) => compileTrustPolicy(identity, this.extensions))
      .filter((plan): plan is AwsTrustPolicyPlan => plan !== undefined)
      .sort(bySemanticId);
    const s3ResourcePolicies = compileS3ResourcePolicies(
      blueprint,
      this.extensions,
    );
    const kmsKeyPolicies = compileKmsKeyPolicies(blueprint, this.extensions);
    const workloadIdentityAssociations = blueprint.identities
      .filter((identity) => identity.kind === "workload")
      .map((identity) => workloadAssociation(identity, this.extensions))
      .sort((left, right) => left.identityId.localeCompare(right.identityId));
    return {
      cloud: "aws",
      identityPolicies,
      trustPolicies,
      s3ResourcePolicies,
      kmsKeyPolicies,
      workloadIdentityAssociations,
    };
  }
}

export function compileAwsIam(
  blueprint: PlatformBlueprint,
  extensions: AwsIamProviderExtensions,
): AwsIamPlan {
  return compileBlueprint(blueprint, new AwsIamAdapter(extensions));
}

function compileIdentityPolicy(
  blueprint: PlatformBlueprint,
  identity: Identity,
  extensions: AwsIamProviderExtensions,
): AwsIdentityPolicyPlan | undefined {
  const binding = requiredIdentityBinding(identity.id, extensions);
  const grants = blueprint.grants
    .filter((grant) => grant.identityId === identity.id)
    .sort((left, right) => left.id.localeCompare(right.id));
  if (grants.length === 0) return undefined;
  const statements = grants.flatMap((grant) =>
    grant.resourceIds.flatMap((resourceId) =>
      identityStatements(identity, grant, resourceId, extensions),
    ),
  );
  const document = policyDocument(statements);
  return namedPolicy(`aws:iam:identity:${identity.id}`, document, {
    identityId: identity.id,
    roleArn: binding.roleArn,
    resourceIds: [
      ...new Set(grants.flatMap((grant) => grant.resourceIds)),
    ].sort(),
  });
}

function identityStatements(
  identity: Identity,
  grant: IdentityGrant,
  resourceId: string,
  extensions: AwsIamProviderExtensions,
): AwsPolicyStatement[] {
  const resource = requiredResourceBinding(resourceId, extensions);
  if (resource.kind === "generic") {
    const actions = mappedActions(grant, resource.actionMap);
    validatePrivilegeScope(grant, actions, resource.resourceArns);
    return [
      {
        Sid: sid(grant.id, resourceId, "Resource"),
        Effect: effect(grant),
        Action: actions,
        Resource: sortedArns(resource.resourceArns, grant.id),
        Condition: grantConditions(identity, grant),
      },
    ];
  }
  const tenantId = requiredTenantId(identity, grant);
  const prefix = requiredTenantValue(
    resource.prefixByTenant,
    tenantId,
    `prefix for '${resourceId}'`,
  );
  const keyArn = requiredTenantValue(
    resource.keyArnByTenant,
    tenantId,
    `KMS key for '${resourceId}'`,
  );
  const read = grant.actions.includes("data:read");
  const write = grant.actions.includes("data:write");
  rejectUnknownDataActions(grant);
  const common = grantConditions(identity, grant);
  const statements: AwsPolicyStatement[] = [];
  if (read) {
    statements.push(
      {
        Sid: sid(grant.id, resourceId, "ListTenantPrefix"),
        Effect: effect(grant),
        Action: "s3:ListBucket",
        Resource: resource.bucketArn,
        Condition: mergeConditions(common, {
          StringLike: { "s3:prefix": [`${prefix}*`] },
        }),
      },
      {
        Sid: sid(grant.id, resourceId, "ReadTenantObjects"),
        Effect: effect(grant),
        Action: "s3:GetObject",
        Resource: objectArn(resource.bucketArn, prefix),
        Condition: common,
      },
    );
  }
  if (write) {
    statements.push({
      Sid: sid(grant.id, resourceId, "WriteTenantObjects"),
      Effect: effect(grant),
      Action: ["s3:DeleteObject", "s3:PutObject"],
      Resource: objectArn(resource.bucketArn, prefix),
      Condition: common,
    });
  }
  const kmsActions = [
    ...(read ? ["kms:Decrypt"] : []),
    ...(write ? ["kms:Encrypt", "kms:GenerateDataKey"] : []),
  ];
  if (kmsActions.length > 0) {
    statements.push({
      Sid: sid(grant.id, resourceId, "TenantKey"),
      Effect: effect(grant),
      Action: kmsActions,
      Resource: keyArn,
      Condition: mergeConditions(common, {
        StringLike: {
          "kms:EncryptionContext:aws:s3:arn": [
            objectArn(resource.bucketArn, prefix),
          ],
        },
      }),
    });
  }
  return statements;
}

function compileTrustPolicy(
  identity: Identity,
  extensions: AwsIamProviderExtensions,
): AwsTrustPolicyPlan | undefined {
  const binding = requiredIdentityBinding(identity.id, extensions);
  let statement: AwsPolicyStatement | undefined;
  if (identity.kind === "workload") {
    const podIdentity = requiredPodIdentity(identity.id, binding);
    if (
      binding.oidcProviderArn ||
      binding.oidcIssuerHost ||
      binding.oidcSubject ||
      binding.audience
    ) {
      throw new Error(
        `AWS workload identity '${identity.id}' must use EKS Pod Identity only; IRSA/OIDC fields are not accepted by the Auto Mode baseline.`,
      );
    }
    statement = {
      Sid: "TrustEksPodIdentity",
      Effect: "Allow",
      Action: ["sts:AssumeRole", "sts:TagSession"],
      Principal: { Service: "pods.eks.amazonaws.com" },
      Condition: {
        StringEquals: {
          "aws:SourceOrgId": extensions.organizationId,
          "aws:RequestTag/kubernetes-namespace": podIdentity.namespace,
          "aws:RequestTag/kubernetes-service-account":
            podIdentity.serviceAccount,
        },
      },
    };
  } else if (identity.kind === "vendor") {
    const principalArn = requiredText(
      binding.principalArn,
      `vendor role principal for '${identity.id}'`,
    );
    if (!/^arn:[^:]+:iam::\d{12}:role\/.+/.test(principalArn)) {
      throw new Error(
        `AWS vendor identity '${identity.id}' must trust an IAM role principal.`,
      );
    }
    const externalId = requiredText(
      binding.externalId,
      `external ID for '${identity.id}'`,
    );
    const sourceAccount = requiredText(
      binding.sourceAccount,
      `source account for '${identity.id}'`,
    );
    const sourceArn = requiredText(
      binding.sourceArn,
      `source ARN for '${identity.id}'`,
    );
    statement = {
      Sid: "TrustVendorRole",
      Effect: "Allow",
      Action: "sts:AssumeRole",
      Principal: { AWS: principalArn },
      Condition: {
        StringEquals: {
          "sts:ExternalId": externalId,
          "aws:SourceAccount": sourceAccount,
        },
        ArnEquals: { "aws:SourceArn": sourceArn },
        StringLike: {
          "sts:SourceIdentity": requiredText(
            binding.sourceIdentityPattern,
            `source identity pattern for '${identity.id}'`,
          ),
        },
      },
    };
  }
  if (!statement) return undefined;
  const maxSessionDurationSeconds = binding.maxSessionDurationSeconds ?? 3600;
  if (maxSessionDurationSeconds < 900 || maxSessionDurationSeconds > 3600) {
    throw new Error(
      `AWS identity '${identity.id}' must use a session duration between 900 and 3600 seconds.`,
    );
  }
  const document = policyDocument([statement]);
  return namedPolicy(`aws:iam:trust:${identity.id}`, document, {
    identityId: identity.id,
    maxSessionDurationSeconds,
  });
}

function compileS3ResourcePolicies(
  blueprint: PlatformBlueprint,
  extensions: AwsIamProviderExtensions,
): AwsNamedPolicy[] {
  return Object.entries(extensions.resources)
    .filter(
      (entry): entry is [string, AwsDataResourceBinding] =>
        entry[1].kind === "data",
    )
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([resourceId, resource]) => {
      const statements = grantsForResource(blueprint, resourceId).flatMap(
        ({ grant, identity }) => {
          const tenantId = requiredTenantId(identity, grant);
          const prefix = requiredTenantValue(
            resource.prefixByTenant,
            tenantId,
            `prefix for '${resourceId}'`,
          );
          const principal = requiredIdentityBinding(
            identity.id,
            extensions,
          ).roleArn;
          const result: AwsPolicyStatement[] = [];
          if (grant.actions.includes("data:read")) {
            result.push({
              Sid: sid(grant.id, identity.id, "AllowList"),
              Effect: effect(grant),
              Action: "s3:ListBucket",
              Resource: resource.bucketArn,
              Principal: { AWS: principal },
              Condition: { StringLike: { "s3:prefix": [`${prefix}*`] } },
            });
          }
          const objectActions = [
            ...(grant.actions.includes("data:read") ? ["s3:GetObject"] : []),
            ...(grant.actions.includes("data:write")
              ? ["s3:DeleteObject", "s3:PutObject"]
              : []),
          ];
          if (objectActions.length > 0) {
            result.push({
              Sid: sid(grant.id, identity.id, "AllowObjects"),
              Effect: effect(grant),
              Action: objectActions,
              Resource: objectArn(resource.bucketArn, prefix),
              Principal: { AWS: principal },
            });
          }
          return result;
        },
      );
      const document = policyDocument(statements);
      return namedPolicy(`aws:s3:policy:${resourceId}`, document);
    });
}

function compileKmsKeyPolicies(
  blueprint: PlatformBlueprint,
  extensions: AwsIamProviderExtensions,
): AwsNamedPolicy[] {
  const byKey = new Map<string, AwsPolicyStatement[]>();
  for (const [resourceId, binding] of Object.entries(extensions.resources)) {
    if (binding.kind !== "data") continue;
    for (const { grant, identity } of grantsForResource(
      blueprint,
      resourceId,
    )) {
      const tenantId = requiredTenantId(identity, grant);
      const keyArn = requiredTenantValue(
        binding.keyArnByTenant,
        tenantId,
        `KMS key for '${resourceId}'`,
      );
      const prefix = requiredTenantValue(
        binding.prefixByTenant,
        tenantId,
        `prefix for '${resourceId}'`,
      );
      const actions = [
        ...(grant.actions.includes("data:read") ? ["kms:Decrypt"] : []),
        ...(grant.actions.includes("data:write")
          ? ["kms:Encrypt", "kms:GenerateDataKey"]
          : []),
      ];
      if (actions.length === 0) continue;
      const statements = byKey.get(keyArn) ?? [];
      statements.push({
        Sid: sid(grant.id, identity.id, "UseTenantKey"),
        Effect: effect(grant),
        Action: actions,
        Resource: "*",
        Principal: {
          AWS: requiredIdentityBinding(identity.id, extensions).roleArn,
        },
        Condition: {
          StringLike: {
            "kms:EncryptionContext:aws:s3:arn": [
              objectArn(binding.bucketArn, prefix),
            ],
          },
        },
      });
      byKey.set(keyArn, statements);
    }
  }
  return [...byKey.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([keyArn, statements]) => {
      const document = policyDocument([
        {
          Sid: "RootKeyAdministration",
          Effect: "Allow",
          Action: "kms:*",
          Resource: "*",
          Principal: {
            AWS: `arn:${extensions.partition ?? "aws"}:iam::${extensions.accountId}:root`,
          },
        },
        ...statements,
      ]);
      return namedPolicy(`aws:kms:policy:${keyArn}`, document);
    });
}

function workloadAssociation(
  identity: Identity,
  extensions: AwsIamProviderExtensions,
): AwsWorkloadIdentityAssociation {
  const binding = requiredIdentityBinding(identity.id, extensions);
  const podIdentity = requiredPodIdentity(identity.id, binding);
  return {
    mode: "eks-pod-identity",
    identityId: identity.id,
    roleArn: binding.roleArn,
    namespace: podIdentity.namespace,
    serviceAccount: podIdentity.serviceAccount,
    sessionTagsEnabled: true,
  };
}

function validateExtensions(
  blueprint: PlatformBlueprint,
  extensions: AwsIamProviderExtensions,
) {
  if (!/^\d{12}$/.test(extensions.accountId))
    throw new Error("AWS IAM accountId must contain 12 digits.");
  if (!/^o-[a-z0-9]{10,32}$/.test(extensions.organizationId)) {
    throw new Error(
      "AWS IAM organizationId must be one exact AWS Organizations ID.",
    );
  }
  for (const identity of blueprint.identities)
    requiredIdentityBinding(identity.id, extensions);
  for (const grant of blueprint.grants) {
    for (const resourceId of grant.resourceIds)
      requiredResourceBinding(resourceId, extensions);
  }
  for (const [resourceId, binding] of Object.entries(extensions.resources)) {
    if (binding.kind !== "data") continue;
    const prefixes = Object.values(binding.prefixByTenant);
    if (new Set(prefixes).size !== prefixes.length) {
      throw new Error(
        `AWS data resource '${resourceId}' has overlapping tenant prefixes.`,
      );
    }
    for (const prefix of prefixes) {
      if (
        !prefix ||
        prefix.startsWith("/") ||
        prefix.includes("..") ||
        prefix.includes("*")
      ) {
        throw new Error(
          `AWS data resource '${resourceId}' has an unmanaged tenant prefix.`,
        );
      }
    }
  }
}

function requiredPodIdentity(
  identityId: string,
  binding: AwsIdentityBinding,
): NonNullable<AwsIdentityBinding["podIdentity"]> {
  const podIdentity = binding.podIdentity;
  if (
    !podIdentity ||
    !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(podIdentity.namespace) ||
    !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(podIdentity.serviceAccount)
  ) {
    throw new Error(
      `AWS workload identity '${identityId}' requires one exact EKS Pod Identity namespace and ServiceAccount.`,
    );
  }
  return podIdentity;
}

function grantsForResource(blueprint: PlatformBlueprint, resourceId: string) {
  const identities = new Map(
    blueprint.identities.map((identity) => [identity.id, identity]),
  );
  return blueprint.grants
    .filter((grant) => grant.resourceIds.includes(resourceId))
    .sort((left, right) => left.id.localeCompare(right.id))
    .map((grant) => ({ grant, identity: identities.get(grant.identityId)! }));
}

function mappedActions(
  grant: IdentityGrant,
  actionMap: Readonly<Record<string, readonly string[]>>,
): string[] {
  const actions = grant.actions.flatMap((action) => {
    const mapped = actionMap[action];
    if (!mapped?.length)
      throw new Error(
        `AWS grant '${grant.id}' has no managed action mapping for '${action}'.`,
      );
    return mapped;
  });
  if (actions.some((action) => action.includes("*")))
    throw new Error(
      `AWS grant '${grant.id}' contains an unmanaged wildcard action.`,
    );
  return [...new Set(actions)].sort();
}

function validatePrivilegeScope(
  grant: IdentityGrant,
  actions: readonly string[],
  arns: readonly string[],
) {
  if (!actions.some((action) => privilegeEscalationActions.has(action))) return;
  if (
    arns.length === 0 ||
    arns.some((arn) => arn.includes("*")) ||
    !grant.conditions ||
    Object.keys(grant.conditions).length === 0
  ) {
    throw new Error(
      `AWS privilege-escalation grant '${grant.id}' requires explicit resource and condition scopes.`,
    );
  }
}

function grantConditions(identity: Identity, grant: IdentityGrant) {
  const stringEquals: Record<string, AwsPolicyValue> = {};
  if (identity.tenantId)
    stringEquals["aws:PrincipalTag/deus-tenant-id"] = identity.tenantId;
  for (const [key, value] of Object.entries(grant.conditions ?? {})) {
    if (key === "brokered")
      stringEquals["aws:PrincipalTag/deus-brokered"] = value;
    else if (key.startsWith("aws:")) stringEquals[key] = value;
    else
      throw new Error(
        `AWS grant '${grant.id}' contains unmanaged condition '${key}'.`,
      );
  }
  return Object.keys(stringEquals).length > 0
    ? { StringEquals: stringEquals }
    : undefined;
}

function mergeConditions(
  left: AwsPolicyStatement["Condition"],
  right: NonNullable<AwsPolicyStatement["Condition"]>,
) {
  const result: Record<string, Record<string, AwsPolicyValue>> = {};
  for (const source of [left ?? {}, right]) {
    for (const [operator, values] of Object.entries(source)) {
      result[operator] = { ...(result[operator] ?? {}), ...values };
    }
  }
  return result;
}

function namedPolicy<T extends object>(
  semanticId: string,
  document: AwsPolicyDocument,
  extra?: T,
): AwsNamedPolicy & T {
  return {
    semanticId,
    document,
    canonicalJson: canonicalPolicyJson(document),
    ...(extra ?? ({} as T)),
  };
}

function effect(grant: IdentityGrant) {
  return grant.effect === "allow" ? ("Allow" as const) : ("Deny" as const);
}
function sid(...parts: string[]) {
  return parts
    .join("-")
    .replace(/[^A-Za-z0-9]/g, "")
    .slice(0, 128);
}
function objectArn(bucketArn: string, prefix: string) {
  return `${bucketArn}/${prefix}*`;
}
function sortedArns(arns: readonly string[], grantId: string) {
  if (
    arns.length === 0 ||
    arns.some((arn) => !arn.startsWith("arn:") || arn === "*")
  )
    throw new Error(`AWS grant '${grantId}' requires explicit resource ARNs.`);
  return [...new Set(arns)].sort();
}
function requiredTenantId(identity: Identity, grant: IdentityGrant) {
  const tenantId = grant.tenantId ?? identity.tenantId;
  if (!tenantId || (identity.tenantId && identity.tenantId !== tenantId))
    throw new Error(
      `AWS grant '${grant.id}' requires one matching tenant context.`,
    );
  return tenantId;
}
function requiredTenantValue(
  values: Readonly<Record<string, string>>,
  tenantId: string,
  label: string,
) {
  return requiredText(values[tenantId], `${label} for tenant '${tenantId}'`);
}
function requiredIdentityBinding(
  identityId: string,
  extensions: AwsIamProviderExtensions,
) {
  const binding = extensions.identities[identityId];
  if (
    !binding?.roleArn ||
    !/^arn:[^:]+:iam::\d{12}:role\/.+/.test(binding.roleArn)
  )
    throw new Error(
      `AWS identity '${identityId}' requires an explicit role ARN binding.`,
    );
  return binding;
}
function requiredResourceBinding(
  resourceId: string,
  extensions: AwsIamProviderExtensions,
) {
  const binding = extensions.resources[resourceId];
  if (!binding)
    throw new Error(`AWS resource '${resourceId}' has no provider binding.`);
  return binding;
}
function requiredText(value: string | undefined, label: string) {
  if (!value?.trim()) throw new Error(`AWS ${label} is required.`);
  return value;
}
function rejectUnknownDataActions(grant: IdentityGrant) {
  const unknown = grant.actions.filter(
    (action) => action !== "data:read" && action !== "data:write",
  );
  if (unknown.length > 0)
    throw new Error(
      `AWS data grant '${grant.id}' contains unmanaged actions: ${unknown.join(", ")}.`,
    );
}
function bySemanticId(left: AwsNamedPolicy, right: AwsNamedPolicy) {
  return left.semanticId.localeCompare(right.semanticId);
}
