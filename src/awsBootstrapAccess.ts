import * as aws from "@pulumi/aws";
import type { ResourceOptions } from "@pulumi/pulumi";
import {
  compileAwsBootstrapAccessPlan,
  type AwsAccessRolePolicyPlan,
} from "./adapters/aws";
import { baseTags } from "./config";

export interface AwsBootstrapAccountAccessResources {
  accountName: string;
  accountId: string;
  sourceDigest: string;
  roles: Readonly<
    Record<
      string,
      {
        plan: AwsAccessRolePolicyPlan;
        boundary: aws.iam.Policy;
        delegatedBoundary?: aws.iam.Policy;
        role: aws.iam.Role;
        inlinePolicy: aws.iam.RolePolicy;
      }
    >
  >;
}

export function createAwsBootstrapAccountAccess(
  planValue: unknown,
  accountName: string,
): AwsBootstrapAccountAccessResources {
  const compiled = compileAwsBootstrapAccessPlan(planValue);
  const rolePlans = compiled.roles.filter(
    (role) => role.accountName === accountName,
  );
  if (rolePlans.length === 0) {
    throw new Error(
      `AWS bootstrap access plan does not declare account '${accountName}'.`,
    );
  }
  const accountIds = new Set(rolePlans.map((role) => role.accountId));
  if (accountIds.size !== 1) {
    throw new Error(`Access roles for '${accountName}' cross AWS accounts.`);
  }

  const resources: Record<
    string,
    {
      plan: AwsAccessRolePolicyPlan;
      boundary: aws.iam.Policy;
      delegatedBoundary?: aws.iam.Policy;
      role: aws.iam.Role;
      inlinePolicy: aws.iam.RolePolicy;
    }
  > = {};
  for (const rolePlan of rolePlans) {
    const key = rolePlan.actionSet ?? rolePlan.mode;
    const resourceName = accessResourceName(accountName, key);
    const resourceOptions: ResourceOptions = {
      protect: true,
      retainOnDelete: true,
    };
    const tags = {
      ...baseTags,
      Name: rolePlan.roleName,
      BootstrapAccessAccount: accountName,
      BootstrapAccessMode: rolePlan.mode,
      BootstrapAccessLane: rolePlan.actionSet ?? "all",
      BootstrapAccessSourceDigest: compiled.sourceDigest,
      DestructiveMutation: "false",
    };
    const boundary = new aws.iam.Policy(
      `${resourceName}-boundary`,
      {
        name: rolePlan.permissionsBoundaryName,
        description: `Permissions boundary for ${accountName} ${rolePlan.mode} ${rolePlan.actionSet ?? "all"}.`,
        policy: rolePlan.canonicalPermissionsBoundary,
        tags,
      },
      resourceOptions,
    );
    const delegatedBoundary = rolePlan.delegatedRoleBoundary
      ? new aws.iam.Policy(
          `${resourceName}-delegated-boundary`,
          {
            name: rolePlan.delegatedRoleBoundary.name,
            description: `Delegated service-role boundary for ${accountName} ${rolePlan.actionSet}.`,
            policy: rolePlan.delegatedRoleBoundary.canonicalPolicy,
            tags: {
              ...tags,
              BoundaryPurpose: "delegated-service-role",
            },
          },
          resourceOptions,
        )
      : undefined;
    const role = new aws.iam.Role(
      `${resourceName}-role`,
      {
        name: rolePlan.roleName,
        description: `Rootless infrastructure ${rolePlan.mode} role for ${accountName} ${rolePlan.actionSet ?? "all"}.`,
        assumeRolePolicy: rolePlan.canonicalTrustPolicy,
        maxSessionDuration: rolePlan.maxSessionDurationSeconds,
        permissionsBoundary: boundary.arn,
        tags,
      },
      { ...resourceOptions, dependsOn: [boundary] },
    );
    const inlinePolicy = new aws.iam.RolePolicy(
      `${resourceName}-permissions`,
      {
        name: `${rolePlan.roleName}Permissions`,
        role: role.name,
        policy: rolePlan.canonicalPermissionsPolicy,
      },
      { ...resourceOptions, dependsOn: [boundary, role] },
    );
    resources[key] = {
      plan: rolePlan,
      boundary,
      ...(delegatedBoundary ? { delegatedBoundary } : {}),
      role,
      inlinePolicy,
    };
  }

  return {
    accountName,
    accountId: rolePlans[0]!.accountId,
    sourceDigest: compiled.sourceDigest,
    roles: resources,
  };
}

function accessResourceName(accountName: string, lane: string): string {
  return `bootstrap-access-${accountName}-${lane}`
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-|-$/g, "");
}
