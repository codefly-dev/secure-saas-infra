import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { IdentityCenterConfig, baseTags, named } from "./config";

export interface IdentityCenterResult {
  permissionSetArns: pulumi.Output<Record<string, string>>;
  groupIds: pulumi.Output<Record<string, string>>;
}

export function createIdentityCenter(config: IdentityCenterConfig): IdentityCenterResult {
  const instances = aws.ssoadmin.getInstancesOutput({});
  const instanceArn = pulumi.output(config.identityCenterInstanceArn ?? instances.arns.apply((arns) => arns[0]));
  const identityStoreId = pulumi.output(config.identityStoreId ?? instances.identityStoreIds.apply((ids) => ids[0]));
  const accountIds: pulumi.Output<Record<string, string>> = config.organizationStackRef
    ? (new pulumi.StackReference("organization", { name: config.organizationStackRef }).requireOutput(
        "organizationAccountIds",
      ) as pulumi.Output<Record<string, string>>)
    : pulumi.output<Record<string, string>>({});

  const groupIds: Record<string, pulumi.Output<string>> = {};
  for (const group of config.groups) {
    if (group.groupId) {
      groupIds[group.name] = pulumi.output(group.groupId);
      continue;
    }

    if (group.create ?? true) {
      const created = new aws.identitystore.Group(named(`identity-group-${slug(group.name)}`), {
        identityStoreId,
        displayName: group.displayName,
        description: group.description ?? `${group.displayName} access group.`,
      });
      groupIds[group.name] = created.groupId;
      continue;
    }

    groupIds[group.name] = aws.identitystore.getGroupOutput({
      identityStoreId,
      alternateIdentifier: {
        uniqueAttribute: {
          attributePath: "DisplayName",
          attributeValue: group.displayName,
        },
      },
    }).groupId;
  }

  const permissionSets: Record<string, aws.ssoadmin.PermissionSet> = {};
  const permissionSetDependencies: Record<string, pulumi.Resource[]> = {};
  for (const permissionSet of config.permissionSets) {
    const resource = new aws.ssoadmin.PermissionSet(named(`permission-set-${slug(permissionSet.name)}`), {
      instanceArn,
      name: permissionSet.name,
      description: permissionSet.description,
      sessionDuration: permissionSet.sessionDuration,
      tags: tag(`permission-set-${slug(permissionSet.name)}`),
    });

    permissionSets[permissionSet.name] = resource;
    const dependencies: pulumi.Resource[] = [resource];

    permissionSet.managedPolicyArns.forEach((policyArn, index) => {
      const attachment = new aws.ssoadmin.ManagedPolicyAttachment(
        named(`permission-set-${slug(permissionSet.name)}-policy-${index + 1}`),
        {
          instanceArn,
          permissionSetArn: resource.arn,
          managedPolicyArn: policyArn,
        },
      );
      dependencies.push(attachment);
    });

    if (permissionSet.inlinePolicy) {
      const inlinePolicy = new aws.ssoadmin.PermissionSetInlinePolicy(
        named(`permission-set-${slug(permissionSet.name)}-inline`),
        {
          instanceArn,
          permissionSetArn: resource.arn,
          inlinePolicy: JSON.stringify(permissionSet.inlinePolicy),
        },
      );
      dependencies.push(inlinePolicy);
    }

    permissionSetDependencies[permissionSet.name] = dependencies;
  }

  for (const assignment of config.assignments) {
    const groupId = groupIds[assignment.groupName];
    const permissionSet = permissionSets[assignment.permissionSetName];

    if (!groupId || !permissionSet) {
      continue;
    }

    const explicitAccountIds = assignment.accountIds ?? [];
    const accountNameTargets = assignment.accountNames ?? [];

    explicitAccountIds.forEach((accountId, index) => {
      createAssignment(assignment.groupName, assignment.permissionSetName, `id-${index + 1}`, {
        instanceArn,
        permissionSetArn: permissionSet.arn,
        groupId,
        accountId: pulumi.output(accountId),
        dependsOn: permissionSetDependencies[assignment.permissionSetName],
      });
    });

    accountNameTargets.forEach((accountName) => {
      createAssignment(assignment.groupName, assignment.permissionSetName, accountName, {
        instanceArn,
        permissionSetArn: permissionSet.arn,
        groupId,
        accountId: accountIds.apply((ids) => ids[accountName]),
        dependsOn: permissionSetDependencies[assignment.permissionSetName],
      });
    });
  }

  return {
    groupIds: pulumi.output(Object.fromEntries(Object.entries(groupIds))),
    permissionSetArns: pulumi.output(
      Object.fromEntries(Object.entries(permissionSets).map(([name, permissionSet]) => [name, permissionSet.arn])),
    ),
  };
}

function createAssignment(
  groupName: string,
  permissionSetName: string,
  targetName: string,
  args: {
    instanceArn: pulumi.Input<string>;
    permissionSetArn: pulumi.Input<string>;
    groupId: pulumi.Input<string>;
    accountId: pulumi.Input<string>;
    dependsOn?: pulumi.Resource[];
  },
) {
  new aws.ssoadmin.AccountAssignment(
    named(`identity-${slug(groupName)}-${slug(permissionSetName)}-${slug(targetName)}`),
    {
      instanceArn: args.instanceArn,
      permissionSetArn: args.permissionSetArn,
      principalId: args.groupId,
      principalType: "GROUP",
      targetId: args.accountId,
      targetType: "AWS_ACCOUNT",
    },
    { dependsOn: args.dependsOn },
  );
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
