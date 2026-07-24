import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { compileAwsEksAccessGrants } from "./adapters/aws";
import { EksConfig, baseTags, named } from "./config";
import { SpokeNetwork } from "./network";

export interface EksClusterResult {
  cluster: aws.eks.Cluster;
  clusterRole: aws.iam.Role;
  nodeRole: aws.iam.Role;
}

export function createEksCluster(
  spoke: SpokeNetwork,
  config: EksConfig,
): EksClusterResult {
  const clusterRole = new aws.iam.Role(
    named(`${spoke.name}-eks-cluster-role`),
    {
      assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({
        Service: "eks.amazonaws.com",
      }),
      tags: tag(`${spoke.name}-eks-cluster-role`),
    },
  );

  const clusterPolicyArns = [
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    "arn:aws:iam::aws:policy/AmazonEKSComputePolicy",
    "arn:aws:iam::aws:policy/AmazonEKSBlockStoragePolicy",
    "arn:aws:iam::aws:policy/AmazonEKSLoadBalancingPolicy",
    "arn:aws:iam::aws:policy/AmazonEKSNetworkingPolicy",
  ];

  const clusterPolicyAttachments = clusterPolicyArns.map(
    (policyArn, index) =>
      new aws.iam.RolePolicyAttachment(
        named(`${spoke.name}-eks-cluster-policy-${index + 1}`),
        {
          role: clusterRole.name,
          policyArn,
        },
      ),
  );

  const nodeRole = new aws.iam.Role(named(`${spoke.name}-eks-auto-node-role`), {
    assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({
      Service: "ec2.amazonaws.com",
    }),
    tags: tag(`${spoke.name}-eks-auto-node-role`),
  });

  const nodePolicies = [
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodeMinimalPolicy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly",
  ];

  const nodePolicyAttachments = nodePolicies.map(
    (policyArn, index) =>
      new aws.iam.RolePolicyAttachment(
        named(`${spoke.name}-eks-auto-node-policy-${index + 1}`),
        {
          role: nodeRole.name,
          policyArn,
        },
      ),
  );

  const clusterName = named(`${spoke.name}-eks`);

  const secretsKey = new aws.kms.Key(named(`${spoke.name}-eks-secrets-key`), {
    description: `KMS key for Kubernetes secret envelope encryption in ${clusterName}.`,
    enableKeyRotation: true,
    deletionWindowInDays: 30,
    tags: tag(`${spoke.name}-eks-secrets-key`),
  });

  new aws.kms.Alias(named(`${spoke.name}-eks-secrets-key-alias`), {
    name: `alias/${clusterName}-secrets`,
    targetKeyId: secretsKey.keyId,
  });

  const logGroup = new aws.cloudwatch.LogGroup(
    named(`${spoke.name}-eks-control-plane-logs`),
    {
      name: `/aws/eks/${clusterName}/cluster`,
      retentionInDays: 365,
      tags: tag(`${spoke.name}-eks-control-plane-logs`),
    },
  );

  const cluster = new aws.eks.Cluster(
    clusterName,
    {
      name: clusterName,
      version: config.version,
      roleArn: clusterRole.arn,
      enabledClusterLogTypes: [
        "api",
        "audit",
        "authenticator",
        "controllerManager",
        "scheduler",
      ],
      accessConfig: {
        authenticationMode: "API",
        bootstrapClusterCreatorAdminPermissions: false,
      },
      vpcConfig: {
        subnetIds: spoke.privateSubnets.map((subnet) => subnet.id),
        endpointPrivateAccess: true,
        endpointPublicAccess: config.endpointPublicAccess,
      },
      encryptionConfig: {
        provider: {
          keyArn: secretsKey.arn,
        },
        resources: ["secrets"],
      },
      computeConfig: {
        enabled: true,
        nodeRoleArn: nodeRole.arn,
        nodePools: config.autoModeNodePools,
      },
      kubernetesNetworkConfig: {
        elasticLoadBalancing: {
          enabled: true,
        },
      },
      storageConfig: {
        blockStorage: {
          enabled: true,
        },
      },
      upgradePolicy: {
        supportType: "STANDARD",
      },
      tags: tag(`${spoke.name}-eks`, {
        SpokeKind: spoke.kind,
      }),
    },
    {
      dependsOn: [
        logGroup,
        ...clusterPolicyAttachments,
        ...nodePolicyAttachments,
        spoke.attachment,
      ],
    },
  );

  const nodeAccessEntry = new aws.eks.AccessEntry(
    named(`${spoke.name}-eks-auto-node-access`),
    {
      clusterName: cluster.name,
      principalArn: nodeRole.arn,
      type: "EC2",
    },
  );
  new aws.eks.AccessPolicyAssociation(
    named(`${spoke.name}-eks-auto-node-policy`),
    {
      clusterName: cluster.name,
      principalArn: nodeRole.arn,
      policyArn:
        "arn:aws:eks::aws:cluster-access-policy/AmazonEKSAutoNodePolicy",
      accessScope: { type: "cluster" },
    },
    { dependsOn: nodeAccessEntry },
  );

  for (const grant of compileAwsEksAccessGrants(config.accessGrants)) {
    const roleArn = resolveEksAccessPrincipal(grant.principal);
    const accessEntry = new aws.eks.AccessEntry(
      named(`${spoke.name}-${grant.id}-access`),
      {
        clusterName: cluster.name,
        principalArn: roleArn,
        type: "STANDARD",
        tags: tag(`${spoke.name}-${grant.id}-access`, {
          AccessCategory: grant.principal.category,
          AccessPolicy: grant.accessPolicy,
        }),
      },
    );

    new aws.eks.AccessPolicyAssociation(
      named(`${spoke.name}-${grant.id}-${grant.accessPolicy}`),
      {
        clusterName: cluster.name,
        principalArn: roleArn,
        policyArn: grant.policyArn,
        accessScope:
          grant.scope.type === "cluster"
            ? { type: "cluster" }
            : { type: "namespace", namespaces: [...grant.scope.namespaces] },
      },
      { dependsOn: accessEntry },
    );
  }

  return {
    cluster,
    clusterRole,
    nodeRole,
  };
}

function resolveEksAccessPrincipal(
  principal: ReturnType<typeof compileAwsEksAccessGrants>[number]["principal"],
): pulumi.Input<string> {
  if (principal.kind === "iam-role") return principal.roleArn;
  const roles = aws.iam.getRolesOutput({
    nameRegex: principal.roleNameRegex,
    pathPrefix: principal.rolePathPrefix,
  });
  return roles.arns.apply((arns) => {
    if (arns.length !== 1) {
      throw new Error(
        `EKS_ACCESS_IDENTITY_CENTER_RESOLUTION expected exactly one IAM role for permission set '${principal.permissionSetName}', found ${arns.length}. Ensure its account assignment is provisioned before this stack.`,
      );
    }
    const roleArn = arns[0];
    if (
      !/^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role\/aws-reserved\/sso\.amazonaws\.com\/(?:[a-z0-9-]+\/)?AWSReservedSSO_[A-Za-z0-9+=,.@_-]+_[A-Fa-f0-9]{16}$/.test(
        roleArn,
      )
    ) {
      throw new Error(
        `EKS_ACCESS_IDENTITY_CENTER_RESOLUTION resolved role for '${principal.permissionSetName}' has an unexpected ARN shape.`,
      );
    }
    return roleArn;
  });
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
