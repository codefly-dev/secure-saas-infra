import * as aws from "@pulumi/aws";
import { EksConfig, adminRoleArns, baseTags, named } from "./config";
import { SpokeNetwork } from "./network";

export interface EksClusterResult {
  cluster: aws.eks.Cluster;
  clusterRole: aws.iam.Role;
  nodeRole: aws.iam.Role;
}

export function createEksCluster(spoke: SpokeNetwork, config: EksConfig): EksClusterResult {
  const clusterRole = new aws.iam.Role(named(`${spoke.name}-eks-cluster-role`), {
    assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({
      Service: "eks.amazonaws.com",
    }),
    tags: tag(`${spoke.name}-eks-cluster-role`),
  });

  const clusterPolicyArns = [
    "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy",
    "arn:aws:iam::aws:policy/AmazonEKSComputePolicy",
    "arn:aws:iam::aws:policy/AmazonEKSBlockStoragePolicy",
    "arn:aws:iam::aws:policy/AmazonEKSLoadBalancingPolicy",
    "arn:aws:iam::aws:policy/AmazonEKSNetworkingPolicy",
  ];

  const clusterPolicyAttachments = clusterPolicyArns.map(
    (policyArn, index) =>
      new aws.iam.RolePolicyAttachment(named(`${spoke.name}-eks-cluster-policy-${index + 1}`), {
        role: clusterRole.name,
        policyArn,
      }),
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
      new aws.iam.RolePolicyAttachment(named(`${spoke.name}-eks-auto-node-policy-${index + 1}`), {
        role: nodeRole.name,
        policyArn,
      }),
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

  const logGroup = new aws.cloudwatch.LogGroup(named(`${spoke.name}-eks-control-plane-logs`), {
    name: `/aws/eks/${clusterName}/cluster`,
    retentionInDays: 365,
    tags: tag(`${spoke.name}-eks-control-plane-logs`),
  });

  const cluster = new aws.eks.Cluster(
    clusterName,
    {
      name: clusterName,
      version: config.version,
      roleArn: clusterRole.arn,
      enabledClusterLogTypes: ["api", "audit", "authenticator", "controllerManager", "scheduler"],
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
      } as any,
      kubernetesNetworkConfig: {
        elasticLoadBalancing: {
          enabled: true,
        },
      } as any,
      storageConfig: {
        blockStorage: {
          enabled: true,
        },
      } as any,
      upgradePolicy: {
        supportType: "STANDARD",
      },
      tags: tag(`${spoke.name}-eks`, {
        SpokeKind: spoke.kind,
      }),
    } as any,
    {
      dependsOn: [logGroup, ...clusterPolicyAttachments, ...nodePolicyAttachments, spoke.attachment],
    },
  );

  new aws.eks.AccessEntry(named(`${spoke.name}-eks-auto-node-access`), {
    clusterName: cluster.name,
    principalArn: nodeRole.arn,
    type: "EC2",
  });

  adminRoleArns.forEach((roleArn, index) => {
    const accessEntry = new aws.eks.AccessEntry(named(`${spoke.name}-admin-${index + 1}-access`), {
      clusterName: cluster.name,
      principalArn: roleArn,
      type: "STANDARD",
    });

    new aws.eks.AccessPolicyAssociation(
      named(`${spoke.name}-admin-${index + 1}-cluster-admin`),
      {
        clusterName: cluster.name,
        principalArn: roleArn,
        policyArn: "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy",
        accessScope: {
          type: "cluster",
        },
      },
      { dependsOn: accessEntry },
    );
  });

  createEksAddons(spoke.name, cluster, config);

  return {
    cluster,
    clusterRole,
    nodeRole,
  };
}

function createEksAddons(name: string, cluster: aws.eks.Cluster, config: EksConfig) {
  const addonDefaults = {
    clusterName: cluster.name,
    resolveConflictsOnCreate: "OVERWRITE",
    resolveConflictsOnUpdate: "OVERWRITE",
  };

  new aws.eks.Addon(`${named(`${name}-pod-identity-agent`)}`, {
    ...addonDefaults,
    addonName: "eks-pod-identity-agent",
    tags: tag(`${name}-pod-identity-agent`),
  });

  new aws.eks.Addon(`${named(`${name}-vpc-cni`)}`, {
    ...addonDefaults,
    addonName: "vpc-cni",
    configurationValues: JSON.stringify({
      enableNetworkPolicy: "true",
      env: {
        NETWORK_POLICY_ENFORCING_MODE: config.networkPolicyMode,
      },
      nodeAgent: {
        enablePolicyEventLogs: "true",
      },
    }),
    tags: tag(`${name}-vpc-cni`),
  });
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
