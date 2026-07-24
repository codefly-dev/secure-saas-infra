import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { createHash } from "node:crypto";
import {
  assertAwsApplyLaneIamConstraint,
  awsApplyLaneIamRoleName,
  awsManagedPostgresDatabaseUser,
  compileAwsPostgresBootstrapSecretPolicy,
  compileAwsRdsProxyConnectPolicy,
  type AwsApplyLaneIamConstraint,
} from "./adapters/aws";
import { baseTags, named } from "./config";
import type { DatabaseResult } from "./database";
import type {
  ManagedPostgresBinding,
  ManagedPostgresEnvironment,
} from "./core";
import { parseAwsDatabaseInfrastructureHandoff } from "./core";

export type AwsDatabaseAccessClass = "runtime" | "migration" | "bootstrap";

export interface AwsDatabaseWorkloadManifest {
  namespace: {
    apiVersion: "v1";
    kind: "Namespace";
    metadata: { name: string; labels: Record<string, string> };
  };
  serviceAccount: {
    apiVersion: string;
    kind: string;
    metadata: {
      name: string;
      namespace: string;
      labels: Record<string, string>;
      annotations: Record<string, string>;
    };
    automountServiceAccountToken: false;
  };
  admissionPolicy: {
    apiVersion: "kyverno.io/v1";
    kind: "ClusterPolicy";
    metadata: { name: string; annotations: Record<string, string> };
    spec: {
      admission: true;
      background: false;
      failurePolicy: "Fail";
      validationFailureAction: "Enforce";
      rules: Array<{
        name: string;
        match: {
          any: Array<{
            resources: { kinds: string[]; namespaces?: string[] };
          }>;
        };
        preconditions?: {
          any: Array<{
            key: string;
            operator: "Equals" | "AnyIn" | "GreaterThan";
            value: string | number | boolean | string[];
          }>;
        };
        validate: {
          message: string;
          pattern?: Record<string, unknown>;
          deny?: {
            conditions: {
              all: Array<{
                key: string | boolean;
                operator: "Equals" | "NotEquals";
                value: string | boolean;
              }>;
            };
          };
        };
      }>;
    };
  };
  applicationNetworkPolicy: {
    apiVersion: "networking.k8s.aws/v1alpha1";
    kind: "ApplicationNetworkPolicy";
    metadata: { name: string; namespace: string };
    spec: {
      podSelector: { matchLabels: Record<string, string> };
      policyTypes: ["Ingress", "Egress"];
      ingress: ReadonlyArray<never>;
      egress: Array<{
        to: Array<{
          domainNames?: string[];
          ipBlock?: { cidr: string };
        }>;
        ports: Array<{ protocol: "TCP"; port: number }>;
      }>;
    };
  };
  nodeClass: {
    apiVersion: "eks.amazonaws.com/v1";
    kind: "NodeClass";
    metadata: { name: string };
    spec: {
      role: string;
      subnetSelectorTerms: Array<{ id: string }>;
      securityGroupSelectorTerms: Array<{
        tags: Record<string, string>;
      }>;
      podSubnetSelectorTerms: Array<{ id: string }>;
      podSecurityGroupSelectorTerms: Array<{ id: string }>;
      snatPolicy: "Disabled";
      networkPolicy: "DefaultDeny";
      networkPolicyEventLogs: "Enabled";
      advancedNetworking: { associatePublicIPAddress: false };
    };
  };
  nodePool: {
    apiVersion: "karpenter.sh/v1";
    kind: "NodePool";
    metadata: { name: string };
    spec: {
      template: {
        metadata: { labels: Record<string, string> };
        spec: {
          nodeClassRef: {
            group: "eks.amazonaws.com";
            kind: "NodeClass";
            name: string;
          };
          taints: Array<{
            key: string;
            value: string;
            effect: "NoSchedule";
          }>;
          requirements: Array<{
            key: string;
            operator: "In";
            values: string[];
          }>;
          expireAfter: "336h";
        };
      };
      limits: { cpu: "64"; memory: "256Gi" };
      disruption: {
        consolidationPolicy: "WhenEmptyOrUnderutilized";
        consolidateAfter: "5m";
      };
    };
  };
  requiredPodScheduling: {
    nodeSelector: Readonly<Record<string, string>>;
    tolerations: ReadonlyArray<{
      key: string;
      operator: "Equal";
      value: string;
      effect: "NoSchedule";
    }>;
  };
  requiredPodLabels: Readonly<Record<string, string>>;
  requiredPodAnnotations: Readonly<Record<string, string>>;
}

export interface AwsDatabaseAccessIdentityResult {
  accessClass: AwsDatabaseAccessClass;
  namespace: string;
  serviceAccount: string;
  databaseUser?: string;
  role: aws.iam.Role;
  policy: aws.iam.RolePolicy;
  association?: aws.eks.PodIdentityAssociation;
  securityGroup: aws.ec2.SecurityGroup;
  bindingDigest: pulumi.Output<string>;
  workloadBundleDigest: pulumi.Output<string>;
  workloadManifest: pulumi.Output<AwsDatabaseWorkloadManifest>;
}

export function awsDatabaseAccessReservationKey(
  bindingId: string,
  accessClass: AwsDatabaseAccessClass,
): string {
  const suffix = createHash("sha256")
    .update(`${bindingId}:${accessClass}`, "utf8")
    .digest("hex")
    .slice(0, 16);
  return `node-restriction.kubernetes.io/database-access-${suffix}`;
}

export function compileAwsDatabaseAdmissionPolicy(args: {
  bindingId: string;
  accessClass: AwsDatabaseAccessClass;
  namespace: string;
  serviceAccount: string;
  bindingLabels: Record<string, string>;
  requiredPodAnnotations: Record<string, string>;
  requiredPodScheduling: AwsDatabaseWorkloadManifest["requiredPodScheduling"];
}): AwsDatabaseWorkloadManifest["admissionPolicy"] {
  const schedulingLabel = awsDatabaseAccessReservationKey(
    args.bindingId,
    args.accessClass,
  );
  const taintKey = schedulingLabel;
  const managedResourceName = dnsLabel(
    `${args.bindingId}-${args.accessClass}-access`,
  );
  const schedulingValue = dnsLabel(
    `${args.bindingId}-${args.accessClass}-database-access`,
  );
  if (
    args.requiredPodScheduling.nodeSelector[schedulingLabel] !==
      schedulingValue ||
    !args.requiredPodScheduling.tolerations.some(
      (toleration) =>
        toleration.key === taintKey &&
        toleration.operator === "Equal" &&
        toleration.value === schedulingValue &&
        toleration.effect === "NoSchedule",
    )
  ) {
    throw new Error(
      `Database admission policy '${args.bindingId}/${args.accessClass}' requires its exact content-addressed node selector and taint toleration.`,
    );
  }
  const allowedPodOwnerKind =
    args.accessClass === "runtime" ? "ReplicaSet" : "Job";
  const forbiddenWorkloadKinds =
    args.accessClass === "runtime"
      ? ["DaemonSet", "Job", "CronJob", "StatefulSet", "ReplicationController"]
      : [
          "Deployment",
          "DaemonSet",
          "CronJob",
          "StatefulSet",
          "ReplicaSet",
          "ReplicationController",
        ];
  return {
    apiVersion: "kyverno.io/v1",
    kind: "ClusterPolicy",
    metadata: {
      name: managedResourceName,
      annotations: {
        "pod-policies.kyverno.io/autogen-controllers": "none",
      },
    },
    spec: {
      admission: true,
      background: false,
      failurePolicy: "Fail",
      validationFailureAction: "Enforce",
      rules: [
        {
          name: "bind-exact-database-access-class",
          match: {
            any: [
              {
                resources: {
                  kinds: ["Pod"],
                  namespaces: [args.namespace],
                },
              },
            ],
          },
          validate: {
            message: "SEC_DATABASE_ACCESS_BINDING_DENIED",
            pattern: {
              metadata: {
                labels: args.bindingLabels,
                annotations: args.requiredPodAnnotations,
              },
              spec: {
                serviceAccountName: args.serviceAccount,
                automountServiceAccountToken: false,
                nodeSelector: args.requiredPodScheduling.nodeSelector,
                "^(tolerations)": args.requiredPodScheduling.tolerations,
              },
            },
          },
        },
        {
          name: "reserve-database-node-pool",
          match: {
            any: [{ resources: { kinds: ["Pod"] } }],
          },
          preconditions: {
            any: [
              {
                key: `{{ request.object.spec.nodeSelector."${schedulingLabel}" || '' }}`,
                operator: "Equals",
                value: schedulingValue,
              },
              {
                key: `{{ request.object.spec.tolerations[?key == '${taintKey}'] | length(@) }}`,
                operator: "GreaterThan",
                value: 0,
              },
              {
                key: `{{ contains(to_string(request.object.spec.affinity || \`{}\`), '${schedulingLabel}') }}`,
                operator: "Equals",
                value: true,
              },
            ],
          },
          validate: {
            message: "SEC_DATABASE_NODE_POOL_RESERVED",
            deny: {
              conditions: {
                all: [
                  {
                    key: "{{ request.object.metadata.namespace || '' }}",
                    operator: "NotEquals" as const,
                    value: args.namespace,
                  },
                ],
              },
            },
          },
        },
        {
          name: "deny-direct-node-binding",
          match: {
            any: [
              {
                resources: {
                  kinds: ["Pod"],
                  namespaces: [args.namespace],
                },
              },
            ],
          },
          validate: {
            message: "SEC_DATABASE_NODE_NAME_DENIED",
            deny: {
              conditions: {
                all: [
                  {
                    key: "{{ request.object.spec.nodeName || '' }}",
                    operator: "NotEquals" as const,
                    value: "",
                  },
                ],
              },
            },
          },
        },
        {
          name: "require-database-pod-controller-identity",
          match: {
            any: [
              {
                resources: {
                  kinds: ["Pod"],
                  namespaces: [args.namespace],
                },
              },
            ],
          },
          validate: {
            message: "SEC_DATABASE_POD_ACTOR_DENIED",
            deny: {
              conditions: {
                all: [
                  {
                    key: "{{ request.userInfo.username || '' }}",
                    operator: "NotEquals" as const,
                    value: "system:kube-controller-manager",
                  },
                  {
                    key: "{{ request.userInfo.username || '' }}",
                    operator: "NotEquals",
                    value:
                      "system:serviceaccount:kube-system:replicaset-controller",
                  },
                  {
                    key: "{{ request.userInfo.username || '' }}",
                    operator: "NotEquals",
                    value: "system:serviceaccount:kube-system:job-controller",
                  },
                ],
              },
            },
          },
        },
        ...(args.accessClass === "runtime"
          ? [
              {
                name: "require-database-replicaset-controller-identity",
                match: {
                  any: [
                    {
                      resources: {
                        kinds: ["apps/v1/ReplicaSet"],
                        namespaces: [args.namespace],
                      },
                    },
                  ],
                },
                validate: {
                  message: "SEC_DATABASE_CHILD_ACTOR_DENIED",
                  deny: {
                    conditions: {
                      all: [
                        {
                          key: "{{ request.userInfo.username || '' }}",
                          operator: "NotEquals" as const,
                          value: "system:kube-controller-manager",
                        },
                        {
                          key: "{{ request.userInfo.username || '' }}",
                          operator: "NotEquals" as const,
                          value:
                            "system:serviceaccount:kube-system:replicaset-controller",
                        },
                      ],
                    },
                  },
                },
              },
            ]
          : []),
        {
          name: "database-pod-bindings-scheduler-only",
          match: {
            any: [
              {
                resources: {
                  kinds: ["Pod/binding"],
                  namespaces: [args.namespace],
                },
              },
            ],
          },
          validate: {
            message: "SEC_DATABASE_POD_BINDING_DENIED",
            deny: {
              conditions: {
                all: [
                  {
                    key: "{{ request.userInfo.username || '' }}",
                    operator: "NotEquals" as const,
                    value: "system:kube-scheduler",
                  },
                ],
              },
            },
          },
        },
        {
          name: "database-pods-default-scheduler-only",
          match: {
            any: [
              {
                resources: {
                  kinds: ["Pod"],
                  namespaces: [args.namespace],
                },
              },
            ],
          },
          validate: {
            message: "SEC_DATABASE_CUSTOM_SCHEDULER_DENIED",
            deny: {
              conditions: {
                all: [
                  {
                    key: "{{ request.object.spec.schedulerName || 'default-scheduler' }}",
                    operator: "NotEquals" as const,
                    value: "default-scheduler",
                  },
                ],
              },
            },
          },
        },
        {
          name: "require-database-pod-controller-owner",
          match: {
            any: [
              {
                resources: {
                  kinds: ["Pod"],
                  namespaces: [args.namespace],
                },
              },
            ],
          },
          validate: {
            message: "SEC_DATABASE_POD_OWNER_DENIED",
            pattern: {
              metadata: {
                ownerReferences: [
                  { controller: true, kind: allowedPodOwnerKind },
                ],
              },
            },
          },
        },
        {
          name: "restrict-database-workload-kind",
          match: {
            any: [
              {
                resources: {
                  kinds: forbiddenWorkloadKinds,
                  namespaces: [args.namespace],
                },
              },
            ],
          },
          validate: {
            message: "SEC_DATABASE_WORKLOAD_KIND_DENIED",
            deny: {
              conditions: {
                all: [
                  {
                    key: true,
                    operator: "Equals",
                    value: true,
                  },
                ],
              },
            },
          },
        },
      ],
    },
  };
}

export interface AwsManagedPostgresAccessResult {
  runtime: AwsDatabaseAccessIdentityResult;
  migration: AwsDatabaseAccessIdentityResult;
  bootstrap: AwsDatabaseAccessIdentityResult;
}

export interface AwsDatabaseInfrastructureHandoff {
  apiVersion: "infrastructure.deus.dev/aws-database-infrastructure-handoff/v1alpha1";
  kind: "AwsDatabaseInfrastructureHandoff";
  bindingId: string;
  handoffSpecDigest: string;
  owner: "external-iac";
  authorizedConsumer: "infrastructure-controller";
  applicationMutationAllowed: false;
  deploymentAuthorization: {
    state: "pending-identity-binding";
    directPodCreationAllowed: false;
    namespaceWriteAccess: "exclusive-controller";
    allowedWorkloadKinds: {
      runtime: readonly ["Deployment"];
      migration: readonly ["Job"];
      bootstrap: readonly ["Job"];
    };
    requiredActorEvidence: readonly [
      "exact-controller-service-account",
      "exact-source-repository-and-path",
      "namespace-rbac-denial-matrix",
      "direct-pod-creation-denied",
    ];
  };
  accessClasses: Record<
    AwsDatabaseAccessClass,
    {
      namespace: string;
      serviceAccount: string;
      activationMode: "persistent" | "just-in-time";
      podIdentityAssociationId: string | null;
      bindingDigest: string;
      workloadBundleDigest: string;
      manifests: AwsDatabaseWorkloadManifest;
    }
  >;
  readiness: {
    state: "pending-application";
    reason: "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED";
    requiredEvidence: readonly string[];
  };
}

export function materializeAwsDatabaseInfrastructureHandoff(
  bindingId: string,
  access: AwsManagedPostgresAccessResult,
): pulumi.Output<AwsDatabaseInfrastructureHandoff> {
  if (!access.runtime.association || !access.migration.association) {
    throw new Error(
      `Database infrastructure handoff '${bindingId}' requires persistent runtime and migration Pod Identity associations.`,
    );
  }
  if (access.bootstrap.association) {
    throw new Error(
      `Database infrastructure handoff '${bindingId}' forbids a standing bootstrap Pod Identity association.`,
    );
  }
  return pulumi
    .output({
      runtime: resolvedHandoffAccessClass(access.runtime),
      migration: resolvedHandoffAccessClass(access.migration),
      bootstrap: resolvedHandoffAccessClass(access.bootstrap),
    })
    .apply((accessClasses): AwsDatabaseInfrastructureHandoff => {
      for (const [accessClass, resolved] of Object.entries(accessClasses)) {
        if (
          resolved.manifests.namespace.metadata.name !== resolved.namespace ||
          resolved.manifests.serviceAccount.metadata.namespace !==
            resolved.namespace ||
          resolved.manifests.serviceAccount.metadata.name !==
            resolved.serviceAccount
        ) {
          throw new Error(
            `Database infrastructure handoff '${bindingId}' ${accessClass} namespace/ServiceAccount substitution denied.`,
          );
        }
        if (
          resolved.manifests.requiredPodAnnotations[
            "security.deus.dev/workload-identity-binding-digest"
          ] !== resolved.bindingDigest
        ) {
          throw new Error(
            `Database infrastructure handoff '${bindingId}' ${accessClass} binding digest substitution denied.`,
          );
        }
        if (
          awsDatabaseAccessBindingDigest(resolved.manifests) !==
          resolved.workloadBundleDigest
        ) {
          throw new Error(
            `Database infrastructure handoff '${bindingId}' ${accessClass} bundle digest substitution denied.`,
          );
        }
      }
      const subject: Omit<
        AwsDatabaseInfrastructureHandoff,
        "handoffSpecDigest"
      > = {
        apiVersion:
          "infrastructure.deus.dev/aws-database-infrastructure-handoff/v1alpha1",
        kind: "AwsDatabaseInfrastructureHandoff",
        bindingId,
        owner: "external-iac",
        authorizedConsumer: "infrastructure-controller",
        applicationMutationAllowed: false,
        deploymentAuthorization: {
          state: "pending-identity-binding",
          directPodCreationAllowed: false,
          namespaceWriteAccess: "exclusive-controller",
          allowedWorkloadKinds: {
            runtime: ["Deployment"],
            migration: ["Job"],
            bootstrap: ["Job"],
          },
          requiredActorEvidence: [
            "exact-controller-service-account",
            "exact-source-repository-and-path",
            "namespace-rbac-denial-matrix",
            "direct-pod-creation-denied",
          ],
        },
        accessClasses,
        readiness: {
          state: "pending-application",
          reason: "DATABASE_ACCESS_BUNDLE_NOT_OBSERVED",
          requiredEvidence: [
            "namespace-observed",
            "service-account-observed",
            "admission-policy-enforced",
            "application-network-policy-enforced",
            "node-class-ready",
            "node-pool-ready",
            "pod-identity-association-observed",
            "deployment-authority-observed",
          ],
        },
      };
      const handoff = {
        ...subject,
        handoffSpecDigest: awsDatabaseAccessBindingDigest(subject),
      };
      parseAwsDatabaseInfrastructureHandoff(handoff);
      return handoff;
    });
}

function resolvedHandoffAccessClass(identity: AwsDatabaseAccessIdentityResult) {
  return {
    namespace: identity.namespace,
    serviceAccount: identity.serviceAccount,
    activationMode:
      identity.accessClass === "bootstrap"
        ? ("just-in-time" as const)
        : ("persistent" as const),
    podIdentityAssociationId: identity.association
      ? identity.association.associationId
      : null,
    bindingDigest: identity.bindingDigest,
    workloadBundleDigest: identity.workloadBundleDigest,
    manifests: identity.workloadManifest,
  };
}

export function createAwsManagedPostgresAccess(args: {
  organizationId: string;
  environment: ManagedPostgresEnvironment;
  clusterName: pulumi.Input<string>;
  clusterArn: pulumi.Input<string>;
  nodeRoleName: pulumi.Input<string>;
  podSubnetIds: pulumi.Input<string>[];
  binding: ManagedPostgresBinding;
  database: DatabaseResult;
  secretsManagerVpcEndpointId: pulumi.Input<string>;
  secretsManagerVpcEndpointSecurityGroupId: pulumi.Input<string>;
  iamRoleConstraint: AwsApplyLaneIamConstraint;
}): AwsManagedPostgresAccessResult {
  validateOrganizationId(args.organizationId);
  assertAwsApplyLaneIamConstraint(args.iamRoleConstraint, "database");
  if (!args.database.proxy || !args.database.proxyResourceId) {
    throw new Error(
      `Managed PostgreSQL access '${args.binding.id}' requires an end-to-end IAM RDS Proxy.`,
    );
  }
  const expectedRuntimeUser = awsManagedPostgresDatabaseUser(
    args.binding.access.runtimeIdentityId,
  );
  const expectedMigrationUser = awsManagedPostgresDatabaseUser(
    args.binding.access.migrationIdentityId,
  );
  if (
    args.database.runtimeDatabaseUser !== expectedRuntimeUser ||
    args.database.migrationDatabaseUser !== expectedMigrationUser
  ) {
    throw new Error(
      `Managed PostgreSQL access '${args.binding.id}' database users do not match its exact runtime and migration identities.`,
    );
  }
  createBootstrapSecretEndpointPath({
    bindingId: args.binding.id,
    bootstrapSecurityGroupId: args.database.bootstrapAccessSecurityGroup.id,
    endpointSecurityGroupId: args.secretsManagerVpcEndpointSecurityGroupId,
  });
  const runtimeNamespace = databaseAccessNamespace(
    args.binding.id,
    "runtime",
    args.environment,
  );
  const migrationNamespace = databaseAccessNamespace(
    args.binding.id,
    "migration",
    args.environment,
  );
  const bootstrapNamespace = databaseAccessNamespace(
    args.binding.id,
    "bootstrap",
    args.environment,
  );
  const partition = aws.getPartitionOutput({}).partition;
  const region = aws.getRegionOutput({}).name;
  const accountId = aws.getCallerIdentityOutput({}).accountId;
  const runtime = createIdentity({
    iamRoleConstraint: args.iamRoleConstraint,
    accessClass: "runtime",
    identityId: args.binding.access.runtimeIdentityId,
    namespace: runtimeNamespace,
    serviceAccount: dnsLabel(args.binding.access.runtimeIdentityId),
    organizationId: args.organizationId,
    clusterName: args.clusterName,
    clusterArn: args.clusterArn,
    nodeRoleName: args.nodeRoleName,
    podSubnetIds: args.podSubnetIds,
    bindingId: args.binding.id,
    networkEgress: [
      {
        domainName: args.database.proxy.endpoint,
        port: args.binding.database.port,
      },
    ],
    databaseUser: args.database.runtimeDatabaseUser,
    securityGroup: args.database.runtimeAccessSecurityGroup,
    policy: pulumi
      .all([partition, region, accountId, args.database.proxyResourceId])
      .apply(([resolvedPartition, resolvedRegion, resolvedAccount, proxyId]) =>
        JSON.stringify(
          compileAwsRdsProxyConnectPolicy({
            partition: exactPartition(resolvedPartition),
            region: resolvedRegion,
            accountId: resolvedAccount,
            proxyResourceId: proxyId,
            databaseUser: args.database.runtimeDatabaseUser,
            role: "runtime",
          }),
        ),
      ),
  });
  const migration = createIdentity({
    iamRoleConstraint: args.iamRoleConstraint,
    accessClass: "migration",
    identityId: args.binding.access.migrationIdentityId,
    namespace: migrationNamespace,
    serviceAccount: dnsLabel(args.binding.access.migrationIdentityId),
    organizationId: args.organizationId,
    clusterName: args.clusterName,
    clusterArn: args.clusterArn,
    nodeRoleName: args.nodeRoleName,
    podSubnetIds: args.podSubnetIds,
    bindingId: args.binding.id,
    networkEgress: [
      {
        domainName: args.database.proxy.endpoint,
        port: args.binding.database.port,
      },
    ],
    databaseUser: args.database.migrationDatabaseUser,
    securityGroup: args.database.migrationAccessSecurityGroup,
    policy: pulumi
      .all([partition, region, accountId, args.database.proxyResourceId])
      .apply(([resolvedPartition, resolvedRegion, resolvedAccount, proxyId]) =>
        JSON.stringify(
          compileAwsRdsProxyConnectPolicy({
            partition: exactPartition(resolvedPartition),
            region: resolvedRegion,
            accountId: resolvedAccount,
            proxyResourceId: proxyId,
            databaseUser: args.database.migrationDatabaseUser,
            role: "migration",
          }),
        ),
      ),
  });
  const bootstrap = createIdentity({
    iamRoleConstraint: args.iamRoleConstraint,
    accessClass: "bootstrap",
    identityId: `${args.binding.id}-bootstrap`,
    namespace: bootstrapNamespace,
    serviceAccount: dnsLabel(`postgres-bootstrap-${args.binding.id}`),
    organizationId: args.organizationId,
    clusterName: args.clusterName,
    clusterArn: args.clusterArn,
    nodeRoleName: args.nodeRoleName,
    podSubnetIds: args.podSubnetIds,
    bindingId: args.binding.id,
    networkEgress: [
      {
        domainName: args.database.cluster.endpoint,
        port: args.binding.database.port,
      },
      {
        domainName: pulumi
          .all([partition, region])
          .apply(([resolvedPartition, resolvedRegion]) =>
            secretsManagerHostname(
              exactPartition(resolvedPartition),
              resolvedRegion,
            ),
          ),
        port: 443,
      },
    ],
    createAssociation: false,
    securityGroup: args.database.bootstrapAccessSecurityGroup,
    policy: pulumi
      .all([
        partition,
        region,
        accountId,
        args.database.masterUserSecretArn,
        args.database.kmsKey.arn,
        args.secretsManagerVpcEndpointId,
      ])
      .apply(
        ([
          resolvedPartition,
          resolvedRegion,
          resolvedAccount,
          masterSecretArn,
          kmsKeyArn,
          endpointId,
        ]) =>
          JSON.stringify(
            compileAwsPostgresBootstrapSecretPolicy({
              partition: exactPartition(resolvedPartition),
              region: resolvedRegion,
              accountId: resolvedAccount,
              masterSecretArn,
              kmsKeyArn,
              secretsManagerVpcEndpointId: endpointId,
            }),
          ),
      ),
  });
  return { runtime, migration, bootstrap };
}

function createBootstrapSecretEndpointPath(args: {
  bindingId: string;
  bootstrapSecurityGroupId: pulumi.Input<string>;
  endpointSecurityGroupId: pulumi.Input<string>;
}) {
  const name = dnsLabel(`${args.bindingId}-bootstrap-to-secrets-manager`);
  new aws.vpc.SecurityGroupEgressRule(named(`${name}-egress`), {
    securityGroupId: args.bootstrapSecurityGroupId,
    referencedSecurityGroupId: args.endpointSecurityGroupId,
    ipProtocol: "tcp",
    fromPort: 443,
    toPort: 443,
    description: "Bootstrap identity to exact Secrets Manager VPC endpoint",
    tags: {
      ...baseTags,
      Name: named(`${name}-egress`),
      AccessClass: "bootstrap",
      Destination: "secrets-manager-vpc-endpoint",
    },
  });
  new aws.vpc.SecurityGroupIngressRule(named(`${name}-ingress`), {
    securityGroupId: args.endpointSecurityGroupId,
    referencedSecurityGroupId: args.bootstrapSecurityGroupId,
    ipProtocol: "tcp",
    fromPort: 443,
    toPort: 443,
    description: "Exact bootstrap identity to Secrets Manager VPC endpoint",
    tags: {
      ...baseTags,
      Name: named(`${name}-ingress`),
      AccessClass: "bootstrap",
      Source: "postgres-bootstrap-security-group",
    },
  });
}

export function compileAwsEksPodIdentityTrustPolicy(args: {
  organizationId: string;
  clusterArn: string;
  namespace: string;
  serviceAccount: string;
}) {
  validateOrganizationId(args.organizationId);
  const namespace = dnsLabel(args.namespace);
  const serviceAccount = dnsLabel(args.serviceAccount);
  if (namespace !== args.namespace || serviceAccount !== args.serviceAccount) {
    throw new Error(
      "EKS Pod Identity trust requires exact DNS-safe namespace and ServiceAccount names.",
    );
  }
  if (
    !/^arn:(?:aws|aws-us-gov|aws-cn):eks:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:cluster\/[A-Za-z0-9][A-Za-z0-9_-]{0,99}$/.test(
      args.clusterArn,
    )
  ) {
    throw new Error(
      "EKS Pod Identity trust requires one exact EKS cluster ARN.",
    );
  }
  return {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "TrustExactEksPodIdentity",
        Effect: "Allow",
        Principal: { Service: "pods.eks.amazonaws.com" },
        Action: ["sts:AssumeRole", "sts:TagSession"],
        Condition: {
          StringEquals: {
            "aws:SourceOrgId": args.organizationId,
            "aws:RequestTag/eks-cluster-arn": args.clusterArn,
            "aws:RequestTag/kubernetes-namespace": namespace,
            "aws:RequestTag/kubernetes-service-account": serviceAccount,
          },
        },
      },
    ],
  } as const;
}

function createIdentity(args: {
  iamRoleConstraint: AwsApplyLaneIamConstraint;
  accessClass: AwsDatabaseAccessClass;
  identityId: string;
  namespace: string;
  serviceAccount: string;
  bindingId: string;
  organizationId: string;
  clusterName: pulumi.Input<string>;
  clusterArn: pulumi.Input<string>;
  nodeRoleName: pulumi.Input<string>;
  podSubnetIds: pulumi.Input<string>[];
  networkEgress: ReadonlyArray<{
    domainName: pulumi.Input<string>;
    port: number;
  }>;
  databaseUser?: string;
  securityGroup: aws.ec2.SecurityGroup;
  policy: pulumi.Input<string>;
  createAssociation?: boolean;
}): AwsDatabaseAccessIdentityResult {
  const resourceName = dnsLabel(
    `${args.identityId}-${args.accessClass}-postgres-access`,
  );
  const nodePoolName = dnsLabel(`${args.bindingId}-${args.accessClass}-access`);
  const schedulingValue = dnsLabel(
    `${args.bindingId}-${args.accessClass}-database-access`,
  );
  const bindingLabels = {
    "security.deus.dev/workload-identity-binding": dnsLabel(args.identityId),
  };
  const schedulingLabel = awsDatabaseAccessReservationKey(
    args.bindingId,
    args.accessClass,
  );
  const taintKey = schedulingLabel;
  const allowedWorkloadKind =
    args.accessClass === "runtime" ? "Deployment" : "Job";
  const allowedPodOwnerKind =
    args.accessClass === "runtime" ? "ReplicaSet" : "Job";
  const requiredPodScheduling = {
    nodeSelector: { [schedulingLabel]: schedulingValue },
    tolerations: [
      {
        key: taintKey,
        operator: "Equal" as const,
        value: schedulingValue,
        effect: "NoSchedule" as const,
      },
    ],
  };
  const trustPolicy = pulumi.output(args.clusterArn).apply((clusterArn) =>
    JSON.stringify(
      compileAwsEksPodIdentityTrustPolicy({
        organizationId: args.organizationId,
        clusterArn,
        namespace: args.namespace,
        serviceAccount: args.serviceAccount,
      }),
    ),
  );
  const role = new aws.iam.Role(named(resourceName), {
    name: awsApplyLaneIamRoleName(args.iamRoleConstraint, resourceName),
    assumeRolePolicy: trustPolicy,
    maxSessionDuration: 3600,
    permissionsBoundary: args.iamRoleConstraint.permissionsBoundaryArn,
    tags: {
      ...tags(resourceName, args),
      InfrastructureActionSet: args.iamRoleConstraint.actionSet,
      BootstrapAccessSourceDigest: args.iamRoleConstraint.sourceDigest,
    },
  });
  const policy = new aws.iam.RolePolicy(named(`${resourceName}-policy`), {
    role: role.id,
    policy: args.policy,
  });
  const association =
    args.createAssociation === false
      ? undefined
      : new aws.eks.PodIdentityAssociation(
          named(`${resourceName}-association`),
          {
            clusterName: args.clusterName,
            namespace: args.namespace,
            serviceAccount: args.serviceAccount,
            roleArn: role.arn,
            disableSessionTags: false,
            tags: tags(`${resourceName}-association`, args),
          },
          { dependsOn: policy },
        );
  const resolvedPodSubnetIds = pulumi.all(args.podSubnetIds);
  const resolvedNetworkEgressDomains = pulumi.all(
    args.networkEgress.map(({ domainName }) => domainName),
  );
  const bindingDigest = pulumi
    .all({
      roleArn: role.arn,
      securityGroupId: args.securityGroup.id,
      clusterName: args.clusterName,
      clusterArn: args.clusterArn,
      nodeRoleName: args.nodeRoleName,
      podSubnetIds: resolvedPodSubnetIds,
      networkEgressDomains: resolvedNetworkEgressDomains,
      permissionPolicy: args.policy,
      resolvedTrustPolicy: trustPolicy,
    })
    .apply(
      ({
        roleArn,
        securityGroupId,
        clusterName,
        clusterArn,
        nodeRoleName,
        podSubnetIds,
        networkEgressDomains,
        permissionPolicy,
        resolvedTrustPolicy,
      }) => {
        if (
          !Array.isArray(networkEgressDomains) ||
          typeof permissionPolicy !== "string" ||
          typeof resolvedTrustPolicy !== "string"
        ) {
          throw new Error(
            "AWS database access binding requires resolved policy documents and egress domains.",
          );
        }
        return awsDatabaseAccessBindingDigest({
          apiVersion:
            "infrastructure.deus.dev/aws-database-access-binding/v1alpha1",
          identity: {
            accessClass: args.accessClass,
            identityId: args.identityId,
            namespace: args.namespace,
            serviceAccount: args.serviceAccount,
            roleArn,
          },
          cloud: {
            securityGroupId,
            clusterName,
            clusterArn,
            nodeRoleName,
            podSubnetIds: [...podSubnetIds].sort(),
          },
          iam: {
            trustPolicy: JSON.parse(resolvedTrustPolicy),
            permissionPolicy: JSON.parse(permissionPolicy),
            podIdentityAssociation:
              args.createAssociation === false
                ? {
                    state: "absent",
                    activationMode: "just-in-time",
                    clusterName,
                    namespace: args.namespace,
                    serviceAccount: args.serviceAccount,
                    roleArn,
                  }
                : {
                    state: "present",
                    activationMode: "persistent",
                    clusterName,
                    namespace: args.namespace,
                    serviceAccount: args.serviceAccount,
                    roleArn,
                    disableSessionTags: false,
                  },
          },
          enforcement: {
            namespace: {
              name: args.namespace,
              labels: {
                "pod-security.kubernetes.io/enforce": "restricted",
                "pod-security.kubernetes.io/audit": "restricted",
                "pod-security.kubernetes.io/warn": "restricted",
                "security.deus.dev/service-account-token-policy": "restricted",
                "security.deus.dev/database-access-binding": args.bindingId,
                "security.deus.dev/database-access-class": args.accessClass,
              },
            },
            serviceAccount: {
              automountServiceAccountToken: false,
              labels: bindingLabels,
            },
            admissionPolicy: {
              apiVersion: "kyverno.io/v1",
              failurePolicy: "Fail",
              validationFailureAction: "Enforce",
              namespace: args.namespace,
              serviceAccountName: args.serviceAccount,
              labels: bindingLabels,
              bindingDigest: "<computed-binding-digest>",
              requiredPodScheduling,
              allowedWorkloadKind,
              allowedPodOwnerKind,
              directPodCreationAllowed: false,
              nodePoolReservation: {
                selectorLabel: schedulingLabel,
                nodePoolName,
                namespace: args.namespace,
              },
              denialCodes: [
                "SEC_DATABASE_ACCESS_BINDING_DENIED",
                "SEC_DATABASE_NODE_POOL_RESERVED",
                "SEC_DATABASE_POD_OWNER_DENIED",
                "SEC_DATABASE_WORKLOAD_KIND_DENIED",
              ],
            },
            applicationNetworkPolicy: {
              apiVersion: "networking.k8s.aws/v1alpha1",
              policyTypes: ["Ingress", "Egress"],
              ingress: [],
              podIdentityAgent: {
                cidr: "169.254.170.23/32",
                protocol: "TCP",
                port: 80,
              },
              networkEgress: networkEgressDomains
                .map((domainName, index) => ({
                  domainName,
                  port: args.networkEgress[index].port,
                }))
                .sort(networkEgressOrder),
            },
            nodeClass: {
              apiVersion: "eks.amazonaws.com/v1",
              name: nodePoolName,
              podSecurityGroupId: securityGroupId,
              snatPolicy: "Disabled",
              networkPolicy: "DefaultDeny",
              networkPolicyEventLogs: "Enabled",
              associatePublicIPAddress: false,
            },
            nodePool: {
              apiVersion: "karpenter.sh/v1",
              name: nodePoolName,
              architecture: "amd64",
              capacityType: "on-demand",
              expireAfter: "336h",
              cpuLimit: "64",
              memoryLimit: "256Gi",
              consolidationPolicy: "WhenEmptyOrUnderutilized",
              consolidateAfter: "5m",
            },
            requiredPodScheduling,
          },
        });
      },
    );
  const workloadManifest = pulumi
    .all([
      role.arn,
      args.securityGroup.id,
      bindingDigest,
      args.clusterName,
      args.clusterArn,
      args.nodeRoleName,
      resolvedPodSubnetIds,
      resolvedNetworkEgressDomains,
    ])
    .apply(
      ([
        roleArn,
        securityGroupId,
        digest,
        clusterName,
        _clusterArn,
        nodeRoleName,
        podSubnetIds,
        networkEgressDomains,
      ]): AwsDatabaseWorkloadManifest => {
        const requiredPodAnnotations = {
          "security.deus.dev/workload-identity-mode": "eks-pod-identity",
          "security.deus.dev/workload-identity-audience":
            "pods.eks.amazonaws.com",
          "security.deus.dev/workload-identity-binding-digest": digest,
        } as const;
        const networkEgress = networkEgressDomains
          .map((domainName, index) => ({
            domainName,
            port: args.networkEgress[index].port,
          }))
          .sort(networkEgressOrder);
        return {
          namespace: {
            apiVersion: "v1",
            kind: "Namespace",
            metadata: {
              name: args.namespace,
              labels: {
                "pod-security.kubernetes.io/enforce": "restricted",
                "pod-security.kubernetes.io/audit": "restricted",
                "pod-security.kubernetes.io/warn": "restricted",
                "security.deus.dev/service-account-token-policy": "restricted",
                "security.deus.dev/database-access-binding": args.bindingId,
                "security.deus.dev/database-access-class": args.accessClass,
              },
            },
          },
          serviceAccount: {
            apiVersion: "v1",
            kind: "ServiceAccount",
            metadata: {
              name: args.serviceAccount,
              namespace: args.namespace,
              labels: bindingLabels,
              annotations: {
                ...requiredPodAnnotations,
                "security.deus.dev/cloud-identity-provider": "aws",
                "security.deus.dev/cloud-role-reference": roleArn,
              },
            },
            automountServiceAccountToken: false,
          },
          admissionPolicy: compileAwsDatabaseAdmissionPolicy({
            bindingId: args.bindingId,
            accessClass: args.accessClass,
            namespace: args.namespace,
            serviceAccount: args.serviceAccount,
            bindingLabels,
            requiredPodAnnotations,
            requiredPodScheduling,
          }),
          applicationNetworkPolicy: {
            apiVersion: "networking.k8s.aws/v1alpha1",
            kind: "ApplicationNetworkPolicy",
            metadata: {
              name: nodePoolName,
              namespace: args.namespace,
            },
            spec: {
              podSelector: { matchLabels: bindingLabels },
              policyTypes: ["Ingress", "Egress"],
              ingress: [],
              egress: [
                {
                  to: [{ ipBlock: { cidr: "169.254.170.23/32" } }],
                  ports: [{ protocol: "TCP", port: 80 }],
                },
                ...networkEgress.map(({ domainName, port }) => ({
                  to: [{ domainNames: [domainName] }],
                  ports: [{ protocol: "TCP" as const, port }],
                })),
              ],
            },
          },
          nodeClass: {
            apiVersion: "eks.amazonaws.com/v1",
            kind: "NodeClass",
            metadata: { name: nodePoolName },
            spec: {
              role: nodeRoleName,
              subnetSelectorTerms: [...podSubnetIds]
                .sort()
                .map((id) => ({ id })),
              securityGroupSelectorTerms: [
                {
                  tags: {
                    "aws:eks:cluster-name": clusterName,
                  },
                },
              ],
              podSubnetSelectorTerms: [...podSubnetIds]
                .sort()
                .map((id) => ({ id })),
              podSecurityGroupSelectorTerms: [{ id: securityGroupId }],
              snatPolicy: "Disabled",
              networkPolicy: "DefaultDeny",
              networkPolicyEventLogs: "Enabled",
              advancedNetworking: { associatePublicIPAddress: false },
            },
          },
          nodePool: {
            apiVersion: "karpenter.sh/v1",
            kind: "NodePool",
            metadata: { name: nodePoolName },
            spec: {
              template: {
                metadata: {
                  labels: { [schedulingLabel]: schedulingValue },
                },
                spec: {
                  nodeClassRef: {
                    group: "eks.amazonaws.com",
                    kind: "NodeClass",
                    name: nodePoolName,
                  },
                  taints: [
                    {
                      key: taintKey,
                      value: schedulingValue,
                      effect: "NoSchedule",
                    },
                  ],
                  requirements: [
                    {
                      key: "kubernetes.io/arch",
                      operator: "In",
                      values: ["amd64"],
                    },
                    {
                      key: "karpenter.sh/capacity-type",
                      operator: "In",
                      values: ["on-demand"],
                    },
                  ],
                  expireAfter: "336h",
                },
              },
              limits: { cpu: "64", memory: "256Gi" },
              disruption: {
                consolidationPolicy: "WhenEmptyOrUnderutilized",
                consolidateAfter: "5m",
              },
            },
          },
          requiredPodLabels: bindingLabels,
          requiredPodScheduling,
          requiredPodAnnotations,
        };
      },
    );
  const workloadBundleDigest = workloadManifest.apply((manifest) =>
    awsDatabaseAccessBindingDigest(manifest),
  );
  return {
    accessClass: args.accessClass,
    namespace: args.namespace,
    serviceAccount: args.serviceAccount,
    ...(args.databaseUser ? { databaseUser: args.databaseUser } : {}),
    role,
    policy,
    association,
    securityGroup: args.securityGroup,
    bindingDigest,
    workloadBundleDigest,
    workloadManifest,
  };
}

function databaseAccessNamespace(
  bindingId: string,
  accessClass: AwsDatabaseAccessClass,
  environment: ManagedPostgresEnvironment,
) {
  return dnsLabel(`codefly-db-${accessClass}-${bindingId}-${environment}`);
}

function validateOrganizationId(value: string) {
  if (!/^o-[a-z0-9]{10,32}$/.test(value)) {
    throw new Error(
      "Managed PostgreSQL Pod Identity requires one exact AWS Organizations ID.",
    );
  }
}

function exactPartition(value: string): "aws" | "aws-us-gov" | "aws-cn" {
  if (value === "aws" || value === "aws-us-gov" || value === "aws-cn") {
    return value;
  }
  throw new Error(`Unsupported AWS partition '${value}'.`);
}

function secretsManagerHostname(
  partition: "aws" | "aws-us-gov" | "aws-cn",
  region: string,
): string {
  const dnsSuffix =
    partition === "aws-cn" ? "amazonaws.com.cn" : "amazonaws.com";
  return `secretsmanager.${region}.${dnsSuffix}`;
}

function networkEgressOrder(
  left: { domainName: string; port: number },
  right: { domainName: string; port: number },
) {
  return (
    left.domainName.localeCompare(right.domainName) || left.port - right.port
  );
}

function dnsLabel(value: string): string {
  const result = value
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  if (!result || result.length > 63) {
    throw new Error(`'${value}' cannot become one exact Kubernetes DNS label.`);
  }
  return result;
}

function tags(
  name: string,
  args: Pick<
    Parameters<typeof createIdentity>[0],
    "accessClass" | "identityId" | "namespace" | "serviceAccount"
  >,
) {
  return {
    ...baseTags,
    Name: name,
    AccessClass: args.accessClass,
    SemanticIdentityId: args.identityId,
    KubernetesNamespace: args.namespace,
    KubernetesServiceAccount: args.serviceAccount,
  };
}

export function awsDatabaseAccessBindingDigest(value: unknown): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}
