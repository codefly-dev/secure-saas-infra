import * as pulumi from "@pulumi/pulumi";
import { createAwsManagedPostgresAccess } from "../databaseAccess";
import { createEksCluster } from "../eks";
import { createE2bByocAccess } from "../e2bByoc";
import { createDatabaseCluster } from "../database";
import { createDetachedSpokeNetwork } from "../network";
import { createAccountSecurityBaseline } from "../security";
import {
  E2bByocAccessConfig,
  DatabaseConfig,
  EksConfig,
  SecurityConfig,
  SpokeStackConfig,
} from "../config";
import {
  assertManagedPostgresIntent,
  type ManagedPostgresIntent,
  type PlatformBlueprint,
} from "../core";
import {
  awsWorkloadProviderExtensionsFromConfig,
  compileAwsNetworkBlueprint,
  compileAwsDatabases,
  compileAwsWorkloads,
  requireAwsSpokePlan,
  type AwsApplyLaneIamConstraint,
} from "../adapters/aws";
import {
  managedPostgresBindingForBoundary,
  managedPostgresDatabaseOverrides,
  materializeManagedPostgresBootstrapBindingOutputs,
  materializeManagedPostgresBindingOutputs,
  materializeManagedPostgresMigrationBindingOutputs,
  assertAwsManagedPostgresMaterialization,
  assertManagedPostgresPlanMatchesDatabases,
  compileManagedPostgresMaterializationPlan,
} from "./databaseBindings";

export function createSpokeClusterStack(args: {
  spokeConfig: SpokeStackConfig;
  eksConfig: EksConfig;
  securityConfig: SecurityConfig;
  platformBlueprint?: PlatformBlueprint;
  e2bByocAccessConfig?: E2bByocAccessConfig;
  databaseConfig?: DatabaseConfig;
  managedPostgresIntent?: ManagedPostgresIntent;
  awsOrganizationId?: string;
  awsAccountId?: string;
  awsRegion?: string;
  iamRoleConstraint?: AwsApplyLaneIamConstraint;
}) {
  if (args.managedPostgresIntent && args.platformBlueprint) {
    assertManagedPostgresIntent(
      args.managedPostgresIntent,
      args.platformBlueprint,
    );
  }
  if (args.managedPostgresIntent) {
    if (
      !args.databaseConfig ||
      !args.platformBlueprint ||
      !args.awsAccountId ||
      !args.awsRegion
    ) {
      throw new Error(
        "AWS Managed Postgres materialization requires exact database, blueprint, account, and region configuration.",
      );
    }
    assertAwsManagedPostgresMaterialization(
      args.managedPostgresIntent.bindings,
      args.databaseConfig,
    );
  }
  const managedPostgresPlan = args.managedPostgresIntent
    ? compileManagedPostgresMaterializationPlan({
        intent: args.managedPostgresIntent,
        blueprint: args.platformBlueprint!,
        config: args.databaseConfig!,
        accountId: args.awsAccountId!,
        region: args.awsRegion!,
      })
    : undefined;
  createAccountSecurityBaseline(args.securityConfig);

  const transitGatewayId =
    args.spokeConfig.transitGatewayId ??
    new pulumi.StackReference("network-hub", {
      name: args.spokeConfig.networkStackRef,
    }).requireOutput("transitGatewayId");

  const compiled = args.platformBlueprint
    ? compileSpokeIntent(args.platformBlueprint, args)
    : undefined;
  const spokeIntent = compiled?.spoke ?? {
    name: args.spokeConfig.name,
    kind: args.spokeConfig.kind,
    cidr: args.spokeConfig.cidr,
    availabilityZoneCount: args.spokeConfig.azCount,
    zoneId: args.spokeConfig.zoneId ?? `zone:${args.spokeConfig.name}`,
    networkDomainId:
      args.spokeConfig.networkDomainId ?? `network:${args.spokeConfig.name}`,
  };

  const spoke = createDetachedSpokeNetwork({
    name: spokeIntent.name,
    kind: spokeIntent.kind,
    cidr: spokeIntent.cidr,
    createEks: compiled
      ? compiled.workload?.deploymentKind !== "e2b-byoc" &&
        compiled.workload !== undefined
      : args.spokeConfig.createEks,
    azCount: spokeIntent.availabilityZoneCount,
    transitGatewayId,
  });

  const createEks = compiled
    ? compiled.workload?.deploymentKind === "private-eks" ||
      compiled.workload?.deploymentKind === "private-eks-microvm"
    : args.spokeConfig.createEks;
  const cluster = createEks
    ? createEksCluster(spoke, args.eksConfig)
    : undefined;
  const e2bByoc =
    compiled?.workload?.deploymentKind === "e2b-byoc"
      ? createE2bByocAccess(requiredE2bConfig(args.e2bByocAccessConfig))
      : undefined;
  const clusters = cluster
    ? {
        [spokeIntent.name]: {
          name: cluster.cluster.name,
          endpoint: cluster.cluster.endpoint,
          certificateAuthority: cluster.cluster.certificateAuthority,
          nodeRoleArn: cluster.nodeRole.arn,
        },
      }
    : {};
  const databases = Object.fromEntries(
    (compiled?.databases ?? []).map((plan) => {
      const config = requiredDatabaseConfig(
        args.databaseConfig,
        plan.boundaryId,
      );
      const binding = args.managedPostgresIntent
        ? managedPostgresBindingForBoundary(
            args.managedPostgresIntent,
            plan.boundaryId,
          )
        : undefined;
      const overrides = binding
        ? managedPostgresDatabaseOverrides(binding)
        : undefined;
      return [
        plan.boundaryId,
        createDatabaseCluster({
          iamRoleConstraint: requiredDataIamConstraint(args.iamRoleConstraint),
          config: {
            ...config,
            name: `${config.name}-${plan.boundaryId}`,
            databaseName: overrides?.databaseName ?? config.databaseName,
          },
          plan,
          vpcId: spoke.vpc.id,
          privateSubnetIds: spoke.privateSubnets.map((subnet) => subnet.id),
          accessBoundaryIds: overrides?.accessBoundaryIds,
          databaseIdentityUsers: overrides?.databaseIdentityUsers,
        }),
      ];
    }),
  );
  if (managedPostgresPlan) {
    assertManagedPostgresPlanMatchesDatabases(
      managedPostgresPlan,
      compiled?.databases ?? [],
    );
  }
  const databaseBindings = args.managedPostgresIntent
    ? materializeManagedPostgresBindingOutputs(
        args.managedPostgresIntent,
        managedPostgresPlan!,
        databases,
      )
    : {};
  const databaseBootstrapBindings = args.managedPostgresIntent
    ? materializeManagedPostgresBootstrapBindingOutputs(
        args.managedPostgresIntent,
        managedPostgresPlan!,
        databases,
      )
    : {};
  const databaseMigrationBindings = args.managedPostgresIntent
    ? materializeManagedPostgresMigrationBindingOutputs(
        args.managedPostgresIntent,
        managedPostgresPlan!,
        databases,
      )
    : {};
  const databaseAccess = args.managedPostgresIntent
    ? materializeDatabaseAccess({
        intent: args.managedPostgresIntent,
        databases,
        cluster,
        podSubnetIds: spoke.privateSubnets.map((subnet) => subnet.id),
        organizationId: args.awsOrganizationId,
        iamRoleConstraint: args.iamRoleConstraint,
        secretsManagerVpcEndpointId: spoke.interfaceEndpoints.secretsmanager.id,
        secretsManagerVpcEndpointSecurityGroupId:
          spoke.secretsManagerEndpointSecurityGroup.id,
      })
    : {};

  return {
    spoke,
    clusters,
    e2bByoc,
    semanticIds: {
      zoneId: spokeIntent.zoneId,
      networkDomainId: spokeIntent.networkDomainId,
    },
    workloadPlan: compiled?.workload,
    managedPostgresPlan,
    databasePlans: compiled?.databases ?? [],
    databases,
    databaseBindings,
    databaseMigrationBindings,
    databaseBootstrapBindings,
    databaseAccess,
  };
}

function materializeDatabaseAccess(args: {
  intent: ManagedPostgresIntent;
  databases: Readonly<Record<string, ReturnType<typeof createDatabaseCluster>>>;
  cluster: ReturnType<typeof createEksCluster> | undefined;
  podSubnetIds: pulumi.Input<string>[];
  organizationId: string | undefined;
  iamRoleConstraint: AwsApplyLaneIamConstraint | undefined;
  secretsManagerVpcEndpointId: pulumi.Input<string>;
  secretsManagerVpcEndpointSecurityGroupId: pulumi.Input<string>;
}) {
  if (!args.cluster || !args.organizationId) {
    throw new Error(
      "Managed PostgreSQL access requires an EKS cluster and exact AWS Organizations ID in the same platform stack.",
    );
  }
  return Object.fromEntries(
    Object.entries(args.databases)
      .map(([boundaryId, database]) => {
        const binding = managedPostgresBindingForBoundary(
          args.intent,
          boundaryId,
        );
        return [
          binding.id,
          createAwsManagedPostgresAccess({
            iamRoleConstraint: requiredDataIamConstraint(
              args.iamRoleConstraint,
            ),
            organizationId: args.organizationId!,
            environment: args.intent.environment,
            clusterName: args.cluster!.cluster.name,
            clusterArn: args.cluster!.cluster.arn,
            nodeRoleName: args.cluster!.nodeRole.name,
            podSubnetIds: args.podSubnetIds,
            binding,
            database,
            secretsManagerVpcEndpointId: args.secretsManagerVpcEndpointId,
            secretsManagerVpcEndpointSecurityGroupId:
              args.secretsManagerVpcEndpointSecurityGroupId,
          }),
        ] as const;
      })
      .sort(([left], [right]) => left.localeCompare(right)),
  );
}

function requiredDataIamConstraint(
  value: AwsApplyLaneIamConstraint | undefined,
): AwsApplyLaneIamConstraint {
  if (!value) {
    throw new Error(
      "AWS relational infrastructure requires the compiled database apply-lane IAM constraint.",
    );
  }
  return value;
}

function compileSpokeIntent(
  blueprint: PlatformBlueprint,
  args: {
    spokeConfig: SpokeStackConfig;
    eksConfig: EksConfig;
    e2bByocAccessConfig?: E2bByocAccessConfig;
    databaseConfig?: DatabaseConfig;
  },
) {
  const zoneId = requiredSemanticId(args.spokeConfig.zoneId, "spoke.zoneId");
  const networkDomainId = requiredSemanticId(
    args.spokeConfig.networkDomainId,
    "spoke.networkDomainId",
  );
  const network = compileAwsNetworkBlueprint(blueprint, {
    shareTransitGatewayWithOrganization: false,
    createEksByZoneId: {},
    spokeKindByZoneId: {},
  });
  const spoke = requireAwsSpokePlan(network, zoneId, networkDomainId);
  if (spoke.kind !== args.spokeConfig.kind) {
    throw new Error(
      `AWS spoke '${networkDomainId}' compiles kind '${spoke.kind}', not configured stack kind '${args.spokeConfig.kind}'.`,
    );
  }
  const hasWorkloadInZone = blueprint.workloadPlanes.some(
    (plane) => plane.zoneId === zoneId,
  );
  const matching = hasWorkloadInZone
    ? compileAwsWorkloads(
        blueprint,
        awsWorkloadProviderExtensionsFromConfig(
          args.eksConfig,
          args.e2bByocAccessConfig ?? disabledE2bConfig(),
        ),
      ).planes.filter((plane) => plane.zoneId === zoneId)
    : [];
  if (matching.length > 1) {
    throw new Error(
      `AWS spoke zone '${zoneId}' has multiple workload planes; use a separate spoke boundary per plane.`,
    );
  }
  const databases = args.databaseConfig
    ? compileAwsDatabases(blueprint, {
        engine: args.databaseConfig.engine,
        engineVersion: args.databaseConfig.engineVersion,
        instanceClass: args.databaseConfig.instanceClass,
        instanceCount: args.databaseConfig.instanceCount,
        backupRetentionDays: args.databaseConfig.backupRetentionDays,
        continuousPointInTimeRecovery: true,
        replicaRegion: args.databaseConfig.replicaRegion,
      }).databases.filter((database) => database.zoneId === zoneId)
    : [];
  const relationalBoundaries = blueprint.dataBoundaries.filter(
    (boundary) =>
      boundary.zoneId === zoneId && boundary.services.includes("relational"),
  );
  if (relationalBoundaries.length > 0 && !args.databaseConfig) {
    throw new Error(
      `AWS spoke zone '${zoneId}' declares relational data but has no database configuration.`,
    );
  }
  if (matching.length === 0 && databases.length === 0) {
    throw new Error(
      `AWS spoke zone '${zoneId}' has no workload or relational data plane in the platform blueprint.`,
    );
  }
  return { spoke, workload: matching[0], databases };
}

function requiredDatabaseConfig(
  config: DatabaseConfig | undefined,
  boundaryId: string,
) {
  if (!config) {
    throw new Error(
      `Database configuration is required for relational boundary '${boundaryId}'.`,
    );
  }
  return config;
}

function requiredSemanticId(value: string | undefined, label: string) {
  if (!value) {
    throw new Error(
      `${label} is required when platformBlueprint drives a detached spoke stack.`,
    );
  }
  return value;
}

function requiredE2bConfig(
  config: E2bByocAccessConfig | undefined,
): E2bByocAccessConfig {
  if (!config) {
    throw new Error(
      "e2bByocAccess configuration is required for an E2B workload plan.",
    );
  }
  return config;
}

function disabledE2bConfig(): E2bByocAccessConfig {
  return {
    createVendorRole: false,
    vendorPrincipalArns: [],
    managedPolicyArns: [],
  };
}
