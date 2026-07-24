import { createEksCluster } from "../eks";
import { createE2bByocAccess } from "../e2bByoc";
import { createDatabaseCluster } from "../database";
import { createAwsManagedPostgresAccess } from "../databaseAccess";
import { createCentralizedEgressNetwork } from "../network";
import { createAccountSecurityBaseline } from "../security";
import {
  E2bByocAccessConfig,
  DatabaseConfig,
  EksConfig,
  NetworkConfig,
  SecurityConfig,
} from "../config";
import {
  awsWorkloadProviderExtensionsFromConfig,
  compileAwsNetworkBlueprint,
  compileAwsDatabases,
  compileAwsWorkloads,
  validateAndCompileAwsNetwork,
  type AwsApplyLaneIamConstraint,
} from "../adapters/aws";
import {
  assertManagedPostgresIntent,
  type ManagedPostgresIntent,
  type PlatformBlueprint,
} from "../core";
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

export function createWorkloadStack(args: {
  networkConfig: NetworkConfig;
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
  if (
    args.platformBlueprint?.dataBoundaries.some((boundary) =>
      boundary.services.includes("relational"),
    ) &&
    !args.databaseConfig
  ) {
    throw new Error(
      "AWS single-account workload stack requires database configuration for relational data intent.",
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

  const plan = args.platformBlueprint
    ? compileAwsNetworkBlueprint(args.platformBlueprint, {
        shareTransitGatewayWithOrganization:
          args.networkConfig.egress.shareTransitGatewayWithOrganization ??
          false,
        createEksByZoneId: {},
        spokeKindByZoneId: {},
      })
    : validateAndCompileAwsNetwork(args.networkConfig, {
        name: "single-account-network",
        environment: "deployment",
        requireInspectedEgress:
          args.networkConfig.egress.networkFirewallEnabled,
      });
  const network = createCentralizedEgressNetwork(plan.networkConfig);
  const e2bConfig = args.e2bByocAccessConfig ?? disabledE2bConfig();
  const workloadPlan = args.platformBlueprint
    ? compileAwsWorkloads(
        args.platformBlueprint,
        awsWorkloadProviderExtensionsFromConfig(args.eksConfig, e2bConfig),
      )
    : undefined;
  const eksSpokeNames = workloadPlan
    ? new Set(
        workloadPlan.planes
          .filter((plane) => plane.deploymentKind.startsWith("private-eks"))
          .map((plane) => plan.zoneToSpokeName[plane.zoneId]),
      )
    : undefined;

  const clusterResources = Object.fromEntries(
    plan.networkConfig.spokes
      .filter((spoke) =>
        eksSpokeNames ? eksSpokeNames.has(spoke.name) : spoke.createEks,
      )
      .map((spoke) => {
        const spokeNetwork = network.spokes[spoke.name];
        const cluster = createEksCluster(spokeNetwork, args.eksConfig);
        return [spoke.name, cluster] as const;
      }),
  );
  const clusters = Object.fromEntries(
    Object.entries(clusterResources).map(([name, cluster]) => [
      name,
      {
        name: cluster.cluster.name,
        endpoint: cluster.cluster.endpoint,
        certificateAuthority: cluster.cluster.certificateAuthority,
        nodeRoleArn: cluster.nodeRole.arn,
      },
    ]),
  );
  const e2bByoc = workloadPlan?.planes.some(
    (plane) => plane.deploymentKind === "e2b-byoc",
  )
    ? createE2bByocAccess(e2bConfig)
    : undefined;

  const databasePlans = args.platformBlueprint
    ? args.databaseConfig
      ? compileAwsDatabases(args.platformBlueprint, {
          engine: args.databaseConfig.engine,
          engineVersion: args.databaseConfig.engineVersion,
          instanceClass: args.databaseConfig.instanceClass,
          instanceCount: args.databaseConfig.instanceCount,
          backupRetentionDays: args.databaseConfig.backupRetentionDays,
          continuousPointInTimeRecovery: true,
          replicaRegion: args.databaseConfig.replicaRegion,
        }).databases
      : []
    : [];
  const databases = Object.fromEntries(
    databasePlans.map((databasePlan) => {
      const spokeName = plan.zoneToSpokeName[databasePlan.zoneId];
      const spoke = network.spokes[spokeName];
      if (!spoke || !args.databaseConfig) {
        throw new Error(
          `AWS relational boundary '${databasePlan.boundaryId}' has no compiled spoke or database configuration.`,
        );
      }
      const binding = args.managedPostgresIntent
        ? managedPostgresBindingForBoundary(
            args.managedPostgresIntent,
            databasePlan.boundaryId,
          )
        : undefined;
      const overrides = binding
        ? managedPostgresDatabaseOverrides(binding)
        : undefined;
      return [
        databasePlan.boundaryId,
        createDatabaseCluster({
          iamRoleConstraint: requiredDataIamConstraint(args.iamRoleConstraint),
          config: {
            ...args.databaseConfig,
            name: `${args.databaseConfig.name}-${databasePlan.boundaryId}`,
            databaseName:
              overrides?.databaseName ?? args.databaseConfig.databaseName,
          },
          plan: databasePlan,
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
      databasePlans,
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
    ? Object.fromEntries(
        databasePlans
          .map((databasePlan) => {
            const database = databases[databasePlan.boundaryId];
            const spokeName = plan.zoneToSpokeName[databasePlan.zoneId];
            const cluster = clusterResources[spokeName];
            const spoke = network.spokes[spokeName];
            const binding = managedPostgresBindingForBoundary(
              args.managedPostgresIntent!,
              databasePlan.boundaryId,
            );
            if (!cluster || !args.awsOrganizationId) {
              throw new Error(
                `Managed PostgreSQL access '${binding.id}' requires an EKS cluster and exact AWS Organizations ID in its spoke.`,
              );
            }
            return [
              binding.id,
              createAwsManagedPostgresAccess({
                iamRoleConstraint: requiredDataIamConstraint(
                  args.iamRoleConstraint,
                ),
                organizationId: args.awsOrganizationId,
                environment: args.managedPostgresIntent!.environment,
                clusterName: cluster.cluster.name,
                clusterArn: cluster.cluster.arn,
                nodeRoleName: cluster.nodeRole.name,
                podSubnetIds: spoke.privateSubnets.map((subnet) => subnet.id),
                binding,
                database,
                secretsManagerVpcEndpointId:
                  spoke.interfaceEndpoints.secretsmanager.id,
                secretsManagerVpcEndpointSecurityGroupId:
                  spoke.secretsManagerEndpointSecurityGroup.id,
              }),
            ] as const;
          })
          .sort(([left], [right]) => left.localeCompare(right)),
      )
    : {};

  return {
    network,
    clusters,
    e2bByoc,
    workloadPlan,
    managedPostgresPlan,
    databasePlans,
    databases,
    databaseBindings,
    databaseMigrationBindings,
    databaseBootstrapBindings,
    databaseAccess,
  };
}

function disabledE2bConfig(): E2bByocAccessConfig {
  return {
    createVendorRole: false,
    vendorPrincipalArns: [],
    managedPolicyArns: [],
  };
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
