import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { DatabaseConfig, baseTags, named } from "./config";
import {
  assertAwsApplyLaneIamConstraint,
  awsApplyLaneIamRoleName,
  type AwsApplyLaneIamConstraint,
  type AwsDatabasePlan,
} from "./adapters/aws";

export interface DatabaseResult {
  cluster: aws.rds.Cluster;
  instances: aws.rds.ClusterInstance[];
  kmsKey: aws.kms.Key;
  parameterGroup: aws.rds.ClusterParameterGroup;
  subnetGroup: aws.rds.SubnetGroup;
  securityGroup: aws.ec2.SecurityGroup;
  runtimeAccessSecurityGroup: aws.ec2.SecurityGroup;
  migrationAccessSecurityGroup: aws.ec2.SecurityGroup;
  bootstrapAccessSecurityGroup: aws.ec2.SecurityGroup;
  proxySecurityGroup?: aws.ec2.SecurityGroup;
  proxy?: aws.rds.Proxy;
  proxyResourceId?: pulumi.Output<string>;
  proxyEndpoint?: aws.rds.ProxyDefaultTargetGroup;
  monitoringRole?: aws.iam.Role;
  runtimeDatabaseUser: string;
  migrationDatabaseUser: string;
  caCertIdentifier: string;
  masterUserSecretArn: pulumi.Output<string>;
}

export function createDatabaseCluster(args: {
  config: DatabaseConfig;
  vpcId: pulumi.Input<string>;
  privateSubnetIds: pulumi.Input<pulumi.Input<string>[]>;
  plan?: AwsDatabasePlan;
  accessBoundaryIds?: {
    runtime: string;
    migration: string;
    bootstrap?: string;
  };
  databaseIdentityUsers?: {
    runtime: string;
    migration: string;
  };
  iamRoleConstraint: AwsApplyLaneIamConstraint;
}): DatabaseResult {
  const { config, vpcId, privateSubnetIds, plan } = args;
  assertAwsApplyLaneIamConstraint(args.iamRoleConstraint, "database");
  const caCertIdentifier = "rds-ca-rsa4096-g1";
  assertDatabasePlanCompatibility(config, plan);
  const accessBoundaryIds = args.accessBoundaryIds ?? {
    runtime: `${config.name}-runtime-db-access`,
    migration: `${config.name}-migration-db-access`,
    bootstrap: `${config.name}-bootstrap-db-access`,
  };
  const bootstrapBoundaryId =
    accessBoundaryIds.bootstrap ?? `${config.name}-bootstrap-db-access`;
  if (
    !accessBoundaryIds.runtime ||
    !accessBoundaryIds.migration ||
    !bootstrapBoundaryId ||
    new Set([
      accessBoundaryIds.runtime,
      accessBoundaryIds.migration,
      bootstrapBoundaryId,
    ]).size !== 3
  ) {
    throw new Error(
      "Database runtime and migration access boundaries must be explicit and separate.",
    );
  }
  const databaseIdentityUsers = args.databaseIdentityUsers ?? {
    runtime: databaseIdentityUser(`${config.name}-runtime`),
    migration: databaseIdentityUser(`${config.name}-migration`),
  };
  if (
    databaseIdentityUsers.runtime === databaseIdentityUsers.migration ||
    !safeDatabaseIdentityUser(databaseIdentityUsers.runtime) ||
    !safeDatabaseIdentityUser(databaseIdentityUsers.migration)
  ) {
    throw new Error(
      "Database runtime and migration IAM users must be safe, explicit, and separate.",
    );
  }

  const partition = aws.getPartitionOutput({});
  const current = aws.getCallerIdentityOutput({});
  const region = aws.getRegionOutput({});

  const kmsKey = new aws.kms.Key(named(`${config.name}-db-key`), {
    description: `KMS key for Aurora cluster ${config.name}.`,
    enableKeyRotation: true,
    deletionWindowInDays: 30,
    policy: pulumi
      .all([current.accountId, partition.partition])
      .apply(([accountId, partitionName]) =>
        JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "EnableRootAccountAdministration",
              Effect: "Allow",
              Principal: { AWS: `arn:${partitionName}:iam::${accountId}:root` },
              Action: "kms:*",
              Resource: "*",
            },
          ],
        }),
      ),
    tags: tag(`${config.name}-db-key`, {
      DataClass: "platform-database",
      EvidenceSinkId: plan?.evidenceSinkId ?? "audit-log",
    }),
  });

  new aws.kms.Alias(named(`${config.name}-db-key-alias`), {
    name: `alias/${named(config.name)}-db`,
    targetKeyId: kmsKey.keyId,
  });

  const subnetGroup = new aws.rds.SubnetGroup(
    named(`${config.name}-db-subnets`),
    {
      name: named(`${config.name}-db-subnets`),
      subnetIds: privateSubnetIds,
      tags: tag(`${config.name}-db-subnets`),
    },
  );

  const runtimeAccessSecurityGroup = new aws.ec2.SecurityGroup(
    named(`${config.name}-db-runtime-access-sg`),
    {
      vpcId,
      description: `Explicit runtime database source boundary for ${config.name}.`,
      ingress: [],
      egress: [],
      tags: tag(`${config.name}-db-runtime-access-sg`, {
        AccessRole: "runtime",
        SemanticBoundaryId: accessBoundaryIds.runtime,
      }),
    },
  );

  const migrationAccessSecurityGroup = new aws.ec2.SecurityGroup(
    named(`${config.name}-db-migration-access-sg`),
    {
      vpcId,
      description: `Explicit migration database source boundary for ${config.name}.`,
      ingress: [],
      egress: [],
      tags: tag(`${config.name}-db-migration-access-sg`, {
        AccessRole: "migration",
        SemanticBoundaryId: accessBoundaryIds.migration,
      }),
    },
  );

  const bootstrapAccessSecurityGroup = new aws.ec2.SecurityGroup(
    named(`${config.name}-db-bootstrap-access-sg`),
    {
      vpcId,
      description: `Control-plane-only database bootstrap source boundary for ${config.name}.`,
      ingress: [],
      egress: [],
      tags: tag(`${config.name}-db-bootstrap-access-sg`, {
        AccessRole: "bootstrap",
        SemanticBoundaryId: bootstrapBoundaryId,
      }),
    },
  );

  const securityGroup = new aws.ec2.SecurityGroup(
    named(`${config.name}-db-sg`),
    {
      vpcId,
      description: `Database target boundary for ${config.name}; no CIDR ingress.`,
      ingress: [],
      egress: [],
      tags: tag(`${config.name}-db-sg`),
    },
  );

  const parameterGroup = new aws.rds.ClusterParameterGroup(
    named(`${config.name}-db-params`),
    {
      name: named(`${config.name}-db-params`),
      family:
        config.engine === "aurora-postgresql"
          ? `aurora-postgresql${config.engineMajorVersion}`
          : `aurora-mysql${config.engineMajorVersion}`,
      description: `Parameter group for ${config.name}; enables audit logging.`,
      parameters: parameterDefaults(config),
      tags: tag(`${config.name}-db-params`),
    },
  );

  const monitoringRole = new aws.iam.Role(
    named(`${config.name}-db-monitoring-role`),
    {
      name: awsApplyLaneIamRoleName(
        args.iamRoleConstraint,
        `${config.name}-db-monitoring`,
      ),
      assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({
        Service: "monitoring.rds.amazonaws.com",
      }),
      permissionsBoundary: args.iamRoleConstraint.permissionsBoundaryArn,
      tags: tag(`${config.name}-db-monitoring-role`, {
        InfrastructureActionSet: args.iamRoleConstraint.actionSet,
        BootstrapAccessSourceDigest: args.iamRoleConstraint.sourceDigest,
      }),
    },
  );

  new aws.iam.RolePolicyAttachment(
    named(`${config.name}-db-monitoring-attach`),
    {
      role: monitoringRole.name,
      policyArn:
        "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole",
    },
  );

  const cluster = new aws.rds.Cluster(named(`${config.name}-db`), {
    clusterIdentifier: named(`${config.name}-db`),
    engine: config.engine,
    engineVersion: config.engineVersion,
    engineMode: "provisioned",
    masterUsername: config.masterUsername,
    manageMasterUserPassword: true,
    masterUserSecretKmsKeyId: kmsKey.arn,
    databaseName: config.databaseName,
    port: config.port,
    dbSubnetGroupName: subnetGroup.name,
    vpcSecurityGroupIds: [securityGroup.id],
    storageEncrypted: true,
    kmsKeyId: kmsKey.arn,
    iamDatabaseAuthenticationEnabled: true,
    deletionProtection: config.deletionProtection,
    backupRetentionPeriod: config.backupRetentionDays,
    preferredBackupWindow: "03:00-05:00",
    preferredMaintenanceWindow: "sun:05:30-sun:07:30",
    copyTagsToSnapshot: true,
    enabledCloudwatchLogsExports:
      config.engine === "aurora-postgresql"
        ? ["postgresql"]
        : ["audit", "error", "general", "slowquery"],
    dbClusterParameterGroupName: parameterGroup.name,
    skipFinalSnapshot: false,
    finalSnapshotIdentifier: `${named(config.name)}-final`,
    applyImmediately: false,
    tags: tag(`${config.name}-db`, {
      DataClass: "platform-database",
      Backup: "required",
      EvidenceSinkId: plan?.evidenceSinkId ?? "audit-log",
      ...(plan
        ? {
            DataBoundaryId: plan.boundaryId,
            SemanticResourceId: plan.clusterBoundaryId,
          }
        : {}),
    }),
  });

  const instances = Array.from({ length: config.instanceCount }, (_, index) => {
    return new aws.rds.ClusterInstance(
      named(`${config.name}-db-instance-${index + 1}`),
      {
        identifier: named(`${config.name}-db-instance-${index + 1}`),
        clusterIdentifier: cluster.id,
        instanceClass: config.instanceClass,
        engine: config.engine as aws.rds.EngineType,
        engineVersion: config.engineVersion,
        publiclyAccessible: false,
        autoMinorVersionUpgrade: true,
        monitoringInterval: 30,
        monitoringRoleArn: monitoringRole.arn,
        performanceInsightsEnabled: true,
        performanceInsightsKmsKeyId: kmsKey.arn,
        performanceInsightsRetentionPeriod: 731,
        caCertIdentifier,
        tags: tag(`${config.name}-db-instance-${index + 1}`),
      },
    );
  });

  let proxy: aws.rds.Proxy | undefined;
  let proxyEndpoint: aws.rds.ProxyDefaultTargetGroup | undefined;
  let proxySecurityGroup: aws.ec2.SecurityGroup | undefined;
  let proxyResourceId: pulumi.Output<string> | undefined;

  if (config.createProxy) {
    proxySecurityGroup = new aws.ec2.SecurityGroup(
      named(`${config.name}-db-proxy-sg`),
      {
        vpcId,
        description: `RDS Proxy target boundary for ${config.name}.`,
        ingress: [],
        egress: [],
        tags: tag(`${config.name}-db-proxy-sg`, {
          AccessRole: "proxy",
        }),
      },
    );
    createSecurityGroupPath({
      name: `${config.name}-runtime-to-db-proxy`,
      source: runtimeAccessSecurityGroup,
      destination: proxySecurityGroup,
      port: config.port,
      description: "Runtime identity boundary to RDS Proxy",
    });
    createSecurityGroupPath({
      name: `${config.name}-migration-to-db-proxy`,
      source: migrationAccessSecurityGroup,
      destination: proxySecurityGroup,
      port: config.port,
      description: "Migration identity boundary to RDS Proxy",
    });
    createSecurityGroupPath({
      name: `${config.name}-db-proxy-to-cluster`,
      source: proxySecurityGroup,
      destination: securityGroup,
      port: config.port,
      description: "RDS Proxy to database cluster",
    });
    createSecurityGroupPath({
      name: `${config.name}-bootstrap-to-database`,
      source: bootstrapAccessSecurityGroup,
      destination: securityGroup,
      port: config.port,
      description: "Isolated bootstrap identity directly to database cluster",
    });
    const proxyRole = new aws.iam.Role(named(`${config.name}-db-proxy-role`), {
      name: awsApplyLaneIamRoleName(
        args.iamRoleConstraint,
        `${config.name}-db-proxy`,
      ),
      assumeRolePolicy: pulumi
        .all([partition.partition, region.name, current.accountId])
        .apply(([partitionName, regionName, accountId]) =>
          JSON.stringify({
            Version: "2012-10-17",
            Statement: [
              {
                Sid: "TrustRdsProxyInExactAccountAndRegion",
                Effect: "Allow",
                Principal: { Service: "rds.amazonaws.com" },
                Action: "sts:AssumeRole",
                Condition: {
                  StringEquals: { "aws:SourceAccount": accountId },
                  ArnLike: {
                    "aws:SourceArn": `arn:${partitionName}:rds:${regionName}:${accountId}:db-proxy:*`,
                  },
                },
              },
            ],
          }),
        ),
      permissionsBoundary: args.iamRoleConstraint.permissionsBoundaryArn,
      tags: tag(`${config.name}-db-proxy-role`, {
        InfrastructureActionSet: args.iamRoleConstraint.actionSet,
        BootstrapAccessSourceDigest: args.iamRoleConstraint.sourceDigest,
      }),
    });

    const proxyRolePolicy = new aws.iam.RolePolicy(
      named(`${config.name}-db-proxy-connect`),
      {
        role: proxyRole.id,
        policy: pulumi
          .all([
            partition.partition,
            region.name,
            current.accountId,
            cluster.clusterResourceId,
          ])
          .apply(([partitionName, regionName, accountId, clusterResourceId]) =>
            JSON.stringify({
              Version: "2012-10-17",
              Statement: [
                {
                  Sid: "ConnectToThisClusterWithIam",
                  Effect: "Allow",
                  Action: "rds-db:connect",
                  Resource: [
                    `arn:${partitionName}:rds-db:${regionName}:${accountId}:dbuser:${clusterResourceId}/${databaseIdentityUsers.runtime}`,
                    `arn:${partitionName}:rds-db:${regionName}:${accountId}:dbuser:${clusterResourceId}/${databaseIdentityUsers.migration}`,
                  ],
                },
              ],
            }),
          ),
      },
    );

    proxy = new aws.rds.Proxy(
      named(`${config.name}-db-proxy`),
      {
        name: named(`${config.name}-db-proxy`),
        engineFamily:
          config.engine === "aurora-postgresql" ? "POSTGRESQL" : "MYSQL",
        defaultAuthScheme: "IAM_AUTH",
        roleArn: proxyRole.arn,
        vpcSubnetIds: privateSubnetIds,
        vpcSecurityGroupIds: [proxySecurityGroup.id],
        requireTls: true,
        idleClientTimeout: 1800,
        tags: tag(`${config.name}-db-proxy`),
      },
      { dependsOn: proxyRolePolicy },
    );
    proxyResourceId = proxy.arn.apply(rdsProxyResourceIdFromArn);

    proxyEndpoint = new aws.rds.ProxyDefaultTargetGroup(
      named(`${config.name}-db-proxy-target`),
      {
        dbProxyName: proxy.name,
        connectionPoolConfig: {
          maxConnectionsPercent: 90,
          maxIdleConnectionsPercent: 50,
          connectionBorrowTimeout: 120,
        },
      },
    );

    new aws.rds.ProxyTarget(named(`${config.name}-db-proxy-targets`), {
      dbProxyName: proxy.name,
      targetGroupName: proxyEndpoint.name,
      dbClusterIdentifier: cluster.id,
    });
  } else {
    createSecurityGroupPath({
      name: `${config.name}-runtime-to-database`,
      source: runtimeAccessSecurityGroup,
      destination: securityGroup,
      port: config.port,
      description: "Runtime identity boundary to database cluster",
    });
    createSecurityGroupPath({
      name: `${config.name}-migration-to-database`,
      source: migrationAccessSecurityGroup,
      destination: securityGroup,
      port: config.port,
      description: "Migration identity boundary to database cluster",
    });
    createSecurityGroupPath({
      name: `${config.name}-bootstrap-to-database`,
      source: bootstrapAccessSecurityGroup,
      destination: securityGroup,
      port: config.port,
      description: "Isolated bootstrap identity directly to database cluster",
    });
  }

  return {
    cluster,
    instances,
    kmsKey,
    parameterGroup,
    subnetGroup,
    securityGroup,
    runtimeAccessSecurityGroup,
    migrationAccessSecurityGroup,
    bootstrapAccessSecurityGroup,
    proxySecurityGroup,
    proxy,
    proxyResourceId,
    proxyEndpoint,
    monitoringRole,
    runtimeDatabaseUser: databaseIdentityUsers.runtime,
    migrationDatabaseUser: databaseIdentityUsers.migration,
    caCertIdentifier,
    masterUserSecretArn: cluster.masterUserSecrets.apply((secrets) => {
      if (secrets.length !== 1 || !secrets[0].secretArn) {
        throw new Error(
          "RDS-managed master credentials must resolve to exactly one secret ARN.",
        );
      }
      return secrets[0].secretArn;
    }),
  };
}

export function rdsProxyResourceIdFromArn(arn: string): string {
  const match =
    /^arn:(?:aws|aws-us-gov|aws-cn):rds:[a-z]{2}(?:-gov)?-[a-z]+-\d:\d{12}:db-proxy:(prx-[A-Za-z0-9]+)$/.exec(
      arn,
    );
  if (!match) {
    throw new Error(
      "RDS Proxy ARN does not contain one exact Proxy resource ID.",
    );
  }
  return match[1];
}

function databaseIdentityUser(value: string): string {
  const normalized = value.toLowerCase().replace(/[^a-z0-9_]/g, "_");
  if (safeDatabaseIdentityUser(normalized)) return normalized;
  throw new Error(
    `Database identity '${value}' cannot become a safe IAM user.`,
  );
}

function safeDatabaseIdentityUser(value: string): boolean {
  return /^[a-z_][a-z0-9_]{0,62}$/.test(value);
}

function createSecurityGroupPath(args: {
  name: string;
  source: aws.ec2.SecurityGroup;
  destination: aws.ec2.SecurityGroup;
  port: number;
  description: string;
}) {
  new aws.vpc.SecurityGroupEgressRule(named(`${args.name}-egress`), {
    securityGroupId: args.source.id,
    referencedSecurityGroupId: args.destination.id,
    ipProtocol: "tcp",
    fromPort: args.port,
    toPort: args.port,
    description: args.description,
    tags: tag(`${args.name}-egress`),
  });
  new aws.vpc.SecurityGroupIngressRule(named(`${args.name}-ingress`), {
    securityGroupId: args.destination.id,
    referencedSecurityGroupId: args.source.id,
    ipProtocol: "tcp",
    fromPort: args.port,
    toPort: args.port,
    description: args.description,
    tags: tag(`${args.name}-ingress`),
  });
}

function assertDatabasePlanCompatibility(
  config: DatabaseConfig,
  plan: AwsDatabasePlan | undefined,
) {
  if (!plan) return;
  if (
    config.engine !== plan.engine ||
    config.engineVersion !== plan.engineVersion
  ) {
    throw new Error(
      `Database configuration does not match compiled intent for '${plan.boundaryId}'.`,
    );
  }
  if (
    config.instanceCount < plan.instanceCount ||
    config.backupRetentionDays < plan.backupRetentionDays ||
    (plan.deletionProtection && !config.deletionProtection) ||
    (plan.regionalRecoveryCopy &&
      config.replicaRegion !== plan.regionalRecoveryCopy.region)
  ) {
    throw new Error(
      `Database configuration weakens compiled recovery intent for '${plan.boundaryId}'.`,
    );
  }
}

function parameterDefaults(config: DatabaseConfig) {
  if (config.engine === "aurora-postgresql") {
    return [
      {
        name: "shared_preload_libraries",
        value: "pgaudit",
        applyMethod: "pending-reboot",
      },
      { name: "pgaudit.log", value: "all" },
      { name: "log_connections", value: "1" },
      { name: "log_disconnections", value: "1" },
      { name: "log_statement", value: "ddl" },
      { name: "log_min_duration_statement", value: "1000" },
      { name: "rds.force_ssl", value: "1" },
    ];
  }

  return [
    { name: "general_log", value: "1" },
    { name: "slow_query_log", value: "1" },
    { name: "long_query_time", value: "1" },
    { name: "require_secure_transport", value: "ON" },
    {
      name: "server_audit_logging",
      value: "1",
      applyMethod: "pending-reboot",
    },
    {
      name: "server_audit_events",
      value: "CONNECT,QUERY_DDL,QUERY_DCL",
      applyMethod: "pending-reboot",
    },
  ];
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
