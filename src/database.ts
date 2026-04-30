import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { DatabaseConfig, baseTags, named } from "./config";

export interface DatabaseResult {
  cluster: aws.rds.Cluster;
  instances: aws.rds.ClusterInstance[];
  kmsKey: aws.kms.Key;
  parameterGroup: aws.rds.ClusterParameterGroup;
  subnetGroup: aws.rds.SubnetGroup;
  securityGroup: aws.ec2.SecurityGroup;
  proxy?: aws.rds.Proxy;
  proxyEndpoint?: aws.rds.ProxyDefaultTargetGroup;
  monitoringRole?: aws.iam.Role;
}

export function createDatabaseCluster(args: {
  config: DatabaseConfig;
  vpcId: pulumi.Input<string>;
  vpcCidr: pulumi.Input<string>;
  privateSubnetIds: pulumi.Input<pulumi.Input<string>[]>;
}): DatabaseResult {
  const { config, vpcId, vpcCidr, privateSubnetIds } = args;

  const partition = aws.getPartitionOutput({});
  const current = aws.getCallerIdentityOutput({});

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
            {
              Sid: "AllowRdsService",
              Effect: "Allow",
              Principal: { Service: "rds.amazonaws.com" },
              Action: [
                "kms:CreateGrant",
                "kms:Decrypt",
                "kms:DescribeKey",
                "kms:Encrypt",
                "kms:GenerateDataKey*",
                "kms:ReEncrypt*",
              ],
              Resource: "*",
            },
          ],
        }),
      ),
    tags: tag(`${config.name}-db-key`, { DataClass: "platform-database" }),
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

  const securityGroup = new aws.ec2.SecurityGroup(
    named(`${config.name}-db-sg`),
    {
      vpcId,
      description: `Allows database access from the workload VPC for ${config.name}.`,
      ingress: [
        {
          protocol: "tcp",
          fromPort: config.port,
          toPort: config.port,
          cidrBlocks: [vpcCidr],
          description: "Database port from workload VPC",
        },
      ],
      egress: [],
      tags: tag(`${config.name}-db-sg`),
    },
  );

  const parameterGroup = new aws.rds.ClusterParameterGroup(
    named(`${config.name}-db-params`),
    {
      name: named(`${config.name}-db-params`),
      family: config.engine === "aurora-postgresql"
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
      assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({
        Service: "monitoring.rds.amazonaws.com",
      }),
      tags: tag(`${config.name}-db-monitoring-role`),
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

  const password = new aws.secretsmanager.Secret(
    named(`${config.name}-db-master`),
    {
      name: named(`${config.name}-db-master`),
      description: `Bootstrap master password for ${config.name}; rotate via Vault.`,
      kmsKeyId: kmsKey.arn,
      recoveryWindowInDays: 30,
      tags: tag(`${config.name}-db-master`, { SecretClass: "bootstrap" }),
    },
  );

  const passwordValue = new aws.secretsmanager.SecretVersion(
    named(`${config.name}-db-master-version`),
    {
      secretId: password.id,
      secretString: pulumi.secret(generatePlaceholderPassword(config.name)),
    },
  );

  const cluster = new aws.rds.Cluster(named(`${config.name}-db`), {
    clusterIdentifier: named(`${config.name}-db`),
    engine: config.engine,
    engineVersion: config.engineVersion,
    engineMode: "provisioned",
    masterUsername: config.masterUsername,
    masterPassword: passwordValue.secretString,
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
    finalSnapshotIdentifier: `${named(config.name)}-final-${Date.now()}`,
    applyImmediately: false,
    tags: tag(`${config.name}-db`, {
      DataClass: "platform-database",
      Backup: "required",
    }),
  } as any);

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
        caCertIdentifier: "rds-ca-rsa4096-g1",
        tags: tag(`${config.name}-db-instance-${index + 1}`),
      },
    );
  });

  let proxy: aws.rds.Proxy | undefined;
  let proxyEndpoint: aws.rds.ProxyDefaultTargetGroup | undefined;

  if (config.createProxy) {
    const proxyRole = new aws.iam.Role(named(`${config.name}-db-proxy-role`), {
      assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({
        Service: "rds.amazonaws.com",
      }),
      tags: tag(`${config.name}-db-proxy-role`),
    });

    new aws.iam.RolePolicy(named(`${config.name}-db-proxy-secrets`), {
      role: proxyRole.id,
      policy: pulumi
        .all([password.arn, kmsKey.arn])
        .apply(([secretArn, keyArn]) =>
          JSON.stringify({
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: [
                  "secretsmanager:GetSecretValue",
                  "secretsmanager:DescribeSecret",
                ],
                Resource: secretArn,
              },
              {
                Effect: "Allow",
                Action: ["kms:Decrypt"],
                Resource: keyArn,
                Condition: {
                  StringEquals: {
                    "kms:ViaService": pulumi.interpolate`secretsmanager.${aws.config.region}.amazonaws.com`,
                  },
                },
              },
            ],
          }),
        ),
    });

    proxy = new aws.rds.Proxy(named(`${config.name}-db-proxy`), {
      name: named(`${config.name}-db-proxy`),
      engineFamily:
        config.engine === "aurora-postgresql" ? "POSTGRESQL" : "MYSQL",
      auths: [
        {
          authScheme: "SECRETS",
          iamAuth: "REQUIRED",
          secretArn: password.arn,
        },
      ],
      roleArn: proxyRole.arn,
      vpcSubnetIds: privateSubnetIds,
      vpcSecurityGroupIds: [securityGroup.id],
      requireTls: true,
      idleClientTimeout: 1800,
      tags: tag(`${config.name}-db-proxy`),
    });

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
  }

  return {
    cluster,
    instances,
    kmsKey,
    parameterGroup,
    subnetGroup,
    securityGroup,
    proxy,
    proxyEndpoint,
    monitoringRole,
  };
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

function generatePlaceholderPassword(seed: string) {
  return `bootstrap-rotate-via-vault-${seed}-${Date.now().toString(36)}`;
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
