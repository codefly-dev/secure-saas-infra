import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { DnsConfig, baseTags, named } from "./config";

export interface DnsResult {
  rootZone?: aws.route53.Zone;
  environmentZones: Record<string, aws.route53.Zone>;
  delegationRecords: Record<string, aws.route53.Record>;
  queryLogConfig?: aws.route53.QueryLog;
}

export function createDns(config: DnsConfig): DnsResult {
  const environmentZones: Record<string, aws.route53.Zone> = {};
  const delegationRecords: Record<string, aws.route53.Record> = {};
  let rootZone: aws.route53.Zone | undefined;
  let queryLogConfig: aws.route53.QueryLog | undefined;

  if (config.createRootZone) {
    rootZone = new aws.route53.Zone(named("dns-root-zone"), {
      name: config.rootDomain,
      comment: `Root zone for ${config.rootDomain}.`,
      tags: tag("dns-root-zone", { DataClass: "dns" }),
    });

    if (config.enableQueryLogging) {
      // Query log group MUST live in us-east-1 for Route 53 public-zone
      // query logging.
      const usEast1 = new aws.Provider(named("dns-us-east-1"), {
        region: "us-east-1",
      });

      const logGroup = new aws.cloudwatch.LogGroup(
        named("dns-public-zone-logs"),
        {
          name: `/aws/route53/${config.rootDomain}`,
          retentionInDays: 365,
          tags: tag("dns-public-zone-logs", {
            EvidenceClass: "dns-query",
          }),
        },
        { provider: usEast1 },
      );

      const partition = aws.getPartitionOutput({});
      const current = aws.getCallerIdentityOutput({});

      new aws.cloudwatch.LogResourcePolicy(
        named("dns-public-zone-log-policy"),
        {
          policyName: named("dns-public-zone-log-policy"),
          policyDocument: pulumi
            .all([logGroup.arn, partition.partition, current.accountId])
            .apply(([logGroupArn, partitionName, accountId]) =>
              JSON.stringify({
                Version: "2012-10-17",
                Statement: [
                  {
                    Sid: "AllowRoute53QueryLogging",
                    Effect: "Allow",
                    Principal: { Service: "route53.amazonaws.com" },
                    Action: ["logs:CreateLogStream", "logs:PutLogEvents"],
                    Resource: `${logGroupArn}:*`,
                    Condition: {
                      StringEquals: { "aws:SourceAccount": accountId },
                    },
                  },
                ],
              }),
            ),
        },
        { provider: usEast1 },
      );

      queryLogConfig = new aws.route53.QueryLog(
        named("dns-public-zone-query-log"),
        {
          cloudwatchLogGroupArn: logGroup.arn,
          zoneId: rootZone.zoneId,
        },
        { provider: usEast1 },
      );
    }
  }

  for (const env of config.environmentSubdomains) {
    const fqdn = `${env}.${config.rootDomain}`;

    const zone = new aws.route53.Zone(named(`dns-${env}-zone`), {
      name: fqdn,
      comment: `Delegated zone for ${env} environment.`,
      tags: tag(`dns-${env}-zone`, { DataClass: "dns", Environment: env }),
    });
    environmentZones[env] = zone;

    if (rootZone) {
      delegationRecords[env] = new aws.route53.Record(
        named(`dns-${env}-delegation`),
        {
          zoneId: rootZone.zoneId,
          name: fqdn,
          type: "NS",
          ttl: 172800,
          records: zone.nameServers,
        },
      );
    }
  }

  return {
    rootZone,
    environmentZones,
    delegationRecords,
    queryLogConfig,
  };
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
