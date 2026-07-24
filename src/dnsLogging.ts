import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { baseTags, named } from "./config";

export interface DnsQueryLogResult {
  logGroup: aws.cloudwatch.LogGroup;
  resolverLogConfig: aws.route53.ResolverQueryLogConfig;
  associations: aws.route53.ResolverQueryLogConfigAssociation[];
}

export function createDnsQueryLogging(args: {
  vpcIds: pulumi.Input<pulumi.Input<string>[]>;
  name: string;
}): pulumi.Output<DnsQueryLogResult> {
  const logGroup = new aws.cloudwatch.LogGroup(named(`${args.name}-dns-logs`), {
    name: `/aws/route53/${named(args.name)}/resolver`,
    retentionInDays: 365,
    tags: tag(`${args.name}-dns-logs`, { EvidenceClass: "dns-query" }),
  });

  const resolverLogConfig = new aws.route53.ResolverQueryLogConfig(
    named(`${args.name}-dns-log-config`),
    {
      name: named(`${args.name}-dns-log-config`),
      destinationArn: logGroup.arn,
      tags: tag(`${args.name}-dns-log-config`, { EvidenceClass: "dns-query" }),
    },
  );

  const associations = pulumi.output(args.vpcIds).apply((ids) =>
    ids.map(
      (vpcId, index) =>
        new aws.route53.ResolverQueryLogConfigAssociation(
          named(`${args.name}-dns-log-assoc-${index + 1}`),
          {
            resolverQueryLogConfigId: resolverLogConfig.id,
            resourceId: vpcId,
          },
        ),
    ),
  );

  return associations.apply((assoc) => ({
    logGroup,
    resolverLogConfig,
    associations: assoc,
  }));
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
