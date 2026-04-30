import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { WafConfig, baseTags, named } from "./config";

export interface WafResult {
  webAcl: aws.wafv2.WebAcl;
  loggingConfiguration?: aws.wafv2.WebAclLoggingConfiguration;
  logGroup?: aws.cloudwatch.LogGroup;
}

export function createPublicWebAcl(config: WafConfig): WafResult {
  const logGroup = new aws.cloudwatch.LogGroup(named("waf-logs"), {
    name: `aws-waf-logs-${named(config.name)}`,
    retentionInDays: 365,
    tags: tag("waf-logs", { EvidenceClass: "waf" }),
  });

  const rules: aws.types.input.wafv2.WebAclRule[] = [
    {
      name: "rate-limit-per-ip",
      priority: 0,
      action: { block: {} },
      statement: {
        rateBasedStatement: {
          limit: config.rateLimitPer5Minutes,
          aggregateKeyType: "IP",
        },
      },
      visibilityConfig: {
        cloudwatchMetricsEnabled: true,
        metricName: `${config.name}-rate-limit-per-ip`,
        sampledRequestsEnabled: true,
      },
    },
    {
      name: "AWSManagedRulesCommonRuleSet",
      priority: 1,
      overrideAction: { none: {} },
      statement: {
        managedRuleGroupStatement: {
          vendorName: "AWS",
          name: "AWSManagedRulesCommonRuleSet",
        },
      },
      visibilityConfig: {
        cloudwatchMetricsEnabled: true,
        metricName: `${config.name}-common`,
        sampledRequestsEnabled: true,
      },
    },
    {
      name: "AWSManagedRulesKnownBadInputsRuleSet",
      priority: 2,
      overrideAction: { none: {} },
      statement: {
        managedRuleGroupStatement: {
          vendorName: "AWS",
          name: "AWSManagedRulesKnownBadInputsRuleSet",
        },
      },
      visibilityConfig: {
        cloudwatchMetricsEnabled: true,
        metricName: `${config.name}-known-bad-inputs`,
        sampledRequestsEnabled: true,
      },
    },
    {
      name: "AWSManagedRulesAmazonIpReputationList",
      priority: 3,
      overrideAction: { none: {} },
      statement: {
        managedRuleGroupStatement: {
          vendorName: "AWS",
          name: "AWSManagedRulesAmazonIpReputationList",
        },
      },
      visibilityConfig: {
        cloudwatchMetricsEnabled: true,
        metricName: `${config.name}-ip-reputation`,
        sampledRequestsEnabled: true,
      },
    },
    {
      name: "AWSManagedRulesAnonymousIpList",
      priority: 4,
      overrideAction: { none: {} },
      statement: {
        managedRuleGroupStatement: {
          vendorName: "AWS",
          name: "AWSManagedRulesAnonymousIpList",
        },
      },
      visibilityConfig: {
        cloudwatchMetricsEnabled: true,
        metricName: `${config.name}-anonymous-ip`,
        sampledRequestsEnabled: true,
      },
    },
  ];

  if (config.enableBotControl) {
    rules.push({
      name: "AWSManagedRulesBotControlRuleSet",
      priority: 5,
      overrideAction: { none: {} },
      statement: {
        managedRuleGroupStatement: {
          vendorName: "AWS",
          name: "AWSManagedRulesBotControlRuleSet",
          managedRuleGroupConfigs: [
            {
              awsManagedRulesBotControlRuleSet: {
                inspectionLevel: "COMMON",
              },
            },
          ],
        },
      },
      visibilityConfig: {
        cloudwatchMetricsEnabled: true,
        metricName: `${config.name}-bot-control`,
        sampledRequestsEnabled: true,
      },
    });
  }

  if (config.modelGatewayPathPrefixes.length > 0) {
    const escaped = config.modelGatewayPathPrefixes.map((prefix) =>
      prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
    );
    rules.push({
      name: "model-gateway-strict-rate-limit",
      priority: 6,
      action: { block: {} },
      statement: {
        rateBasedStatement: {
          limit: config.modelGatewayRateLimitPer5Minutes,
          aggregateKeyType: "IP",
          scopeDownStatement: {
            regexMatchStatement: {
              fieldToMatch: { uriPath: {} },
              regexString: `^(${escaped.join("|")})`,
              textTransformations: [{ priority: 0, type: "NONE" }],
            },
          },
        },
      },
      visibilityConfig: {
        cloudwatchMetricsEnabled: true,
        metricName: `${config.name}-model-gateway-rate`,
        sampledRequestsEnabled: true,
      },
    });
  }

  const webAcl = new aws.wafv2.WebAcl(named(`${config.name}-waf`), {
    name: named(`${config.name}-waf`),
    scope: config.scope,
    defaultAction: { allow: {} },
    rules,
    visibilityConfig: {
      cloudwatchMetricsEnabled: true,
      metricName: named(`${config.name}-waf`),
      sampledRequestsEnabled: true,
    },
    tags: tag(`${config.name}-waf`, { EvidenceClass: "waf" }),
  });

  const loggingConfiguration = new aws.wafv2.WebAclLoggingConfiguration(
    named(`${config.name}-waf-logging`),
    {
      logDestinationConfigs: [logGroup.arn],
      resourceArn: webAcl.arn,
      redactedFields: [
        { singleHeader: { name: "authorization" } },
        { singleHeader: { name: "cookie" } },
        { singleHeader: { name: "x-api-key" } },
      ],
    },
  );

  return { webAcl, loggingConfiguration, logGroup };
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
