import * as aws from "@pulumi/aws";
import { SecurityToolingConfig, baseTags, named } from "./config";

export function createSecurityTooling(config: SecurityToolingConfig) {
  let guardDutyDetector: aws.guardduty.Detector | undefined;

  if (config.enableGuardDutyOrganization) {
    guardDutyDetector = new aws.guardduty.Detector(named("guardduty"), {
      enable: true,
      findingPublishingFrequency: "FIFTEEN_MINUTES",
      tags: tag("guardduty"),
    });

    new aws.guardduty.OrganizationConfiguration(named("guardduty-org"), {
      detectorId: guardDutyDetector.id,
      autoEnableOrganizationMembers: "ALL",
    });

    for (const feature of [
      "S3_DATA_EVENTS",
      "EKS_AUDIT_LOGS",
      "EBS_MALWARE_PROTECTION",
      "RDS_LOGIN_EVENTS",
      "LAMBDA_NETWORK_LOGS",
      "RUNTIME_MONITORING",
    ]) {
      new aws.guardduty.OrganizationConfigurationFeature(named(`guardduty-${feature.toLowerCase().replaceAll("_", "-")}`), {
        detectorId: guardDutyDetector.id,
        name: feature,
        autoEnable: "ALL",
        additionalConfigurations:
          feature === "RUNTIME_MONITORING"
            ? [
                {
                  name: "EKS_ADDON_MANAGEMENT",
                  autoEnable: "ALL",
                },
              ]
            : undefined,
      });
    }
  }

  if (config.enableSecurityHubOrganization) {
    new aws.securityhub.Account(named("securityhub"), {
      enableDefaultStandards: true,
    });

    new aws.securityhub.FindingAggregator(named("securityhub-finding-aggregator"), {
      linkingMode: "ALL_REGIONS",
    });

    new aws.securityhub.OrganizationConfiguration(named("securityhub-org"), {
      autoEnable: true,
      autoEnableStandards: "DEFAULT",
      organizationConfiguration: {
        configurationType: "CENTRAL",
      },
    });
  }

  if (config.enableInspectorOrganization) {
    new aws.inspector2.OrganizationConfiguration(named("inspector-org"), {
      autoEnable: {
        ec2: true,
        ecr: true,
        lambda: true,
        lambdaCode: true,
      },
    });

    if (config.inspectorAccountIds.length > 0) {
      new aws.inspector2.Enabler(named("inspector-enabler"), {
        accountIds: config.inspectorAccountIds,
        resourceTypes: ["EC2", "ECR", "LAMBDA", "LAMBDA_CODE"],
      });
    }
  }

  if (config.enableConfigAggregator) {
    const role = new aws.iam.Role(named("config-aggregator-role"), {
      assumeRolePolicy: aws.iam.assumeRolePolicyForPrincipal({
        Service: "config.amazonaws.com",
      }),
      tags: tag("config-aggregator-role"),
    });

    new aws.iam.RolePolicyAttachment(named("config-aggregator-org-policy"), {
      role: role.name,
      policyArn: "arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations",
    });

    new aws.cfg.ConfigurationAggregator(named("organization-config-aggregator"), {
      name: named("organization-config-aggregator"),
      organizationAggregationSource: {
        allRegions: config.configAggregatorAllRegions,
        roleArn: role.arn,
      },
      tags: tag("organization-config-aggregator"),
    });
  }

  return { guardDutyDetector };
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
