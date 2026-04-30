import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { DetectionConfig, baseTags, named } from "./config";

export interface DetectionResult {
  topic: aws.sns.Topic;
  rules: aws.cloudwatch.EventRule[];
}

export function createDetectionRules(config: DetectionConfig): DetectionResult {
  const topic = new aws.sns.Topic(named("security-alerts"), {
    name: named("security-alerts"),
    kmsMasterKeyId: "alias/aws/sns",
    tags: tag("security-alerts", { EvidenceClass: "detection" }),
  });

  for (const subscription of config.emailSubscriptions) {
    new aws.sns.TopicSubscription(
      named(`security-alerts-${slug(subscription)}`),
      {
        topic: topic.arn,
        protocol: "email",
        endpoint: subscription,
      },
    );
  }

  const ruleSpecs: Array<{
    name: string;
    description: string;
    eventPattern: Record<string, unknown>;
  }> = [
    {
      name: "guardduty-high-severity",
      description: "GuardDuty findings with severity >= 7.",
      eventPattern: {
        source: ["aws.guardduty"],
        "detail-type": ["GuardDuty Finding"],
        detail: { severity: [{ numeric: [">=", 7] }] },
      },
    },
    {
      name: "iam-identity-center-breakglass",
      description: "Break-glass IAM Identity Center session creation.",
      eventPattern: {
        source: ["aws.sso"],
        detail: {
          eventName: ["CreateAccountAssignment", "DeleteAccountAssignment"],
          requestParameters: { permissionSetArn: [{ exists: true }] },
        },
      },
    },
    {
      name: "kms-rotation-disabled",
      description: "Disable KMS key rotation or scheduled deletion.",
      eventPattern: {
        source: ["aws.kms"],
        "detail-type": ["AWS API Call via CloudTrail"],
        detail: {
          eventName: ["DisableKeyRotation", "ScheduleKeyDeletion"],
        },
      },
    },
    {
      name: "cloudtrail-mutations",
      description: "Mutations on CloudTrail trails.",
      eventPattern: {
        source: ["aws.cloudtrail"],
        "detail-type": ["AWS API Call via CloudTrail"],
        detail: {
          eventName: [
            "DeleteTrail",
            "StopLogging",
            "UpdateTrail",
            "PutEventSelectors",
            "PutInsightSelectors",
          ],
        },
      },
    },
    {
      name: "iam-user-or-key-creation",
      description: "Creation of IAM users or access keys.",
      eventPattern: {
        source: ["aws.iam"],
        "detail-type": ["AWS API Call via CloudTrail"],
        detail: {
          eventName: ["CreateUser", "CreateAccessKey", "CreateLoginProfile"],
        },
      },
    },
    {
      name: "network-firewall-deny-spike",
      description:
        "AWS Network Firewall ALERT log fanout via EventBridge (rule fires on metric alarm via SNS).",
      eventPattern: {
        source: ["aws.cloudwatch"],
        "detail-type": ["CloudWatch Alarm State Change"],
        detail: {
          alarmName: [{ prefix: named("network-firewall-deny-") }],
          state: { value: ["ALARM"] },
        },
      },
    },
    {
      name: "config-noncompliant-resource",
      description:
        "AWS Config compliance change to NON_COMPLIANT for high-severity rules.",
      eventPattern: {
        source: ["aws.config"],
        "detail-type": ["Config Rules Compliance Change"],
        detail: {
          newEvaluationResult: { complianceType: ["NON_COMPLIANT"] },
        },
      },
    },
    {
      name: "securityhub-critical-finding",
      description: "Security Hub critical findings imported.",
      eventPattern: {
        source: ["aws.securityhub"],
        "detail-type": ["Security Hub Findings - Imported"],
        detail: {
          findings: {
            Severity: { Label: ["CRITICAL", "HIGH"] },
            Workflow: { Status: ["NEW", "NOTIFIED"] },
          },
        },
      },
    },
  ];

  const rules = ruleSpecs.map((spec) => {
    const rule = new aws.cloudwatch.EventRule(named(`detect-${spec.name}`), {
      name: named(`detect-${spec.name}`),
      description: spec.description,
      eventPattern: pulumi.output(JSON.stringify(spec.eventPattern)),
      tags: tag(`detect-${spec.name}`, { EvidenceClass: "detection" }),
    });

    new aws.cloudwatch.EventTarget(
      named(`detect-${spec.name}-target`),
      {
        rule: rule.name,
        arn: topic.arn,
      },
    );

    return rule;
  });

  new aws.sns.TopicPolicy(named("security-alerts-policy"), {
    arn: topic.arn,
    policy: topic.arn.apply((topicArn) =>
      JSON.stringify({
        Version: "2012-10-17",
        Statement: [
          {
            Sid: "AllowEventBridgePublish",
            Effect: "Allow",
            Principal: { Service: "events.amazonaws.com" },
            Action: "sns:Publish",
            Resource: topicArn,
          },
        ],
      }),
    ),
  });

  return { topic, rules };
}

function slug(value: string) {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "");
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
