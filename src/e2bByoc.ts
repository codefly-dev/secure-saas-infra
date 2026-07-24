import * as aws from "@pulumi/aws";
import { E2bByocAccessConfig, baseTags, named } from "./config";

export function createE2bByocAccess(config: E2bByocAccessConfig) {
  if (!config.createVendorRole) {
    return {};
  }

  const role = new aws.iam.Role(named("e2b-byoc-vendor-access"), {
    assumeRolePolicy: JSON.stringify({
      Version: "2012-10-17",
      Statement: [
        {
          Effect: "Allow",
          Principal: {
            AWS: config.vendorPrincipalArns,
          },
          Action: "sts:AssumeRole",
          Condition: {
            StringEquals: {
              "sts:ExternalId": config.externalId,
            },
          },
        },
      ],
    }),
    description:
      "Reviewed E2B BYOC vendor access role for execution sandbox provisioning.",
    maxSessionDuration: config.maxSessionDurationSeconds ?? 3600,
    tags: tag("e2b-byoc-vendor-access", { AccessClass: "vendor-byoc" }),
  });

  config.managedPolicyArns.forEach((policyArn, index) => {
    new aws.iam.RolePolicyAttachment(
      named(`e2b-byoc-vendor-access-policy-${index + 1}`),
      {
        role: role.name,
        policyArn,
      },
    );
  });

  if (config.inlinePolicy) {
    new aws.iam.RolePolicy(named("e2b-byoc-vendor-access-inline"), {
      role: role.id,
      policy: JSON.stringify(config.inlinePolicy),
    });
  }

  return { vendorRole: role };
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
