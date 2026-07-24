import {
  ResourceValidationArgs,
  ResourceValidationPolicy,
} from "@pulumi/policy";

export const resourcePolicies: ResourceValidationPolicy[] = [
  {
    name: "eks-private-api-and-secrets-encryption",
    description:
      "EKS clusters must use private APIs and Kubernetes secret envelope encryption.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:eks/cluster:Cluster") return;

      if (args.props.vpcConfig?.endpointPublicAccess !== false) {
        reportViolation("EKS public API access must be disabled.");
      }

      const encryptedResources = args.props.encryptionConfig?.resources ?? [];
      if (!encryptedResources.includes("secrets")) {
        reportViolation(
          "EKS clusters must encrypt Kubernetes secrets with KMS.",
        );
      }
    },
  },
  {
    name: "no-public-security-group-ingress",
    description: "Security groups must not allow public ingress.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      let publicIngress = false;
      if (args.type === "aws:ec2/securityGroup:SecurityGroup") {
        publicIngress = (args.props.ingress ?? []).some(
          (rule: Record<string, unknown>) => hasPublicSecurityGroupCidr(rule),
        );
      } else if (
        args.type ===
        "aws:ec2/securityGroupIngressRule:SecurityGroupIngressRule"
      ) {
        publicIngress = hasPublicSecurityGroupCidr(args.props);
      } else if (
        args.type === "aws:ec2/securityGroupRule:SecurityGroupRule" &&
        args.props.type === "ingress"
      ) {
        publicIngress = hasPublicSecurityGroupCidr(args.props);
      } else {
        return;
      }
      if (publicIngress) {
        reportViolation(
          "Security group ingress must not allow 0.0.0.0/0 or ::/0.",
        );
      }
    },
  },
  {
    name: "spokes-have-no-direct-internet",
    description:
      "Only the centralized egress VPC may own Internet Gateways or NAT Gateways.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (
        ![
          "aws:ec2/internetGateway:InternetGateway",
          "aws:ec2/natGateway:NatGateway",
        ].includes(args.type)
      )
        return;

      if (args.props.tags?.NetworkRole !== "central-egress") {
        reportViolation(
          "Internet and NAT gateways are only allowed in the centralized egress VPC.",
        );
      }
    },
  },
  {
    name: "s3-public-access-block-required",
    description:
      "Every declared S3 public access block must block all public access modes.",
    severity: "high",
    validateResource: (args, reportViolation) => {
      if (
        args.type !== "aws:s3/bucketPublicAccessBlock:BucketPublicAccessBlock"
      )
        return;

      for (const property of [
        "blockPublicAcls",
        "blockPublicPolicy",
        "ignorePublicAcls",
        "restrictPublicBuckets",
      ]) {
        if (args.props[property] !== true) {
          reportViolation(
            `S3 public access block must set ${property} to true.`,
          );
        }
      }
    },
  },
  {
    name: "audit-buckets-object-lock",
    description:
      "Audit and Vault backup buckets must enable S3 Object Lock and must not be force-destroyable.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:s3/bucket:Bucket") return;
      if (!isProtectedBucket(args)) return;

      if (args.props.objectLockEnabled !== true) {
        reportViolation(
          "Audit and Vault backup buckets must enable S3 Object Lock.",
        );
      }

      if (args.props.forceDestroy !== false) {
        reportViolation(
          "Audit and Vault backup buckets must not set forceDestroy.",
        );
      }
    },
  },
  {
    name: "kms-rotation-required",
    description: "Customer-managed KMS keys must enable key rotation.",
    severity: "high",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:kms/key:Key") return;

      if (args.props.enableKeyRotation !== true) {
        reportViolation("KMS keys must enable rotation.");
      }
    },
  },
  {
    name: "organization-cloudtrail-required-settings",
    description:
      "Organization CloudTrail must be multi-region with log file validation.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:cloudtrail/trail:Trail") return;

      if (args.props.isOrganizationTrail !== true) {
        reportViolation("CloudTrail must be an organization trail.");
      }

      if (args.props.isMultiRegionTrail !== true) {
        reportViolation("CloudTrail must be multi-region.");
      }

      if (args.props.enableLogFileValidation !== true) {
        reportViolation("CloudTrail log file validation must be enabled.");
      }
    },
  },
  {
    name: "vpc-endpoints-require-explicit-policies",
    description:
      "VPC endpoints must attach explicit endpoint policies and must not use full-access policies.",
    severity: "high",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:ec2/vpcEndpoint:VpcEndpoint") return;

      if (!args.props.policy) {
        reportViolation(
          "VPC endpoints must attach an explicit endpoint policy.",
        );
        return;
      }

      if (hasFullAccessPolicy(args.props.policy)) {
        reportViolation("VPC endpoint policies must not grant full access.");
      }

      if (!hasPrincipalAccountCondition(args.props.policy)) {
        reportViolation(
          "VPC endpoint policies must scope access with aws:PrincipalAccount.",
        );
      }
    },
  },
  {
    name: "vpc-flow-logs-capture-all-traffic",
    description: "VPC Flow Logs must capture accepted and rejected traffic.",
    severity: "high",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:ec2/flowLog:FlowLog") return;

      if (args.props.trafficType !== "ALL") {
        reportViolation("VPC Flow Logs must use trafficType ALL.");
      }

      if (
        args.props.logDestinationType !== "cloud-watch-logs" &&
        args.props.logDestinationType !== "s3"
      ) {
        reportViolation("VPC Flow Logs must deliver to CloudWatch Logs or S3.");
      }
    },
  },
  {
    name: "network-firewall-flow-and-alert-logs",
    description: "AWS Network Firewall must emit both flow and alert logs.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (
        args.type !==
        "aws:networkfirewall/loggingConfiguration:LoggingConfiguration"
      )
        return;

      const configs =
        args.props.loggingConfiguration?.logDestinationConfigs ?? [];
      const logTypes = new Set(
        configs.map((config: { logType?: string }) => config.logType),
      );
      if (!logTypes.has("FLOW") || !logTypes.has("ALERT")) {
        reportViolation(
          "AWS Network Firewall logging must include both FLOW and ALERT logs.",
        );
      }
    },
  },
  {
    name: "iam-identity-policies-avoid-broad-admin",
    description:
      "IAM identity policies, IAM Identity Center inline policies, and attachments must avoid administrator policies, wildcard Allow actions, and unbounded privilege-escalation actions.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (isIamPolicyDocumentResource(args)) {
        for (const violation of iamPolicyDocumentViolations(
          args.props.policy,
        )) {
          reportViolation(violation);
        }
        return;
      }

      if (isIdentityCenterInlinePolicyResource(args)) {
        for (const violation of iamPolicyDocumentViolations(
          args.props.inlinePolicy,
        )) {
          reportViolation(violation);
        }
        return;
      }

      if (!isIamManagedPolicyAttachmentResource(args)) return;

      const policyArn = args.props.policyArn ?? args.props.managedPolicyArn;
      if (isHighRiskManagedPolicyArn(policyArn)) {
        reportViolation(
          "IAM principals and Identity Center permission sets must not attach AdministratorAccess, PowerUserAccess, or IAMFullAccess. Use reviewed least-privilege policies.",
        );
      }
    },
  },
  {
    name: "cloudwatch-log-groups-retain-security-evidence",
    description:
      "CloudWatch Log Groups must keep security evidence for at least one year.",
    severity: "high",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:cloudwatch/logGroup:LogGroup") return;

      if ((args.props.retentionInDays ?? 0) < 365) {
        reportViolation(
          "CloudWatch Log Groups must set retentionInDays to at least 365.",
        );
      }
    },
  },
  {
    name: "secrets-manager-secrets-use-cmk",
    description: "Secrets Manager secrets must use a customer-managed KMS key.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:secretsmanager/secret:Secret") return;

      if (!args.props.kmsKeyId) {
        reportViolation(
          "Secrets Manager secrets must set kmsKeyId to a customer-managed KMS key.",
        );
      }
    },
  },
  {
    name: "s3-encryption-uses-kms",
    description:
      "S3 bucket server-side encryption must use customer-managed KMS and reject SSE-C.",
    severity: "high",
    validateResource: (args, reportViolation) => {
      if (
        args.type !==
        "aws:s3/bucketServerSideEncryptionConfiguration:BucketServerSideEncryptionConfiguration"
      )
        return;

      const rules = args.props.rules ?? [];
      if (rules.length === 0) {
        reportViolation(
          "S3 buckets must declare server-side encryption rules.",
        );
        return;
      }

      for (const rule of rules) {
        const encryption = rule.applyServerSideEncryptionByDefault ?? {};
        if (encryption.sseAlgorithm !== "aws:kms") {
          reportViolation("S3 bucket encryption must use aws:kms.");
        }

        if (!encryption.kmsMasterKeyId) {
          reportViolation(
            "S3 bucket encryption must use an explicit customer-managed KMS key.",
          );
        }

        if (!(rule.blockedEncryptionTypes ?? []).includes("SSE-C")) {
          reportViolation("S3 bucket encryption must block SSE-C uploads.");
        }
      }
    },
  },
  {
    name: "no-iam-users-or-access-keys",
    description:
      "IAM users and long-lived IAM access keys are not allowed in this baseline.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (
        args.type !== "aws:iam/user:User" &&
        args.type !== "aws:iam/accessKey:AccessKey"
      )
        return;

      reportViolation(
        "Do not create IAM users or long-lived access keys. Use IAM Identity Center, workload identity, or GitHub OIDC.",
      );
    },
  },
  {
    name: "ec2-instances-require-imdsv2",
    description:
      "EC2 instances must require IMDSv2 and cap metadata hop limit to one.",
    severity: "high",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:ec2/instance:Instance") return;

      const metadataOptions = args.props.metadataOptions ?? {};
      if (metadataOptions.httpTokens !== "required") {
        reportViolation("EC2 instances must require IMDSv2 httpTokens.");
      }

      if ((metadataOptions.httpPutResponseHopLimit ?? 99) > 1) {
        reportViolation(
          "EC2 instances must set metadataOptions.httpPutResponseHopLimit to 1.",
        );
      }
    },
  },
  {
    name: "rds-clusters-private-and-protected",
    description:
      "Aurora and RDS clusters must encrypt with CMK, enable IAM auth, set deletion protection, and have ample backups.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (args.type === "aws:rds/cluster:Cluster") {
        if (args.props.storageEncrypted !== true) {
          reportViolation("RDS clusters must enable storage encryption.");
        }
        if (!args.props.kmsKeyId) {
          reportViolation(
            "RDS clusters must encrypt with a customer-managed KMS key.",
          );
        }
        if (args.props.iamDatabaseAuthenticationEnabled !== true) {
          reportViolation(
            "RDS clusters must enable IAM database authentication.",
          );
        }
        if (args.props.deletionProtection !== true) {
          reportViolation("RDS clusters must enable deletion protection.");
        }
        if ((args.props.backupRetentionPeriod ?? 0) < 14) {
          reportViolation(
            "RDS clusters must keep backups for at least 14 days.",
          );
        }
        return;
      }

      if (args.type === "aws:rds/clusterInstance:ClusterInstance") {
        if (args.props.publiclyAccessible === true) {
          reportViolation(
            "RDS cluster instances must not be publicly accessible.",
          );
        }
        if (args.props.performanceInsightsEnabled !== true) {
          reportViolation(
            "RDS cluster instances must enable Performance Insights for forensic visibility.",
          );
        }
      }

      if (args.type === "aws:rds/instance:Instance") {
        if (args.props.publiclyAccessible === true) {
          reportViolation("RDS instances must not be publicly accessible.");
        }
        if (args.props.storageEncrypted !== true) {
          reportViolation("RDS instances must enable storage encryption.");
        }
        if (args.props.deletionProtection !== true) {
          reportViolation("RDS instances must enable deletion protection.");
        }
      }
    },
  },
  {
    name: "rds-proxies-require-end-to-end-iam-and-tls",
    description:
      "RDS Proxies must require TLS and end-to-end IAM without secret-backed auth entries.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:rds/proxy:Proxy") return;
      if (args.props.requireTls !== true) {
        reportViolation("RDS Proxies must set requireTls to true.");
      }
      if (args.props.defaultAuthScheme !== "IAM_AUTH") {
        reportViolation("RDS Proxies must set defaultAuthScheme to IAM_AUTH.");
      }
      if ((args.props.auths ?? []).length !== 0) {
        reportViolation(
          "End-to-end IAM RDS Proxies must not configure secret-backed auth entries.",
        );
      }
      if (!args.props.roleArn) {
        reportViolation("RDS Proxies must reference one IAM service role.");
      }
    },
  },
  {
    name: "backup-vault-uses-cmk",
    description:
      "AWS Backup vaults must encrypt with a customer-managed KMS key.",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:backup/vault:Vault") return;
      if (!args.props.kmsKeyArn) {
        reportViolation(
          "AWS Backup vaults must reference a customer-managed KMS key arn.",
        );
      }
      if (args.props.forceDestroy === true) {
        reportViolation("AWS Backup vaults must not set forceDestroy.");
      }
    },
  },
  {
    name: "backup-plans-include-cross-region-copy",
    description:
      "AWS Backup plan rules must declare a copyAction to a remote vault and a non-trivial deleteAfter.",
    severity: "high",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:backup/plan:Plan") return;

      const rules = args.props.rules ?? [];
      for (const rule of rules) {
        if (!rule.copyActions || rule.copyActions.length === 0) {
          reportViolation(
            `AWS Backup rule '${rule.ruleName}' must declare a copyActions block to a remote vault.`,
          );
        }
        const deleteAfter = rule.lifecycle?.deleteAfter ?? 0;
        if (deleteAfter < 35) {
          reportViolation(
            `AWS Backup rule '${rule.ruleName}' lifecycle.deleteAfter must be at least 35 days.`,
          );
        }
      }
    },
  },
  {
    name: "wafv2-web-acl-has-rate-limit",
    description:
      "WAFv2 Web ACLs must include a rate-based statement to defeat brute force and credential stuffing.",
    severity: "high",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:wafv2/webAcl:WebAcl") return;

      const rules = args.props.rules ?? [];
      const hasRateLimit = rules.some(
        (rule: { statement?: { rateBasedStatement?: unknown } }) =>
          rule.statement?.rateBasedStatement,
      );
      if (!hasRateLimit) {
        reportViolation(
          "WAFv2 Web ACLs must include at least one rateBasedStatement rule.",
        );
      }

      const visibility = args.props.visibilityConfig ?? {};
      if (visibility.cloudwatchMetricsEnabled !== true) {
        reportViolation(
          "WAFv2 Web ACLs must enable CloudWatch metrics for visibility.",
        );
      }
    },
  },
  {
    name: "macie-account-finding-frequency",
    description:
      "Macie accounts must publish findings at least every fifteen minutes.",
    severity: "high",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:macie2/account:Account") return;

      if (args.props.findingPublishingFrequency !== "FIFTEEN_MINUTES") {
        reportViolation(
          "Macie accounts must set findingPublishingFrequency to FIFTEEN_MINUTES.",
        );
      }

      if (args.props.status !== "ENABLED") {
        reportViolation("Macie accounts must be enabled.");
      }
    },
  },
  {
    name: "cloudfront-distribution-hardened",
    description:
      "CloudFront distributions must use modern TLS, attach a WAF web ACL, log to S3, and use VPC Origins (no public-IP origins).",
    severity: "critical",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:cloudfront/distribution:Distribution") return;

      const viewerCert = args.props.viewerCertificate ?? {};
      const minimumProtocolVersion = viewerCert.minimumProtocolVersion;
      const acceptableTls = ["TLSv1.2_2021", "TLSv1.3_2021"];
      if (!acceptableTls.includes(minimumProtocolVersion)) {
        reportViolation(
          `CloudFront distribution viewer certificate must use minimumProtocolVersion in ${acceptableTls.join(", ")}.`,
        );
      }

      if (!args.props.webAclId) {
        reportViolation(
          "CloudFront distributions must attach a WAFv2 web ACL via webAclId.",
        );
      }

      if (!args.props.loggingConfig?.bucket) {
        reportViolation(
          "CloudFront distributions must enable access logging to an S3 bucket.",
        );
      }

      const origins: Array<Record<string, unknown>> = args.props.origins ?? [];
      if (origins.length === 0) {
        reportViolation("CloudFront distributions must declare origins.");
        return;
      }

      for (const origin of origins) {
        const isVpcOrigin = Boolean(origin.vpcOriginConfig);
        const isS3Origin = Boolean(origin.s3OriginConfig);
        if (!isVpcOrigin && !isS3Origin) {
          reportViolation(
            `CloudFront origin '${origin.originId}' must use vpcOriginConfig or s3OriginConfig. Public-IP origins are not allowed.`,
          );
        }

        const customOriginConfig = origin.customOriginConfig as
          | Record<string, unknown>
          | undefined;
        if (customOriginConfig) {
          reportViolation(
            `CloudFront origin '${origin.originId}' uses customOriginConfig (public origin). Switch to vpcOriginConfig for private NLB/ALB or s3OriginConfig with OAC.`,
          );
        }

        if (
          isVpcOrigin &&
          (origin.vpcOriginConfig as Record<string, unknown>)
            .originReadTimeout === undefined
        ) {
          // Soft hint, not a violation.
        }
      }

      const cacheBehavior = args.props.defaultCacheBehavior as
        | Record<string, unknown>
        | undefined;
      if (cacheBehavior?.viewerProtocolPolicy === "allow-all") {
        reportViolation(
          "CloudFront defaultCacheBehavior.viewerProtocolPolicy must redirect or require HTTPS.",
        );
      }
    },
  },
  {
    name: "acm-certificate-uses-dns-validation",
    description:
      "ACM certificates must use DNS validation; email validation is not auditable.",
    severity: "high",
    validateResource: (args, reportViolation) => {
      if (args.type !== "aws:acm/certificate:Certificate") return;

      if (args.props.validationMethod !== "DNS") {
        reportViolation("ACM certificates must use validationMethod: DNS.");
      }
    },
  },
];

function isProtectedBucket(args: ResourceValidationArgs) {
  return ["audit", "secrets-backup"].includes(args.props.tags?.DataClass);
}

function hasFullAccessPolicy(policy: unknown) {
  if (typeof policy !== "string") return false;

  try {
    const parsed = JSON.parse(policy);
    const statements: Array<{ Action?: unknown }> = Array.isArray(
      parsed.Statement,
    )
      ? parsed.Statement
      : [parsed.Statement];
    return statements.some((statement: { Action?: unknown }) =>
      hasFullAccessAction(statement?.Action),
    );
  } catch {
    return true;
  }
}

function hasPrincipalAccountCondition(policy: unknown) {
  if (typeof policy !== "string") return false;

  try {
    const parsed = JSON.parse(policy);
    const statements: Array<{
      Effect?: unknown;
      Condition?: Record<string, Record<string, unknown>>;
    }> = Array.isArray(parsed.Statement)
      ? parsed.Statement
      : [parsed.Statement];
    const allows = statements.filter(
      (statement) => statement && statement.Effect === "Allow",
    );
    return (
      allows.length > 0 &&
      allows.every((statement) => {
        const condition = statement.Condition ?? {};
        return Object.values(condition).some(
          (conditionValues) =>
            conditionValues &&
            typeof conditionValues === "object" &&
            Object.prototype.hasOwnProperty.call(
              conditionValues,
              "aws:PrincipalAccount",
            ) &&
            validPrincipalAccount(conditionValues["aws:PrincipalAccount"]),
        );
      })
    );
  } catch {
    return false;
  }
}

function validPrincipalAccount(value: unknown): boolean {
  if (typeof value === "string") return /^[0-9]{12}$/.test(value);
  return (
    Array.isArray(value) &&
    value.length > 0 &&
    value.every(
      (entry) => typeof entry === "string" && /^[0-9]{12}$/.test(entry),
    )
  );
}

function hasFullAccessAction(action: unknown): boolean {
  if (typeof action === "string")
    return action === "*" || action === "*:*" || /^[^:]+:\*$/.test(action);
  if (!Array.isArray(action)) return false;

  return action.some((entry) => hasFullAccessAction(entry));
}

function isIamPolicyDocumentResource(args: ResourceValidationArgs) {
  return [
    "aws:iam/policy:Policy",
    "aws:iam/rolePolicy:RolePolicy",
    "aws:iam/userPolicy:UserPolicy",
    "aws:iam/groupPolicy:GroupPolicy",
  ].includes(args.type);
}

function isIamManagedPolicyAttachmentResource(args: ResourceValidationArgs) {
  return [
    "aws:iam/rolePolicyAttachment:RolePolicyAttachment",
    "aws:iam/userPolicyAttachment:UserPolicyAttachment",
    "aws:iam/groupPolicyAttachment:GroupPolicyAttachment",
    "aws:iam/policyAttachment:PolicyAttachment",
    "aws:ssoadmin/managedPolicyAttachment:ManagedPolicyAttachment",
  ].includes(args.type);
}

function isIdentityCenterInlinePolicyResource(args: ResourceValidationArgs) {
  return (
    args.type ===
    "aws:ssoadmin/permissionSetInlinePolicy:PermissionSetInlinePolicy"
  );
}

function iamPolicyDocumentViolations(policy: unknown) {
  if (typeof policy !== "string") return [];

  try {
    const parsed = JSON.parse(policy);
    const statements = normalizeStatements(parsed.Statement);
    const violations: string[] = [];

    for (const statement of statements) {
      if (statement?.Effect !== "Allow") continue;

      if (statement.NotAction !== undefined) {
        violations.push(
          "IAM Allow policies must not use NotAction because it creates hard-to-review broad access.",
        );
      }

      if (hasFullAccessAction(statement.Action)) {
        violations.push(
          "IAM Allow policies must not use wildcard actions such as *, service:*, or *:*.",
        );
      }

      if (
        hasPrivilegeEscalationAction(statement.Action) &&
        hasUnboundedResource(statement.Resource)
      ) {
        violations.push(
          "IAM privilege-escalation actions such as iam:PassRole, iam:AttachRolePolicy, or sts:AssumeRole must be resource-scoped.",
        );
      }
    }

    return [...new Set(violations)];
  } catch {
    return [
      "IAM policy documents must be valid JSON so guardrails can inspect them.",
    ];
  }
}

function normalizeStatements(
  statement: unknown,
): Array<Record<string, unknown>> {
  if (Array.isArray(statement)) {
    return statement.filter(
      (entry): entry is Record<string, unknown> =>
        entry !== null && typeof entry === "object" && !Array.isArray(entry),
    );
  }

  if (
    statement !== null &&
    typeof statement === "object" &&
    !Array.isArray(statement)
  ) {
    return [statement as Record<string, unknown>];
  }

  return [];
}

function hasPrivilegeEscalationAction(action: unknown): boolean {
  const highRiskActions = [
    "iam:PassRole",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:UpdateAssumeRolePolicy",
    "iam:CreateAccessKey",
    "sts:AssumeRole",
  ];

  if (typeof action === "string") {
    if (hasFullAccessAction(action)) return true;
    return highRiskActions.some(
      (candidate) => action.toLowerCase() === candidate.toLowerCase(),
    );
  }

  if (!Array.isArray(action)) return false;

  return action.some((entry) => hasPrivilegeEscalationAction(entry));
}

function hasUnboundedResource(resource: unknown): boolean {
  if (resource === undefined) return true;
  if (typeof resource === "string") return resource === "*";
  if (!Array.isArray(resource)) return false;

  return resource.some((entry) => hasUnboundedResource(entry));
}

function isHighRiskManagedPolicyArn(policyArn: unknown) {
  if (typeof policyArn !== "string") return false;

  return /^arn:[^:]+:iam::aws:policy\/(AdministratorAccess|PowerUserAccess|IAMFullAccess)$/.test(
    policyArn,
  );
}

function hasPublicSecurityGroupCidr(rule: Record<string, unknown>) {
  return (
    rule.cidrIpv4 === "0.0.0.0/0" ||
    rule.cidrIpv6 === "::/0" ||
    (Array.isArray(rule.cidrBlocks) && rule.cidrBlocks.includes("0.0.0.0/0")) ||
    (Array.isArray(rule.ipv6CidrBlocks) && rule.ipv6CidrBlocks.includes("::/0"))
  );
}
