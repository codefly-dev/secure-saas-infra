import { createHash } from "node:crypto";
import type { AwsPolicyDocument, AwsPolicyStatement } from "./policyDocuments";
import { canonicalPolicyJson, policyDocument } from "./policyDocuments";

export const AWS_BOOTSTRAP_ACCESS_API_VERSION =
  "security.deus.dev/aws-bootstrap-access/v1alpha1" as const;

export type AwsBootstrapAccountKind =
  | "security-tooling"
  | "log-archive"
  | "network"
  | "shared-services"
  | "platform"
  | "execution";

export type AwsInfrastructureActionSet =
  | "audit"
  | "backup"
  | "cost"
  | "data"
  | "database"
  | "dns"
  | "network"
  | "observability"
  | "security"
  | "workload";

export interface AwsBootstrapAccessAccount {
  accountName: string;
  accountId: string;
  kind: AwsBootstrapAccountKind;
  environmentClass: "nonproduction" | "preproduction" | "production";
  allowedRegions: readonly string[];
  resourceNamePrefix: string;
  actionSets: readonly AwsInfrastructureActionSet[];
  allowControllerPlan: boolean;
  allowControllerApply: boolean;
  productionApprovalRequired: boolean;
  roles: {
    planRoleName: string;
    applyRoleName: string;
    planPermissionsBoundaryName: string;
    applyPermissionsBoundaryName: string;
  };
}

export interface AwsBootstrapAccessPlan {
  apiVersion: typeof AWS_BOOTSTRAP_ACCESS_API_VERSION;
  kind: "AwsBootstrapAccessPlan";
  name: string;
  landingZoneOwner: "organizations" | "control-tower";
  organizationName: string;
  management: {
    accountId: string;
    workforceAccess: "iam-identity-center";
    accessInstallerRoleArn: string;
    humanFederationOnly: true;
    automationAccess: false;
    maxSessionDurationSeconds: number;
    root: {
      programmaticAccess: false;
      mfaRequired: true;
      multiPersonRecovery: true;
      centralizedMemberRootAccess: true;
      usedByAutomation: false;
      usedByPulumi: false;
    };
  };
  initialMemberHandoff: {
    roleName: string;
    purpose: "install-scoped-access-roles";
    humanApprovalRequired: true;
    automationAssumable: false;
    retireAfterScopedRolesReady: true;
  };
  controller: {
    roleArn: string;
    hostAccountId: string;
    identityMode: "eks-pod-identity";
    kubernetesNamespace: string;
    kubernetesServiceAccount: string;
    temporaryCredentials: true;
    maxSessionDurationSeconds: number;
    managementAccountAccess: false;
  };
  accounts: readonly AwsBootstrapAccessAccount[];
  deletion: {
    ordinaryApplyRoleAllowed: false;
    dedicatedRoleProvisioned: false;
    minimumApprovals: 2;
  };
}

export interface AwsAccessRolePolicyPlan {
  accountName: string;
  accountId: string;
  environmentClass: AwsBootstrapAccessAccount["environmentClass"];
  mode: "plan" | "apply";
  actionSet: AwsInfrastructureActionSet | null;
  roleName: string;
  roleArn: string;
  permissionsBoundaryName: string;
  permissionsBoundaryArn: string;
  trustedPrincipalArns: readonly string[];
  externalId: string;
  sourceIdentityPattern: string;
  maxSessionDurationSeconds: number;
  productionApprovalRequired: boolean;
  cloudMutation: boolean;
  destructiveMutation: false;
  trustPolicy: AwsPolicyDocument;
  permissionsPolicy: AwsPolicyDocument;
  permissionsBoundary: AwsPolicyDocument;
  delegatedRoleBoundary: {
    name: string;
    arn: string;
    policy: AwsPolicyDocument;
    canonicalPolicy: string;
  } | null;
  canonicalTrustPolicy: string;
  canonicalPermissionsPolicy: string;
  canonicalPermissionsBoundary: string;
}

export interface CompiledAwsBootstrapAccessPlan {
  apiVersion: typeof AWS_BOOTSTRAP_ACCESS_API_VERSION;
  sourceDigest: string;
  landingZoneOwner: AwsBootstrapAccessPlan["landingZoneOwner"];
  managementAccountId: string;
  initialHandoff: AwsBootstrapAccessPlan["initialMemberHandoff"];
  roles: readonly AwsAccessRolePolicyPlan[];
}

export interface AwsApplyLaneIamConstraint {
  sourceDigest: string;
  accountName: string;
  accountId: string;
  actionSet: AwsInfrastructureActionSet;
  roleNamePrefix: string;
  permissionsBoundaryArn: string;
}

const accountKindActionSets: Readonly<
  Record<AwsBootstrapAccountKind, readonly AwsInfrastructureActionSet[]>
> = {
  "security-tooling": ["observability", "security"],
  "log-archive": ["audit", "data", "observability"],
  network: ["dns", "network", "observability"],
  "shared-services": ["data", "dns", "observability"],
  platform: [
    "backup",
    "data",
    "database",
    "dns",
    "network",
    "observability",
    "workload",
  ],
  execution: [
    "backup",
    "data",
    "database",
    "network",
    "observability",
    "workload",
  ],
};

// These are deliberately exact AWS actions. No Allow statement produced by
// this compiler contains '*', 'service:*', or NotAction. The list is an
// initial reviewed ceiling, not a claim that a real preview has proven every
// action necessary. Access Analyzer and sandbox previews must narrow it.
const actionsBySet: Readonly<
  Record<AwsInfrastructureActionSet, readonly string[]>
> = {
  audit: [
    "cloudtrail:AddTags",
    "cloudtrail:CreateTrail",
    "cloudtrail:DescribeTrails",
    "cloudtrail:GetEventSelectors",
    "cloudtrail:GetInsightSelectors",
    "cloudtrail:GetTrail",
    "cloudtrail:GetTrailStatus",
    "cloudtrail:ListTags",
    "cloudtrail:ListTrails",
    "cloudtrail:PutEventSelectors",
    "cloudtrail:PutInsightSelectors",
    "cloudtrail:RemoveTags",
    "cloudtrail:StartLogging",
  ],
  backup: [
    "backup:CreateBackupPlan",
    "backup:CreateBackupSelection",
    "backup:CreateBackupVault",
    "backup:CreateFramework",
    "backup:CreateRestoreTestingPlan",
    "backup:CreateRestoreTestingSelection",
    "backup:DeleteBackupPlan",
    "backup:DeleteBackupSelection",
    "backup:DeleteFramework",
    "backup:DeleteRestoreTestingPlan",
    "backup:DeleteRestoreTestingSelection",
    "backup:DescribeBackupVault",
    "backup:GetBackupPlan",
    "backup:GetBackupSelection",
    "backup:GetBackupVaultAccessPolicy",
    "backup:GetBackupVaultLockConfiguration",
    "backup:GetRestoreTestingPlan",
    "backup:GetRestoreTestingSelection",
    "backup:ListBackupPlans",
    "backup:ListBackupSelections",
    "backup:ListBackupVaults",
    "backup:ListRestoreTestingPlans",
    "backup:ListTags",
    "backup:PutBackupVaultAccessPolicy",
    "backup:PutBackupVaultLockConfiguration",
    "backup:TagResource",
    "backup:UntagResource",
    "backup:UpdateBackupPlan",
    "backup:UpdateFramework",
    "backup:UpdateRestoreTestingPlan",
  ],
  cost: [
    "budgets:CreateBudget",
    "budgets:DeleteBudget",
    "budgets:DescribeBudget",
    "budgets:DescribeBudgets",
    "budgets:UpdateBudget",
    "ce:CreateAnomalyMonitor",
    "ce:CreateAnomalySubscription",
    "ce:DeleteAnomalyMonitor",
    "ce:DeleteAnomalySubscription",
    "ce:GetAnomalyMonitors",
    "ce:GetAnomalySubscriptions",
    "ce:UpdateAnomalyMonitor",
    "ce:UpdateAnomalySubscription",
  ],
  data: [
    "kms:CreateAlias",
    "kms:CreateKey",
    "kms:CreateGrant",
    "kms:DescribeKey",
    "kms:EnableKeyRotation",
    "kms:GetKeyPolicy",
    "kms:GetKeyRotationStatus",
    "kms:ListAliases",
    "kms:ListGrants",
    "kms:ListResourceTags",
    "kms:PutKeyPolicy",
    "kms:ReplicateKey",
    "kms:RetireGrant",
    "kms:TagResource",
    "kms:UntagResource",
    "kms:UpdateAlias",
    "kms:UpdateKeyDescription",
    "s3:CreateBucket",
    "s3:DeleteBucketLifecycle",
    "s3:DeleteBucketPolicy",
    "s3:GetBucketAcl",
    "s3:GetBucketLocation",
    "s3:GetBucketLogging",
    "s3:GetBucketObjectLockConfiguration",
    "s3:GetBucketOwnershipControls",
    "s3:GetBucketPolicy",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetBucketTagging",
    "s3:GetBucketVersioning",
    "s3:GetEncryptionConfiguration",
    "s3:GetLifecycleConfiguration",
    "s3:ListAllMyBuckets",
    "s3:ListBucket",
    "s3:PutBucketLifecycleConfiguration",
    "s3:PutBucketLogging",
    "s3:PutBucketObjectLockConfiguration",
    "s3:PutBucketOwnershipControls",
    "s3:PutBucketPolicy",
    "s3:PutBucketPublicAccessBlock",
    "s3:PutBucketTagging",
    "s3:PutBucketVersioning",
    "s3:PutEncryptionConfiguration",
    "secretsmanager:CreateSecret",
    "secretsmanager:DeleteResourcePolicy",
    "secretsmanager:DescribeSecret",
    "secretsmanager:GetResourcePolicy",
    "secretsmanager:ListSecrets",
    "secretsmanager:ListSecretVersionIds",
    "secretsmanager:PutResourcePolicy",
    "secretsmanager:TagResource",
    "secretsmanager:UntagResource",
    "secretsmanager:UpdateSecret",
  ],
  database: [
    "ec2:AuthorizeSecurityGroupEgress",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:CreateSecurityGroup",
    "ec2:CreateTags",
    "ec2:DeleteSecurityGroup",
    "ec2:DeleteTags",
    "ec2:DescribeSecurityGroupRules",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeTags",
    "ec2:DescribeVpcs",
    "ec2:ModifySecurityGroupRules",
    "ec2:RevokeSecurityGroupEgress",
    "ec2:RevokeSecurityGroupIngress",
    "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
    "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
    "kms:CreateAlias",
    "kms:CreateGrant",
    "kms:CreateKey",
    "kms:DescribeKey",
    "kms:EnableKeyRotation",
    "kms:GetKeyPolicy",
    "kms:GetKeyRotationStatus",
    "kms:ListAliases",
    "kms:ListGrants",
    "kms:ListResourceTags",
    "kms:PutKeyPolicy",
    "kms:RetireGrant",
    "kms:TagResource",
    "kms:UntagResource",
    "kms:UpdateAlias",
    "kms:UpdateKeyDescription",
    "rds:AddTagsToResource",
    "rds:CreateDBCluster",
    "rds:CreateDBClusterParameterGroup",
    "rds:CreateDBInstance",
    "rds:CreateDBProxy",
    "rds:CreateDBSubnetGroup",
    "rds:DeleteDBClusterParameterGroup",
    "rds:DeleteDBProxy",
    "rds:DeleteDBSubnetGroup",
    "rds:DeregisterDBProxyTargets",
    "rds:DescribeDBClusterParameterGroups",
    "rds:DescribeDBClusters",
    "rds:DescribeDBInstances",
    "rds:DescribeDBProxies",
    "rds:DescribeDBProxyTargetGroups",
    "rds:DescribeDBProxyTargets",
    "rds:DescribeDBSubnetGroups",
    "rds:ListTagsForResource",
    "rds:ModifyDBCluster",
    "rds:ModifyDBClusterParameterGroup",
    "rds:ModifyDBInstance",
    "rds:ModifyDBProxy",
    "rds:ModifyDBProxyTargetGroup",
    "rds:ModifyDBSubnetGroup",
    "rds:RegisterDBProxyTargets",
    "rds:RemoveTagsFromResource",
  ],
  dns: [
    "route53:AssociateVPCWithHostedZone",
    "route53:ChangeResourceRecordSets",
    "route53:CreateHostedZone",
    "route53:DeleteHostedZone",
    "route53:GetChange",
    "route53:GetHostedZone",
    "route53:ListHostedZones",
    "route53:ListResourceRecordSets",
    "route53:ListTagsForResource",
    "route53:UpdateHostedZoneComment",
    "route53resolver:AssociateResolverQueryLogConfig",
    "route53resolver:CreateResolverQueryLogConfig",
    "route53resolver:DeleteResolverQueryLogConfig",
    "route53resolver:DisassociateResolverQueryLogConfig",
    "route53resolver:GetResolverQueryLogConfig",
    "route53resolver:ListResolverQueryLogConfigAssociations",
    "route53resolver:ListResolverQueryLogConfigs",
    "route53resolver:ListTagsForResource",
    "route53resolver:TagResource",
    "route53resolver:UntagResource",
  ],
  network: [
    "ec2:AcceptTransitGatewayVpcAttachment",
    "ec2:AllocateAddress",
    "ec2:AssociateRouteTable",
    "ec2:AssociateTransitGatewayRouteTable",
    "ec2:AttachInternetGateway",
    "ec2:CreateFlowLogs",
    "ec2:CreateInternetGateway",
    "ec2:CreateNatGateway",
    "ec2:CreateRoute",
    "ec2:CreateRouteTable",
    "ec2:CreateSecurityGroup",
    "ec2:CreateSubnet",
    "ec2:CreateTags",
    "ec2:CreateTransitGateway",
    "ec2:CreateTransitGatewayRoute",
    "ec2:CreateTransitGatewayRouteTable",
    "ec2:CreateTransitGatewayVpcAttachment",
    "ec2:CreateVpc",
    "ec2:CreateVpcEndpoint",
    "ec2:DeleteFlowLogs",
    "ec2:DeleteInternetGateway",
    "ec2:DeleteNatGateway",
    "ec2:DeleteRoute",
    "ec2:DeleteRouteTable",
    "ec2:DeleteSecurityGroup",
    "ec2:DeleteSubnet",
    "ec2:DeleteTransitGatewayRoute",
    "ec2:DeleteTransitGatewayRouteTable",
    "ec2:DeleteTransitGatewayVpcAttachment",
    "ec2:DeleteVpc",
    "ec2:DeleteVpcEndpoints",
    "ec2:DescribeAddresses",
    "ec2:DescribeAvailabilityZones",
    "ec2:DescribeFlowLogs",
    "ec2:DescribeInternetGateways",
    "ec2:DescribeNatGateways",
    "ec2:DescribeRouteTables",
    "ec2:DescribeSecurityGroups",
    "ec2:DescribeSubnets",
    "ec2:DescribeTags",
    "ec2:DescribeTransitGatewayAttachments",
    "ec2:DescribeTransitGatewayRouteTables",
    "ec2:DescribeTransitGatewayVpcAttachments",
    "ec2:DescribeTransitGateways",
    "ec2:DescribeVpcAttribute",
    "ec2:DescribeVpcEndpoints",
    "ec2:DescribeVpcs",
    "ec2:DetachInternetGateway",
    "ec2:DisableTransitGatewayRouteTablePropagation",
    "ec2:DisassociateRouteTable",
    "ec2:DisassociateTransitGatewayRouteTable",
    "ec2:EnableTransitGatewayRouteTablePropagation",
    "ec2:ModifySubnetAttribute",
    "ec2:ModifyTransitGateway",
    "ec2:ModifyVpcAttribute",
    "ec2:ModifyVpcEndpoint",
    "ec2:ReleaseAddress",
    "ec2:ReplaceRoute",
    "ec2:RevokeSecurityGroupEgress",
    "ec2:RevokeSecurityGroupIngress",
    "ram:AssociateResourceShare",
    "ram:CreateResourceShare",
    "ram:DeleteResourceShare",
    "ram:DisassociateResourceShare",
    "ram:GetResourcePolicies",
    "ram:GetResourceShares",
    "ram:ListPrincipals",
    "ram:ListResources",
    "ram:TagResource",
    "ram:UntagResource",
    "ram:UpdateResourceShare",
  ],
  observability: [
    "events:DeleteRule",
    "events:DescribeRule",
    "events:DisableRule",
    "events:EnableRule",
    "events:ListRules",
    "events:ListTagsForResource",
    "events:ListTargetsByRule",
    "events:PutRule",
    "events:PutTargets",
    "events:RemoveTargets",
    "events:TagResource",
    "events:UntagResource",
    "logs:CreateLogGroup",
    "logs:DeleteLogGroup",
    "logs:DeleteResourcePolicy",
    "logs:DescribeLogGroups",
    "logs:DescribeResourcePolicies",
    "logs:ListTagsForResource",
    "logs:PutResourcePolicy",
    "logs:PutRetentionPolicy",
    "logs:TagResource",
    "logs:UntagResource",
    "sns:CreateTopic",
    "sns:DeleteTopic",
    "sns:GetSubscriptionAttributes",
    "sns:GetTopicAttributes",
    "sns:ListSubscriptionsByTopic",
    "sns:ListTagsForResource",
    "sns:SetSubscriptionAttributes",
    "sns:SetTopicAttributes",
    "sns:Subscribe",
    "sns:TagResource",
    "sns:Unsubscribe",
    "sns:UntagResource",
  ],
  security: [
    "config:DeleteConfigurationAggregator",
    "config:DeleteConformancePack",
    "config:DescribeConfigurationAggregators",
    "config:DescribeConformancePackStatus",
    "config:DescribeConformancePacks",
    "config:PutConfigurationAggregator",
    "config:PutConformancePack",
    "guardduty:CreateDetector",
    "guardduty:DescribeOrganizationConfiguration",
    "guardduty:GetDetector",
    "guardduty:ListDetectors",
    "guardduty:ListTagsForResource",
    "guardduty:TagResource",
    "guardduty:UntagResource",
    "guardduty:UpdateOrganizationConfiguration",
    "inspector2:Enable",
    "inspector2:GetDelegatedAdminAccount",
    "inspector2:ListAccountPermissions",
    "inspector2:ListMembers",
    "inspector2:UpdateOrganizationConfiguration",
    "macie2:CreateClassificationJob",
    "macie2:DescribeClassificationJob",
    "macie2:EnableMacie",
    "macie2:GetMacieSession",
    "macie2:ListClassificationJobs",
    "macie2:ListTagsForResource",
    "macie2:TagResource",
    "macie2:UntagResource",
    "securityhub:CreateFindingAggregator",
    "securityhub:DescribeHub",
    "securityhub:DescribeOrganizationConfiguration",
    "securityhub:EnableSecurityHub",
    "securityhub:GetFindingAggregator",
    "securityhub:ListFindingAggregators",
    "securityhub:ListTagsForResource",
    "securityhub:TagResource",
    "securityhub:UntagResource",
    "securityhub:UpdateOrganizationConfiguration",
  ],
  workload: [
    "acm:AddTagsToCertificate",
    "acm:DeleteCertificate",
    "acm:DescribeCertificate",
    "acm:ListCertificates",
    "acm:ListTagsForCertificate",
    "acm:RemoveTagsFromCertificate",
    "acm:RequestCertificate",
    "cloudfront:CreateDistribution",
    "cloudfront:CreateResponseHeadersPolicy",
    "cloudfront:CreateVpcOrigin",
    "cloudfront:DeleteDistribution",
    "cloudfront:DeleteResponseHeadersPolicy",
    "cloudfront:DeleteVpcOrigin",
    "cloudfront:GetDistribution",
    "cloudfront:GetDistributionConfig",
    "cloudfront:GetResponseHeadersPolicy",
    "cloudfront:GetVpcOrigin",
    "cloudfront:ListDistributions",
    "cloudfront:ListResponseHeadersPolicies",
    "cloudfront:ListTagsForResource",
    "cloudfront:ListVpcOrigins",
    "cloudfront:TagResource",
    "cloudfront:UntagResource",
    "cloudfront:UpdateDistribution",
    "cloudfront:UpdateResponseHeadersPolicy",
    "cloudfront:UpdateVpcOrigin",
    "ecr:CreateRepository",
    "ecr:DeleteLifecyclePolicy",
    "ecr:DeleteRepository",
    "ecr:DeleteRepositoryPolicy",
    "ecr:DescribeRepositories",
    "ecr:GetLifecyclePolicy",
    "ecr:GetRepositoryPolicy",
    "ecr:ListTagsForResource",
    "ecr:PutLifecyclePolicy",
    "ecr:SetRepositoryPolicy",
    "ecr:TagResource",
    "ecr:UntagResource",
    "eks:AssociateAccessPolicy",
    "eks:CreateAccessEntry",
    "eks:CreateAddon",
    "eks:CreateCluster",
    "eks:DeleteAccessEntry",
    "eks:DeleteAddon",
    "eks:DeleteCluster",
    "eks:DescribeAccessEntry",
    "eks:DescribeAddon",
    "eks:DescribeCluster",
    "eks:DescribeUpdate",
    "eks:DisassociateAccessPolicy",
    "eks:ListAccessEntries",
    "eks:ListAccessPolicies",
    "eks:ListAddons",
    "eks:ListAssociatedAccessPolicies",
    "eks:ListClusters",
    "eks:ListTagsForResource",
    "eks:TagResource",
    "eks:UntagResource",
    "eks:UpdateAccessEntry",
    "eks:UpdateAddon",
    "eks:UpdateClusterConfig",
    "eks:UpdateClusterVersion",
    "elasticloadbalancing:AddTags",
    "elasticloadbalancing:CreateListener",
    "elasticloadbalancing:CreateLoadBalancer",
    "elasticloadbalancing:CreateTargetGroup",
    "elasticloadbalancing:DeleteListener",
    "elasticloadbalancing:DeleteLoadBalancer",
    "elasticloadbalancing:DeleteTargetGroup",
    "elasticloadbalancing:DescribeListeners",
    "elasticloadbalancing:DescribeLoadBalancerAttributes",
    "elasticloadbalancing:DescribeLoadBalancers",
    "elasticloadbalancing:DescribeTags",
    "elasticloadbalancing:DescribeTargetGroupAttributes",
    "elasticloadbalancing:DescribeTargetGroups",
    "elasticloadbalancing:ModifyLoadBalancerAttributes",
    "elasticloadbalancing:ModifyTargetGroupAttributes",
    "elasticloadbalancing:RemoveTags",
    "wafv2:CreateWebACL",
    "wafv2:DeleteLoggingConfiguration",
    "wafv2:DeleteWebACL",
    "wafv2:GetLoggingConfiguration",
    "wafv2:GetWebACL",
    "wafv2:ListResourcesForWebACL",
    "wafv2:ListTagsForResource",
    "wafv2:ListWebACLs",
    "wafv2:PutLoggingConfiguration",
    "wafv2:TagResource",
    "wafv2:UntagResource",
    "wafv2:UpdateWebACL",
  ],
};

const readActions = [
  "access-analyzer:ValidatePolicy",
  "account:GetAccountInformation",
  "iam:GetRole",
  "iam:GetRolePolicy",
  "iam:ListAttachedRolePolicies",
  "iam:ListOpenIDConnectProviders",
  "iam:ListRolePolicies",
  "iam:ListRoleTags",
  "iam:ListRoles",
  "organizations:DescribeAccount",
  "organizations:DescribeOrganization",
  "organizations:ListAccounts",
  "organizations:ListParents",
  "tag:GetResources",
] as const;

const iamProvisioningActions = [
  "iam:AttachRolePolicy",
  "iam:CreateOpenIDConnectProvider",
  "iam:CreateRole",
  "iam:DeleteOpenIDConnectProvider",
  "iam:DeleteRole",
  "iam:DeleteRolePolicy",
  "iam:DetachRolePolicy",
  "iam:GetOpenIDConnectProvider",
  "iam:GetRole",
  "iam:GetRolePolicy",
  "iam:ListAttachedRolePolicies",
  "iam:ListOpenIDConnectProviders",
  "iam:ListRolePolicies",
  "iam:ListRoleTags",
  "iam:PassRole",
  "iam:PutRolePermissionsBoundary",
  "iam:PutRolePolicy",
  "iam:TagOpenIDConnectProvider",
  "iam:TagRole",
  "iam:UntagOpenIDConnectProvider",
  "iam:UntagRole",
  "iam:UpdateOpenIDConnectProviderThumbprint",
] as const;

const sensitiveResourcePolicyActions = new Set([
  "backup:PutBackupVaultAccessPolicy",
  "ecr:SetRepositoryPolicy",
  "kms:CreateGrant",
  "kms:PutKeyPolicy",
  "rds:CreateDBProxy",
  "s3:PutBucketPolicy",
  "secretsmanager:PutResourcePolicy",
  "sns:SetTopicAttributes",
]);

const rdsReadActionPattern = /^rds:(?:Describe|List)/;

const forbiddenActions = [
  "account:CloseAccount",
  "cloudtrail:DeleteTrail",
  "cloudtrail:StopLogging",
  "config:DeleteConfigurationRecorder",
  "config:DeleteDeliveryChannel",
  "config:StopConfigurationRecorder",
  "guardduty:DeleteDetector",
  "iam:CreateAccessKey",
  "iam:CreateLoginProfile",
  "iam:CreateUser",
  "iam:DeleteAccountPasswordPolicy",
  "iam:DeleteRolePermissionsBoundary",
  "iam:EnableOrganizationsRootCredentialsManagement",
  "iam:EnableOrganizationsRootSessions",
  "iam:UpdateAccessKey",
  "inspector2:Disable",
  "kms:DisableKey",
  "kms:DisableKeyRotation",
  "kms:ScheduleKeyDeletion",
  "organizations:CreateAccount",
  "organizations:CreateOrganization",
  "organizations:DeleteOrganization",
  "organizations:LeaveOrganization",
  "organizations:MoveAccount",
  "organizations:RemoveAccountFromOrganization",
  "securityhub:DisableSecurityHub",
  "sts:AssumeRoot",
] as const;

export function createReferenceAwsBootstrapAccessPlan(): AwsBootstrapAccessPlan {
  const managementAccountId = "999988887777";
  const controllerAccountId = "888877776666";
  const account = (
    input: Omit<
      AwsBootstrapAccessAccount,
      "allowedRegions" | "resourceNamePrefix" | "roles"
    >,
  ): AwsBootstrapAccessAccount => ({
    ...input,
    allowedRegions: ["us-east-1", "us-west-2"],
    resourceNamePrefix: `deus-${input.accountName}`,
    roles: {
      planRoleName: "InfrastructurePlan",
      applyRoleName:
        input.environmentClass === "production"
          ? "InfrastructureApplyProd"
          : "InfrastructureApplyNonProd",
      planPermissionsBoundaryName: "InfrastructurePlanBoundary",
      applyPermissionsBoundaryName: "InfrastructureApplyBoundary",
    },
  });

  return parseAwsBootstrapAccessPlan({
    apiVersion: AWS_BOOTSTRAP_ACCESS_API_VERSION,
    kind: "AwsBootstrapAccessPlan",
    name: "deus-rootless-bootstrap",
    landingZoneOwner: "organizations",
    organizationName: "deus",
    management: {
      accountId: managementAccountId,
      workforceAccess: "iam-identity-center",
      accessInstallerRoleArn: `arn:aws:iam::${managementAccountId}:role/ScopedAccessInstaller`,
      humanFederationOnly: true,
      automationAccess: false,
      maxSessionDurationSeconds: 3600,
      root: {
        programmaticAccess: false,
        mfaRequired: true,
        multiPersonRecovery: true,
        centralizedMemberRootAccess: true,
        usedByAutomation: false,
        usedByPulumi: false,
      },
    },
    initialMemberHandoff: {
      roleName: "DeusOrganizationBootstrap",
      purpose: "install-scoped-access-roles",
      humanApprovalRequired: true,
      automationAssumable: false,
      retireAfterScopedRolesReady: true,
    },
    controller: {
      roleArn: `arn:aws:iam::${controllerAccountId}:role/InfrastructureController`,
      hostAccountId: controllerAccountId,
      identityMode: "eks-pod-identity",
      kubernetesNamespace: "platform",
      kubernetesServiceAccount: "infrastructure-controller",
      temporaryCredentials: true,
      maxSessionDurationSeconds: 3600,
      managementAccountAccess: false,
    },
    accounts: [
      account({
        accountName: "security-tooling",
        accountId: "333322221111",
        kind: "security-tooling",
        environmentClass: "nonproduction",
        actionSets: ["observability", "security"],
        allowControllerPlan: false,
        allowControllerApply: false,
        productionApprovalRequired: false,
      }),
      account({
        accountName: "log-archive",
        accountId: "222211110000",
        kind: "log-archive",
        environmentClass: "nonproduction",
        actionSets: ["audit", "data", "observability"],
        allowControllerPlan: false,
        allowControllerApply: false,
        productionApprovalRequired: false,
      }),
      account({
        accountName: "network",
        accountId: "777766665555",
        kind: "network",
        environmentClass: "nonproduction",
        actionSets: ["dns", "network", "observability"],
        allowControllerPlan: false,
        allowControllerApply: false,
        productionApprovalRequired: false,
      }),
      account({
        accountName: "shared-services",
        accountId: "111100009999",
        kind: "shared-services",
        environmentClass: "nonproduction",
        actionSets: ["data", "dns", "observability"],
        allowControllerPlan: false,
        allowControllerApply: false,
        productionApprovalRequired: false,
      }),
      account({
        accountName: "platform-dev",
        accountId: controllerAccountId,
        kind: "platform",
        environmentClass: "nonproduction",
        actionSets: [
          "backup",
          "data",
          "database",
          "dns",
          "network",
          "observability",
          "workload",
        ],
        allowControllerPlan: false,
        allowControllerApply: false,
        productionApprovalRequired: false,
      }),
      account({
        accountName: "execution-dev",
        accountId: "666655554444",
        kind: "execution",
        environmentClass: "nonproduction",
        actionSets: [
          "backup",
          "data",
          "database",
          "network",
          "observability",
          "workload",
        ],
        allowControllerPlan: false,
        allowControllerApply: false,
        productionApprovalRequired: false,
      }),
      account({
        accountName: "platform-staging",
        accountId: "121212121212",
        kind: "platform",
        environmentClass: "preproduction",
        actionSets: [
          "backup",
          "data",
          "database",
          "dns",
          "network",
          "observability",
          "workload",
        ],
        allowControllerPlan: false,
        allowControllerApply: false,
        productionApprovalRequired: false,
      }),
      account({
        accountName: "execution-staging",
        accountId: "131313131313",
        kind: "execution",
        environmentClass: "preproduction",
        actionSets: [
          "backup",
          "data",
          "database",
          "network",
          "observability",
          "workload",
        ],
        allowControllerPlan: false,
        allowControllerApply: false,
        productionApprovalRequired: false,
      }),
      account({
        accountName: "platform-prod",
        accountId: "555544443333",
        kind: "platform",
        environmentClass: "production",
        actionSets: [
          "backup",
          "data",
          "database",
          "dns",
          "network",
          "observability",
          "workload",
        ],
        allowControllerPlan: false,
        allowControllerApply: false,
        productionApprovalRequired: true,
      }),
      account({
        accountName: "execution-prod",
        accountId: "444433332222",
        kind: "execution",
        environmentClass: "production",
        actionSets: [
          "backup",
          "data",
          "database",
          "network",
          "observability",
          "workload",
        ],
        allowControllerPlan: false,
        allowControllerApply: false,
        productionApprovalRequired: true,
      }),
    ],
    deletion: {
      ordinaryApplyRoleAllowed: false,
      dedicatedRoleProvisioned: false,
      minimumApprovals: 2,
    },
  });
}

export function parseAwsBootstrapAccessPlan(
  value: unknown,
): AwsBootstrapAccessPlan {
  const root = exactObject(value, "accessPlan", [
    "apiVersion",
    "kind",
    "name",
    "landingZoneOwner",
    "organizationName",
    "management",
    "initialMemberHandoff",
    "controller",
    "accounts",
    "deletion",
  ]);
  const management = exactObject(root.management, "accessPlan.management", [
    "accountId",
    "workforceAccess",
    "accessInstallerRoleArn",
    "humanFederationOnly",
    "automationAccess",
    "maxSessionDurationSeconds",
    "root",
  ]);
  const rootAccess = exactObject(
    management.root,
    "accessPlan.management.root",
    [
      "programmaticAccess",
      "mfaRequired",
      "multiPersonRecovery",
      "centralizedMemberRootAccess",
      "usedByAutomation",
      "usedByPulumi",
    ],
  );
  const handoff = exactObject(
    root.initialMemberHandoff,
    "accessPlan.initialMemberHandoff",
    [
      "roleName",
      "purpose",
      "humanApprovalRequired",
      "automationAssumable",
      "retireAfterScopedRolesReady",
    ],
  );
  const controller = exactObject(root.controller, "accessPlan.controller", [
    "roleArn",
    "hostAccountId",
    "identityMode",
    "kubernetesNamespace",
    "kubernetesServiceAccount",
    "temporaryCredentials",
    "maxSessionDurationSeconds",
    "managementAccountAccess",
  ]);
  const deletion = exactObject(root.deletion, "accessPlan.deletion", [
    "ordinaryApplyRoleAllowed",
    "dedicatedRoleProvisioned",
    "minimumApprovals",
  ]);

  const parsed: AwsBootstrapAccessPlan = {
    apiVersion: literal(
      root.apiVersion,
      "accessPlan.apiVersion",
      AWS_BOOTSTRAP_ACCESS_API_VERSION,
    ),
    kind: literal(root.kind, "accessPlan.kind", "AwsBootstrapAccessPlan"),
    name: identifier(root.name, "accessPlan.name"),
    landingZoneOwner: enumeration(
      root.landingZoneOwner,
      "accessPlan.landingZoneOwner",
      ["organizations", "control-tower"],
    ),
    organizationName: identifier(
      root.organizationName,
      "accessPlan.organizationName",
    ),
    management: {
      accountId: accountId(
        management.accountId,
        "accessPlan.management.accountId",
      ),
      workforceAccess: literal(
        management.workforceAccess,
        "accessPlan.management.workforceAccess",
        "iam-identity-center",
      ),
      accessInstallerRoleArn: roleArn(
        management.accessInstallerRoleArn,
        "accessPlan.management.accessInstallerRoleArn",
      ),
      humanFederationOnly: literal(
        management.humanFederationOnly,
        "accessPlan.management.humanFederationOnly",
        true,
      ),
      automationAccess: literal(
        management.automationAccess,
        "accessPlan.management.automationAccess",
        false,
      ),
      maxSessionDurationSeconds: sessionDuration(
        management.maxSessionDurationSeconds,
        "accessPlan.management.maxSessionDurationSeconds",
      ),
      root: {
        programmaticAccess: literal(
          rootAccess.programmaticAccess,
          "accessPlan.management.root.programmaticAccess",
          false,
        ),
        mfaRequired: literal(
          rootAccess.mfaRequired,
          "accessPlan.management.root.mfaRequired",
          true,
        ),
        multiPersonRecovery: literal(
          rootAccess.multiPersonRecovery,
          "accessPlan.management.root.multiPersonRecovery",
          true,
        ),
        centralizedMemberRootAccess: literal(
          rootAccess.centralizedMemberRootAccess,
          "accessPlan.management.root.centralizedMemberRootAccess",
          true,
        ),
        usedByAutomation: literal(
          rootAccess.usedByAutomation,
          "accessPlan.management.root.usedByAutomation",
          false,
        ),
        usedByPulumi: literal(
          rootAccess.usedByPulumi,
          "accessPlan.management.root.usedByPulumi",
          false,
        ),
      },
    },
    initialMemberHandoff: {
      roleName: iamName(
        handoff.roleName,
        "accessPlan.initialMemberHandoff.roleName",
      ),
      purpose: literal(
        handoff.purpose,
        "accessPlan.initialMemberHandoff.purpose",
        "install-scoped-access-roles",
      ),
      humanApprovalRequired: literal(
        handoff.humanApprovalRequired,
        "accessPlan.initialMemberHandoff.humanApprovalRequired",
        true,
      ),
      automationAssumable: literal(
        handoff.automationAssumable,
        "accessPlan.initialMemberHandoff.automationAssumable",
        false,
      ),
      retireAfterScopedRolesReady: literal(
        handoff.retireAfterScopedRolesReady,
        "accessPlan.initialMemberHandoff.retireAfterScopedRolesReady",
        true,
      ),
    },
    controller: {
      roleArn: roleArn(controller.roleArn, "accessPlan.controller.roleArn"),
      hostAccountId: accountId(
        controller.hostAccountId,
        "accessPlan.controller.hostAccountId",
      ),
      identityMode: literal(
        controller.identityMode,
        "accessPlan.controller.identityMode",
        "eks-pod-identity",
      ),
      kubernetesNamespace: kubernetesName(
        controller.kubernetesNamespace,
        "accessPlan.controller.kubernetesNamespace",
      ),
      kubernetesServiceAccount: kubernetesName(
        controller.kubernetesServiceAccount,
        "accessPlan.controller.kubernetesServiceAccount",
      ),
      temporaryCredentials: literal(
        controller.temporaryCredentials,
        "accessPlan.controller.temporaryCredentials",
        true,
      ),
      maxSessionDurationSeconds: sessionDuration(
        controller.maxSessionDurationSeconds,
        "accessPlan.controller.maxSessionDurationSeconds",
      ),
      managementAccountAccess: literal(
        controller.managementAccountAccess,
        "accessPlan.controller.managementAccountAccess",
        false,
      ),
    },
    accounts: uniqueArray(
      root.accounts,
      "accessPlan.accounts",
      parseAccount,
      (account) => account.accountId,
    ),
    deletion: {
      ordinaryApplyRoleAllowed: literal(
        deletion.ordinaryApplyRoleAllowed,
        "accessPlan.deletion.ordinaryApplyRoleAllowed",
        false,
      ),
      dedicatedRoleProvisioned: literal(
        deletion.dedicatedRoleProvisioned,
        "accessPlan.deletion.dedicatedRoleProvisioned",
        false,
      ),
      minimumApprovals: literal(
        deletion.minimumApprovals,
        "accessPlan.deletion.minimumApprovals",
        2,
      ),
    },
  };
  assertAwsBootstrapAccessPlan(parsed);
  return parsed;
}

export function assertAwsBootstrapAccessPlan(
  plan: AwsBootstrapAccessPlan,
): void {
  if (
    accountFromArn(plan.management.accessInstallerRoleArn) !==
    plan.management.accountId
  ) {
    throw new Error(
      "Management access-installer role must belong to the management account.",
    );
  }
  if (plan.controller.hostAccountId === plan.management.accountId) {
    throw new Error(
      "Infrastructure controller must not run in the management account.",
    );
  }
  if (
    accountFromArn(plan.controller.roleArn) !== plan.controller.hostAccountId
  ) {
    throw new Error(
      "Infrastructure controller role account does not match host account.",
    );
  }
  if (plan.accounts.length === 0) {
    throw new Error("AWS bootstrap access plan requires target accounts.");
  }
  const accountNames = new Set<string>();
  for (const account of plan.accounts) {
    if (accountNames.has(account.accountName)) {
      throw new Error(`Duplicate account name '${account.accountName}'.`);
    }
    accountNames.add(account.accountName);
    if (account.accountId === plan.management.accountId) {
      throw new Error(
        "Management account must not be a target access account.",
      );
    }
    if (
      account.environmentClass === "production" &&
      !account.productionApprovalRequired
    ) {
      throw new Error(
        `Production account '${account.accountName}' requires approval.`,
      );
    }
    if (account.allowControllerApply) {
      throw new Error(
        `Account '${account.accountName}' must not grant direct controller apply authority until a separately reviewed execution identity and broker are installed.`,
      );
    }
    if (account.allowControllerPlan) {
      throw new Error(
        `Account '${account.accountName}' must not trust the controller plan identity until its member-account role and EKS Pod Identity association have been independently materialized and verified.`,
      );
    }
    if (
      account.environmentClass !== "production" &&
      account.productionApprovalRequired
    ) {
      throw new Error(
        `Nonproduction account '${account.accountName}' must not claim production approval.`,
      );
    }
    const allowedSets = new Set(accountKindActionSets[account.kind]);
    for (const actionSet of account.actionSets) {
      if (!allowedSets.has(actionSet)) {
        throw new Error(
          `Account '${account.accountName}' cannot use action set '${actionSet}'.`,
        );
      }
    }
    if (account.actionSets.length === 0) {
      throw new Error(`Account '${account.accountName}' needs action sets.`);
    }
    if (account.roles.planRoleName === account.roles.applyRoleName) {
      throw new Error(
        `Account '${account.accountName}' must separate plan and apply roles.`,
      );
    }
    for (const actionSet of account.actionSets) {
      iamName(
        laneName(account.roles.applyRoleName, actionSet),
        `accounts.${account.accountName}.roles.applyRoleName(${actionSet})`,
      );
      iamName(
        laneName(account.roles.applyPermissionsBoundaryName, actionSet),
        `accounts.${account.accountName}.roles.applyPermissionsBoundaryName(${actionSet})`,
      );
    }
    for (const [index, region] of account.allowedRegions.entries()) {
      awsRegion(
        region,
        `accounts.${account.accountName}.allowedRegions[${index}]`,
      );
    }
  }
}

export function compileAwsBootstrapAccessPlan(
  value: unknown,
): CompiledAwsBootstrapAccessPlan {
  const plan = parseAwsBootstrapAccessPlan(value);
  const roles = plan.accounts
    .flatMap((account) => [
      compileRole(plan, account, "plan", null),
      ...account.actionSets.map((actionSet) =>
        compileRole(plan, account, "apply", actionSet),
      ),
    ])
    .sort((left, right) =>
      `${left.accountName}:${left.mode}:${left.actionSet ?? ""}`.localeCompare(
        `${right.accountName}:${right.mode}:${right.actionSet ?? ""}`,
      ),
    );
  return {
    apiVersion: AWS_BOOTSTRAP_ACCESS_API_VERSION,
    sourceDigest: createHash("sha256").update(stableJson(plan)).digest("hex"),
    landingZoneOwner: plan.landingZoneOwner,
    managementAccountId: plan.management.accountId,
    initialHandoff: plan.initialMemberHandoff,
    roles,
  };
}

export function compileAwsApplyLaneIamConstraint(
  value: unknown,
  accountName: string,
  actionSet: AwsInfrastructureActionSet,
): AwsApplyLaneIamConstraint {
  const plan = parseAwsBootstrapAccessPlan(value);
  const account = plan.accounts.find(
    (candidate) => candidate.accountName === accountName,
  );
  if (!account) {
    throw new Error(
      `AWS bootstrap access plan does not declare account '${accountName}'.`,
    );
  }
  if (!account.actionSets.includes(actionSet)) {
    throw new Error(
      `AWS bootstrap account '${accountName}' does not declare apply lane '${actionSet}'.`,
    );
  }
  const compiled = compileAwsBootstrapAccessPlan(plan);
  const lane = compiled.roles.find(
    (candidate) =>
      candidate.accountName === accountName &&
      candidate.mode === "apply" &&
      candidate.actionSet === actionSet,
  );
  if (!lane) {
    throw new Error(
      `AWS bootstrap account '${accountName}' did not compile apply lane '${actionSet}'.`,
    );
  }
  const roleNamePrefix = `${account.resourceNamePrefix}-${actionSet}-`;
  if (roleNamePrefix.length > 48) {
    throw new Error(
      `AWS apply lane '${accountName}/${actionSet}' role prefix leaves insufficient room for collision-resistant IAM role names.`,
    );
  }
  return {
    sourceDigest: compiled.sourceDigest,
    accountName,
    accountId: account.accountId,
    actionSet,
    roleNamePrefix,
    permissionsBoundaryArn:
      lane.delegatedRoleBoundary?.arn ?? lane.permissionsBoundaryArn,
  };
}

export function awsApplyLaneIamRoleName(
  constraint: AwsApplyLaneIamConstraint,
  semanticName: string,
): string {
  assertAwsApplyLaneIamConstraint(constraint);
  const slug = semanticName
    .toLowerCase()
    .replace(/[^a-z0-9+=,.@_-]+/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-|-$/g, "");
  if (!slug) {
    throw new Error("AWS apply-lane IAM role semantic name must not be empty.");
  }
  const digest = createHash("sha256")
    .update(semanticName)
    .digest("hex")
    .slice(0, 8);
  const available = 64 - constraint.roleNamePrefix.length - digest.length - 1;
  const result = `${constraint.roleNamePrefix}${slug.slice(0, available).replace(/-$/g, "")}-${digest}`;
  return iamName(result, "awsApplyLaneIamRoleName");
}

export function assertAwsApplyLaneIamConstraint(
  value: AwsApplyLaneIamConstraint,
  expectedActionSet?: AwsInfrastructureActionSet,
): void {
  if (
    value === null ||
    typeof value !== "object" ||
    !/^[a-f0-9]{64}$/.test(value.sourceDigest) ||
    !/^\d{12}$/.test(value.accountId) ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value.accountName) ||
    !/^[A-Za-z0-9+=,.@_-]+-$/.test(value.roleNamePrefix) ||
    value.roleNamePrefix.length > 48 ||
    !value.roleNamePrefix.endsWith(`-${value.actionSet}-`) ||
    !new Set<AwsInfrastructureActionSet>([
      "audit",
      "backup",
      "cost",
      "data",
      "database",
      "dns",
      "network",
      "observability",
      "security",
      "workload",
    ]).has(value.actionSet) ||
    value.permissionsBoundaryArn !==
      `arn:aws:iam::${value.accountId}:policy/${value.permissionsBoundaryArn.split("/").at(-1) ?? ""}` ||
    !/^arn:aws:iam::\d{12}:policy\/[A-Za-z0-9+=,.@_-]{1,128}$/.test(
      value.permissionsBoundaryArn,
    )
  ) {
    throw new Error("AWS apply-lane IAM constraint is malformed.");
  }
  if (expectedActionSet && value.actionSet !== expectedActionSet) {
    throw new Error(
      `AWS IAM role requires apply lane '${expectedActionSet}', not '${value.actionSet}'.`,
    );
  }
}

function compileRole(
  plan: AwsBootstrapAccessPlan,
  account: AwsBootstrapAccessAccount,
  mode: "plan" | "apply",
  actionSet: AwsInfrastructureActionSet | null,
): AwsAccessRolePolicyPlan {
  if ((mode === "plan") !== (actionSet === null)) {
    throw new Error(
      "Plan roles cannot select a lane and apply roles require one.",
    );
  }
  const roleName =
    mode === "plan"
      ? account.roles.planRoleName
      : laneName(account.roles.applyRoleName, actionSet!);
  const boundaryName =
    mode === "plan"
      ? account.roles.planPermissionsBoundaryName
      : laneName(account.roles.applyPermissionsBoundaryName, actionSet!);
  const boundaryArn = `arn:aws:iam::${account.accountId}:policy/${boundaryName}`;
  const delegatedRoleBoundary =
    mode === "apply" && actionSet === "database"
      ? compileDatabaseDelegatedRoleBoundary(plan, account, boundaryName)
      : null;
  const childRoleBoundaryArn = delegatedRoleBoundary?.arn ?? boundaryArn;
  const operatorArn = plan.management.accessInstallerRoleArn;
  const trustedPrincipalArns = [
    operatorArn,
    ...((mode === "plan" && account.allowControllerPlan) ||
    (mode === "apply" && account.allowControllerApply)
      ? [plan.controller.roleArn]
      : []),
  ].sort();
  const trustPolicy = policyDocument([
    {
      Sid: "TrustExactFederatedOperatorAndControllerRoles",
      Effect: "Allow",
      Action: ["sts:AssumeRole", "sts:SetSourceIdentity"],
      Principal: { AWS: trustedPrincipalArns },
      Condition: {
        StringEquals: {
          "sts:ExternalId": accessExternalId(
            plan.organizationName,
            account.accountName,
            mode,
            actionSet,
          ),
        },
        StringLike: {
          "sts:SourceIdentity": sourceIdentityPattern(
            plan.organizationName,
            account.accountName,
            mode,
            actionSet,
          ),
        },
      },
    },
  ]);
  const permissionsPolicy =
    mode === "plan"
      ? planPermissionsPolicy(account)
      : applyPermissionsPolicy(plan, account, childRoleBoundaryArn, actionSet!);
  const permissionsBoundary =
    mode === "plan"
      ? planPermissionsPolicy(account)
      : applyPermissionsPolicy(plan, account, childRoleBoundaryArn, actionSet!);
  assertManagedPolicySize(
    permissionsPolicy,
    `${account.accountName}/${mode}/${actionSet ?? "all"}`,
  );
  assertManagedPolicySize(
    permissionsBoundary,
    `${account.accountName}/${mode}/${actionSet ?? "all"} boundary`,
  );
  if (delegatedRoleBoundary) {
    assertManagedPolicySize(
      delegatedRoleBoundary.policy,
      `${account.accountName}/${actionSet}/delegated-role boundary`,
    );
  }
  const roleArnValue = `arn:aws:iam::${account.accountId}:role/${roleName}`;
  return {
    accountName: account.accountName,
    accountId: account.accountId,
    environmentClass: account.environmentClass,
    mode,
    actionSet,
    roleName,
    roleArn: roleArnValue,
    permissionsBoundaryName: boundaryName,
    permissionsBoundaryArn: boundaryArn,
    trustedPrincipalArns,
    externalId: accessExternalId(
      plan.organizationName,
      account.accountName,
      mode,
      actionSet,
    ),
    sourceIdentityPattern: sourceIdentityPattern(
      plan.organizationName,
      account.accountName,
      mode,
      actionSet,
    ),
    maxSessionDurationSeconds: Math.min(
      plan.controller.maxSessionDurationSeconds,
      3600,
    ),
    productionApprovalRequired:
      mode === "apply" && account.productionApprovalRequired,
    cloudMutation: mode === "apply",
    destructiveMutation: false,
    trustPolicy,
    permissionsPolicy,
    permissionsBoundary,
    delegatedRoleBoundary,
    canonicalTrustPolicy: canonicalPolicyJson(trustPolicy),
    canonicalPermissionsPolicy: canonicalPolicyJson(permissionsPolicy),
    canonicalPermissionsBoundary: canonicalPolicyJson(permissionsBoundary),
  };
}

function planPermissionsPolicy(
  account: AwsBootstrapAccessAccount,
): AwsPolicyDocument {
  const actions = [
    ...new Set([...readActions, ...readActionsFor(account.actionSets)]),
  ].sort();
  return policyDocument([
    {
      Sid: "AllowExactInfrastructureObservation",
      Effect: "Allow",
      Action: actions,
      Resource: "*",
    },
    forbiddenStatement(),
  ]);
}

function applyPermissionsPolicy(
  plan: AwsBootstrapAccessPlan,
  account: AwsBootstrapAccessAccount,
  childRoleBoundaryArn: string,
  actionSet: AwsInfrastructureActionSet,
): AwsPolicyDocument {
  const managedRoleArn = `arn:aws:iam::${account.accountId}:role/${account.resourceNamePrefix}-${actionSet}-*`;
  const managedOidcArn = `arn:aws:iam::${account.accountId}:oidc-provider/*`;
  const serviceActions = [...new Set(actionsBySet[actionSet])]
    .filter((action) => !action.startsWith("iam:"))
    .filter(
      (action) =>
        !action.startsWith("rds:") || rdsReadActionPattern.test(action),
    )
    .filter((action) => !sensitiveResourcePolicyActions.has(action))
    .filter((action) => !isDirectDestructiveAction(action))
    .sort();
  const managedRoleLifecycleActions = iamProvisioningActions.filter(
    (action) =>
      !action.includes("OpenIDConnectProvider") &&
      ![
        "iam:CreateRole",
        "iam:PassRole",
        "iam:PutRolePermissionsBoundary",
      ].includes(action) &&
      !isDirectDestructiveAction(action),
  );
  const statements: AwsPolicyStatement[] = [
    {
      Sid: "AllowServices",
      Effect: "Allow",
      Action: serviceActions,
      Resource: "*",
    },
    {
      Sid: "AllowBoundedRoleCreate",
      Effect: "Allow",
      Action: ["iam:CreateRole", "iam:PutRolePermissionsBoundary"],
      Resource: managedRoleArn,
      Condition: {
        ArnEquals: { "iam:PermissionsBoundary": childRoleBoundaryArn },
      },
    },
    {
      Sid: "AllowRoleLifecycle",
      Effect: "Allow",
      Action: managedRoleLifecycleActions,
      Resource: managedRoleArn,
    },
    {
      Sid: "AllowScopedPassRole",
      Effect: "Allow",
      Action: "iam:PassRole",
      Resource: managedRoleArn,
      Condition: {
        StringEquals: {
          "iam:PassedToService": [
            "backup.amazonaws.com",
            "ec2.amazonaws.com",
            "eks.amazonaws.com",
            "rds.amazonaws.com",
            "vpc-flow-logs.amazonaws.com",
          ],
        },
      },
    },
    {
      Sid: "AllowManagedOidcProviderLifecycle",
      Effect: "Allow",
      Action: iamProvisioningActions.filter(
        (action) =>
          action.includes("OpenIDConnectProvider") &&
          !isDirectDestructiveAction(action),
      ),
      Resource: managedOidcArn,
    },
    ...sensitivePolicyStatements(plan, account, actionSet),
    {
      Sid: "DenyOutsideRegions",
      Effect: "Deny",
      Action: "*",
      Resource: "*",
      Condition: {
        StringNotEquals: {
          "aws:RequestedRegion": [...account.allowedRegions].sort(),
        },
      },
    },
    {
      Sid: "DenyAccessLaneMutation",
      Effect: "Deny",
      Action: [
        "iam:DeletePolicy",
        "iam:DeletePolicyVersion",
        "iam:DeleteRole",
        "iam:DeleteRolePermissionsBoundary",
        "iam:SetDefaultPolicyVersion",
        "iam:UpdateAssumeRolePolicy",
      ],
      Resource: [
        `arn:aws:iam::${account.accountId}:role/${account.roles.planRoleName}`,
        `arn:aws:iam::${account.accountId}:role/${account.roles.applyRoleName}`,
        `arn:aws:iam::${account.accountId}:policy/${account.roles.planPermissionsBoundaryName}`,
        `arn:aws:iam::${account.accountId}:policy/${account.roles.applyPermissionsBoundaryName}`,
        childRoleBoundaryArn,
      ],
    },
    forbiddenStatement(),
  ];
  if (account.accountId === plan.management.accountId) {
    throw new Error("Apply policy compiler refuses the management account.");
  }
  return policyDocument(statements);
}

function compileDatabaseDelegatedRoleBoundary(
  plan: AwsBootstrapAccessPlan,
  account: AwsBootstrapAccessAccount,
  applyBoundaryName: string,
): NonNullable<AwsAccessRolePolicyPlan["delegatedRoleBoundary"]> {
  const name = iamName(
    `${applyBoundaryName}DelegatedRoles`,
    `${account.accountName}.databaseDelegatedRoleBoundaryName`,
  );
  const arn = `arn:aws:iam::${account.accountId}:policy/${name}`;
  const secretArn = `arn:aws:secretsmanager:*:${account.accountId}:secret:rds!cluster-*`;
  const policy = policyDocument([
    {
      Sid: "AllowExactRdsMonitoringLogs",
      Effect: "Allow",
      Action: [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:DescribeLogStreams",
        "logs:GetLogEvents",
        "logs:PutLogEvents",
        "logs:PutRetentionPolicy",
      ],
      Resource: [
        `arn:aws:logs:*:${account.accountId}:log-group:RDS*`,
        `arn:aws:logs:*:${account.accountId}:log-group:RDS*:log-stream:*`,
      ],
    },
    {
      Sid: "AllowDatabaseIamConnectCeiling",
      Effect: "Allow",
      Action: "rds-db:connect",
      Resource: `arn:aws:rds-db:*:${account.accountId}:dbuser:*/*`,
    },
    {
      Sid: "AllowRdsManagedSecretReadCeiling",
      Effect: "Allow",
      Action: "secretsmanager:GetSecretValue",
      Resource: secretArn,
    },
    {
      Sid: "AllowRdsManagedSecretDecryptCeiling",
      Effect: "Allow",
      Action: "kms:Decrypt",
      Resource: `arn:aws:kms:*:${account.accountId}:key/*`,
      Condition: {
        StringEquals: {
          "kms:ViaService": account.allowedRegions
            .map((region) => `secretsmanager.${region}.amazonaws.com`)
            .sort(),
        },
        StringLike: {
          "kms:EncryptionContext:SecretARN": secretArn,
        },
      },
    },
    {
      Sid: "DenyCriticalDestruction",
      Effect: "Deny",
      Action: [...forbiddenActions],
      Resource: "*",
    },
    {
      Sid: "DenyOutsideRegions",
      Effect: "Deny",
      Action: "*",
      Resource: "*",
      Condition: {
        StringNotEquals: {
          "aws:RequestedRegion": [...account.allowedRegions].sort(),
        },
      },
    },
  ]);
  return { name, arn, policy, canonicalPolicy: canonicalPolicyJson(policy) };
}

function sensitivePolicyStatements(
  plan: AwsBootstrapAccessPlan,
  account: AwsBootstrapAccessAccount,
  actionSet: AwsInfrastructureActionSet,
): AwsPolicyStatement[] {
  const prefix = account.resourceNamePrefix;
  const statements: AwsPolicyStatement[] = [];
  const actions = new Set(actionsBySet[actionSet]);
  const add = (
    sid: string,
    action: string,
    resource: string,
    condition?: AwsPolicyStatement["Condition"],
  ) => {
    if (!actions.has(action)) return;
    statements.push({
      Sid: sid,
      Effect: "Allow",
      Action: action,
      Resource: resource,
      ...(condition ? { Condition: condition } : {}),
    });
  };
  add(
    "AllowManagedBackupVaultPolicy",
    "backup:PutBackupVaultAccessPolicy",
    `arn:aws:backup:*:${account.accountId}:backup-vault:${prefix}-*`,
  );
  add(
    "AllowManagedEcrRepositoryPolicy",
    "ecr:SetRepositoryPolicy",
    `arn:aws:ecr:*:${account.accountId}:repository/${prefix}-*`,
  );
  add(
    "AllowManagedKmsGrantForAwsResources",
    "kms:CreateGrant",
    `arn:aws:kms:*:${account.accountId}:key/*`,
    {
      Bool: { "kms:GrantIsForAWSResource": true },
      StringEquals: {
        "aws:ResourceTag/ManagedBy": "pulumi",
        "aws:ResourceTag/Organization": plan.organizationName,
      },
    },
  );
  add(
    "AllowManagedKmsKeyPolicy",
    "kms:PutKeyPolicy",
    `arn:aws:kms:*:${account.accountId}:key/*`,
    {
      StringEquals: {
        "aws:ResourceTag/ManagedBy": "pulumi",
        "aws:ResourceTag/Organization": plan.organizationName,
      },
    },
  );
  if (actionSet === "database") {
    statements.push(...managedRdsPolicyStatements(plan, account));
  }
  add(
    "AllowManagedS3BucketPolicy",
    "s3:PutBucketPolicy",
    `arn:aws:s3:::${prefix}-*`,
  );
  add(
    "AllowManagedSecretResourcePolicy",
    "secretsmanager:PutResourcePolicy",
    `arn:aws:secretsmanager:*:${account.accountId}:secret:${prefix}-*`,
  );
  add(
    "AllowManagedSnsTopicPolicy",
    "sns:SetTopicAttributes",
    `arn:aws:sns:*:${account.accountId}:${prefix}-*`,
  );
  return statements;
}

function managedRdsPolicyStatements(
  plan: AwsBootstrapAccessPlan,
  account: AwsBootstrapAccessAccount,
): AwsPolicyStatement[] {
  const accountId = account.accountId;
  const prefix = account.resourceNamePrefix;
  const accountResources = `arn:aws:rds:*:${accountId}:*`;
  const requestCondition = {
    StringEquals: {
      "aws:RequestTag/ManagedBy": "pulumi",
      "aws:RequestTag/Organization": plan.organizationName,
    },
    StringLike: {
      "aws:RequestTag/Name": `${prefix}-*`,
    },
  } as const;
  const managedCondition = {
    StringEquals: {
      "aws:ResourceTag/ManagedBy": "pulumi",
      "aws:ResourceTag/Organization": plan.organizationName,
    },
  } as const;
  return [
    {
      Sid: "AllowRdsCreate",
      Effect: "Allow",
      Action: [
        "rds:CreateDBCluster",
        "rds:CreateDBClusterParameterGroup",
        "rds:CreateDBInstance",
        "rds:CreateDBProxy",
        "rds:CreateDBSubnetGroup",
      ],
      Resource: "*",
      Condition: requestCondition,
    },
    {
      Sid: "AllowRdsMutation",
      Effect: "Allow",
      Action: [
        "rds:AddTagsToResource",
        "rds:ModifyDBCluster",
        "rds:ModifyDBClusterParameterGroup",
        "rds:ModifyDBInstance",
        "rds:ModifyDBProxy",
        "rds:ModifyDBProxyTargetGroup",
        "rds:ModifyDBSubnetGroup",
        "rds:RegisterDBProxyTargets",
        "rds:RemoveTagsFromResource",
      ],
      Resource: accountResources,
      Condition: {
        ...managedCondition,
        "ForAllValues:StringNotEquals": {
          "aws:TagKeys": ["ManagedBy", "Organization"],
        },
      },
    },
    {
      Sid: "DenyRdsOwnerTagRemoval",
      Effect: "Deny",
      Action: "rds:RemoveTagsFromResource",
      Resource: accountResources,
      Condition: {
        "ForAnyValue:StringEquals": {
          "aws:TagKeys": ["ManagedBy", "Organization"],
        },
      },
    },
  ];
}

function forbiddenStatement(): AwsPolicyStatement {
  return {
    Sid: "DenyCriticalDestruction",
    Effect: "Deny",
    Action: [...forbiddenActions],
    Resource: "*",
  };
}

function isDirectDestructiveAction(action: string): boolean {
  const operation = action.split(":", 2)[1] ?? "";
  return /^(BatchDelete|Close|Delete|Deregister|Detach|Disable|Disassociate|Leave|Release|Remove|Retire|Revoke|ScheduleKeyDeletion|Stop|Unsubscribe)/.test(
    operation,
  );
}

function readActionsFor(sets: readonly AwsInfrastructureActionSet[]): string[] {
  return sets
    .flatMap((set) => actionsBySet[set])
    .filter((action) =>
      action
        .split(":", 2)[1]
        ?.match(/^(BatchGet|Describe|Get|List|Lookup|Search)/),
    );
}

function accessExternalId(
  organizationName: string,
  accountName: string,
  mode: "plan" | "apply",
  actionSet: AwsInfrastructureActionSet | null,
): string {
  return `${organizationName}:${accountName}:${mode}:${actionSet ?? "all"}:v1`;
}

function sourceIdentityPattern(
  organizationName: string,
  accountName: string,
  mode: "plan" | "apply",
  actionSet: AwsInfrastructureActionSet | null,
): string {
  return `${organizationName}-${accountName}-${mode}-${actionSet ?? "all"}-*`;
}

function laneName(base: string, actionSet: AwsInfrastructureActionSet): string {
  return `${base}-${actionSet
    .split("-")
    .map((part) => `${part[0]?.toUpperCase() ?? ""}${part.slice(1)}`)
    .join("")}`;
}

function assertManagedPolicySize(
  document: AwsPolicyDocument,
  description: string,
): void {
  const size = canonicalPolicyJson(document).length;
  if (size > 6_144) {
    throw new Error(
      `IAM managed policy '${description}' is ${size} characters; maximum is 6144. Split the capability lane instead of adding wildcard authority.`,
    );
  }
}

function parseAccount(value: unknown, path: string): AwsBootstrapAccessAccount {
  const input = exactObject(value, path, [
    "accountName",
    "accountId",
    "kind",
    "environmentClass",
    "allowedRegions",
    "resourceNamePrefix",
    "actionSets",
    "allowControllerPlan",
    "allowControllerApply",
    "productionApprovalRequired",
    "roles",
  ]);
  const roles = exactObject(input.roles, `${path}.roles`, [
    "planRoleName",
    "applyRoleName",
    "planPermissionsBoundaryName",
    "applyPermissionsBoundaryName",
  ]);
  return {
    accountName: identifier(input.accountName, `${path}.accountName`),
    accountId: accountId(input.accountId, `${path}.accountId`),
    kind: enumeration(input.kind, `${path}.kind`, [
      "security-tooling",
      "log-archive",
      "network",
      "shared-services",
      "platform",
      "execution",
    ]),
    environmentClass: enumeration(
      input.environmentClass,
      `${path}.environmentClass`,
      ["nonproduction", "preproduction", "production"],
    ),
    allowedRegions: uniqueArray(
      input.allowedRegions,
      `${path}.allowedRegions`,
      awsRegion,
    ),
    resourceNamePrefix: identifier(
      input.resourceNamePrefix,
      `${path}.resourceNamePrefix`,
    ),
    actionSets: uniqueArray(
      input.actionSets,
      `${path}.actionSets`,
      (entry, entryPath) =>
        enumeration(entry, entryPath, [
          "audit",
          "backup",
          "cost",
          "data",
          "database",
          "dns",
          "network",
          "observability",
          "security",
          "workload",
        ]),
    ),
    allowControllerPlan: booleanValue(
      input.allowControllerPlan,
      `${path}.allowControllerPlan`,
    ),
    allowControllerApply: booleanValue(
      input.allowControllerApply,
      `${path}.allowControllerApply`,
    ),
    productionApprovalRequired: booleanValue(
      input.productionApprovalRequired,
      `${path}.productionApprovalRequired`,
    ),
    roles: {
      planRoleName: iamName(roles.planRoleName, `${path}.roles.planRoleName`),
      applyRoleName: iamName(
        roles.applyRoleName,
        `${path}.roles.applyRoleName`,
      ),
      planPermissionsBoundaryName: iamName(
        roles.planPermissionsBoundaryName,
        `${path}.roles.planPermissionsBoundaryName`,
      ),
      applyPermissionsBoundaryName: iamName(
        roles.applyPermissionsBoundaryName,
        `${path}.roles.applyPermissionsBoundaryName`,
      ),
    },
  };
}

function exactObject(
  value: unknown,
  path: string,
  allowed: readonly string[],
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${path} must be an object.`);
  }
  const input = value as Record<string, unknown>;
  for (const key of Object.keys(input)) {
    if (!allowed.includes(key))
      throw new Error(`${path}.${key} is not allowed.`);
  }
  for (const key of allowed) {
    if (!(key in input)) throw new Error(`${path}.${key} is required.`);
  }
  return input;
}

function uniqueArray<T>(
  value: unknown,
  path: string,
  parse: (entry: unknown, path: string) => T,
  key: (entry: T) => unknown = (entry) => entry,
): T[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw new Error(`${path} must be a non-empty array.`);
  }
  const parsed = value.map((entry, index) => parse(entry, `${path}[${index}]`));
  const keys = parsed.map((entry) => JSON.stringify(key(entry)));
  if (new Set(keys).size !== keys.length) {
    throw new Error(`${path} must not contain duplicates.`);
  }
  return parsed;
}

function literal<T extends string | number | boolean>(
  value: unknown,
  path: string,
  expected: T,
): T {
  if (value !== expected) throw new Error(`${path} must be '${expected}'.`);
  return expected;
}

function enumeration<const T extends readonly string[]>(
  value: unknown,
  path: string,
  allowed: T,
): T[number] {
  if (typeof value !== "string" || !allowed.includes(value)) {
    throw new Error(`${path} must be one of ${allowed.join(", ")}.`);
  }
  return value as T[number];
}

function identifier(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value) ||
    value.includes("*") ||
    value.includes("..")
  ) {
    throw new Error(`${path} must be an exact identifier.`);
  }
  return value;
}

function iamName(value: unknown, path: string): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9+=,.@_-]{1,64}$/.test(value)) {
    throw new Error(`${path} must be an exact IAM name.`);
  }
  return value;
}

function accountId(value: unknown, path: string): string {
  if (typeof value !== "string" || !/^\d{12}$/.test(value)) {
    throw new Error(`${path} must be a 12-digit AWS account ID.`);
  }
  return value;
}

function roleArn(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^arn:aws(?:-[a-z]+)?:iam::\d{12}:role\/[A-Za-z0-9+=,.@_\/-]+$/.test(
      value,
    ) ||
    value.includes("*") ||
    value.endsWith(":root") ||
    value.includes(":user/")
  ) {
    throw new Error(`${path} must be an exact IAM role ARN.`);
  }
  return value;
}

function accountFromArn(value: string): string {
  return value.split(":")[4] ?? "";
}

function sessionDuration(value: unknown, path: string): number {
  if (
    !Number.isSafeInteger(value) ||
    (value as number) < 900 ||
    (value as number) > 3600
  ) {
    throw new Error(`${path} must be between 900 and 3600 seconds.`);
  }
  return value as number;
}

function awsRegion(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^[a-z]{2}(?:-gov)?-[a-z]+-\d$/.test(value)
  ) {
    throw new Error(`${path} must be an exact AWS region.`);
  }
  return value;
}

function kubernetesName(value: unknown, path: string): string {
  if (
    typeof value !== "string" ||
    !/^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(value)
  ) {
    throw new Error(`${path} must be an exact Kubernetes name.`);
  }
  return value;
}

function booleanValue(value: unknown, path: string): boolean {
  if (typeof value !== "boolean") throw new Error(`${path} must be boolean.`);
  return value;
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}
