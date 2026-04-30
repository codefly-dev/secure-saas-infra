import * as aws from "@pulumi/aws";
import { ComplianceConfig, baseTags, named } from "./config";

export interface ComplianceResult {
  conformancePack?: aws.cfg.ConformancePack;
  auditManagerAssessment?: aws.auditmanager.Assessment;
}

export function createComplianceBaseline(
  config: ComplianceConfig,
): ComplianceResult {
  let conformancePack: aws.cfg.ConformancePack | undefined;

  if (config.deployConformancePack) {
    conformancePack = new aws.cfg.ConformancePack(
      named("conformance-pack-cis"),
      {
        name: named("conformance-pack-cis"),
        templateBody: cisAwsFoundationsConformancePack(),
      },
    );
  }

  let auditManagerAssessment: aws.auditmanager.Assessment | undefined;
  if (
    config.createAuditManagerAssessment &&
    config.auditManagerFrameworkArn &&
    config.auditEvidenceBucket
  ) {
    auditManagerAssessment = new aws.auditmanager.Assessment(
      named("audit-manager-soc2"),
      {
        name: named("audit-manager-soc2"),
        description:
          "SOC 2 Trust Services Criteria evidence collection for the secure SaaS baseline.",
        frameworkId: config.auditManagerFrameworkArn,
        assessmentReportsDestination: {
          destination: `s3://${config.auditEvidenceBucket}`,
          destinationType: "S3",
        },
        scope: {
          awsAccounts: config.auditManagerAccountIds.map((accountId) => ({
            id: accountId,
          })),
          awsServices: [],
        },
        roles: config.auditManagerRoleArns.map((roleArn) => ({
          roleType: "PROCESS_OWNER",
          roleArn,
        })),
        tags: tag("audit-manager-soc2", { EvidenceClass: "compliance" }),
      },
    );
  }

  return { conformancePack, auditManagerAssessment };
}

function cisAwsFoundationsConformancePack() {
  return `Resources:
  CloudTrailEnabled:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: cloudtrail-enabled
      Source:
        Owner: AWS
        SourceIdentifier: CLOUD_TRAIL_ENABLED
  CloudTrailLogFileValidation:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: cloudtrail-log-file-validation-enabled
      Source:
        Owner: AWS
        SourceIdentifier: CLOUD_TRAIL_LOG_FILE_VALIDATION_ENABLED
  CloudTrailEncrypted:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: cloud-trail-encryption-enabled
      Source:
        Owner: AWS
        SourceIdentifier: CLOUD_TRAIL_ENCRYPTION_ENABLED
  S3BucketPublicReadProhibited:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: s3-bucket-public-read-prohibited
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_PUBLIC_READ_PROHIBITED
  S3BucketPublicWriteProhibited:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: s3-bucket-public-write-prohibited
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_PUBLIC_WRITE_PROHIBITED
  S3BucketSSLRequestsOnly:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: s3-bucket-ssl-requests-only
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_SSL_REQUESTS_ONLY
  S3DefaultEncryption:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: s3-bucket-server-side-encryption-enabled
      Source:
        Owner: AWS
        SourceIdentifier: S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED
  RDSStorageEncrypted:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: rds-storage-encrypted
      Source:
        Owner: AWS
        SourceIdentifier: RDS_STORAGE_ENCRYPTED
  RDSPublicAccessProhibited:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: rds-instance-public-access-check
      Source:
        Owner: AWS
        SourceIdentifier: RDS_INSTANCE_PUBLIC_ACCESS_CHECK
  RDSDeletionProtection:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: rds-cluster-deletion-protection-enabled
      Source:
        Owner: AWS
        SourceIdentifier: RDS_CLUSTER_DELETION_PROTECTION_ENABLED
  EKSEndpointNoPublicAccess:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: eks-endpoint-no-public-access
      Source:
        Owner: AWS
        SourceIdentifier: EKS_ENDPOINT_NO_PUBLIC_ACCESS
  EKSSecretsEncrypted:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: eks-secrets-encrypted
      Source:
        Owner: AWS
        SourceIdentifier: EKS_SECRETS_ENCRYPTED
  IamUserNoAccessKey:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: iam-user-no-policies-check
      Source:
        Owner: AWS
        SourceIdentifier: IAM_USER_NO_POLICIES_CHECK
  IamRootMfaEnabled:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: root-account-mfa-enabled
      Source:
        Owner: AWS
        SourceIdentifier: ROOT_ACCOUNT_MFA_ENABLED
  KmsKeyRotation:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: cmk-backing-key-rotation-enabled
      Source:
        Owner: AWS
        SourceIdentifier: CMK_BACKING_KEY_ROTATION_ENABLED
  EbsEncryptedByDefault:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: ec2-ebs-encryption-by-default
      Source:
        Owner: AWS
        SourceIdentifier: EC2_EBS_ENCRYPTION_BY_DEFAULT
  Imdsv2Required:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: ec2-imdsv2-check
      Source:
        Owner: AWS
        SourceIdentifier: EC2_IMDSV2_CHECK
  RestrictedSshIngress:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: restricted-ssh
      Source:
        Owner: AWS
        SourceIdentifier: INCOMING_SSH_DISABLED
  VpcFlowLogsEnabled:
    Type: AWS::Config::ConfigRule
    Properties:
      ConfigRuleName: vpc-flow-logs-enabled
      Source:
        Owner: AWS
        SourceIdentifier: VPC_FLOW_LOGS_ENABLED
`;
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
