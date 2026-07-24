"use strict";

const BASELINE_SCP_DOCUMENT = Object.freeze({
  Version: "2012-10-17",
  Statement: Object.freeze([
    Object.freeze({
      Sid: "DenyLeaveOrganization",
      Effect: "Deny",
      Action: Object.freeze(["organizations:LeaveOrganization"]),
      Resource: "*",
    }),
    Object.freeze({
      Sid: "DenyDisableAuditAndDetection",
      Effect: "Deny",
      Action: Object.freeze([
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail",
        "config:DeleteConfigRule",
        "config:DeleteConfigurationRecorder",
        "config:DeleteDeliveryChannel",
        "config:StopConfigurationRecorder",
        "guardduty:DeleteDetector",
        "guardduty:DisassociateFromAdministratorAccount",
        "guardduty:DisassociateFromMasterAccount",
        "guardduty:DisassociateMembers",
        "guardduty:StopMonitoringMembers",
        "securityhub:DisableSecurityHub",
        "securityhub:DisassociateFromAdministratorAccount",
        "securityhub:DisassociateMembers",
        "inspector2:Disable",
      ]),
      Resource: "*",
    }),
    Object.freeze({
      Sid: "DenyIamUserAndAccessKeyCreation",
      Effect: "Deny",
      Action: Object.freeze([
        "iam:CreateUser",
        "iam:CreateAccessKey",
        "iam:UpdateAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile",
      ]),
      Resource: "*",
    }),
    Object.freeze({
      Sid: "DenyKmsRotationDisable",
      Effect: "Deny",
      Action: Object.freeze([
        "kms:DisableKeyRotation",
        "kms:ScheduleKeyDeletion",
      ]),
      Resource: "*",
    }),
    Object.freeze({
      Sid: "DenyEbsDefaultEncryptionDisable",
      Effect: "Deny",
      Action: Object.freeze(["ec2:DisableEbsEncryptionByDefault"]),
      Resource: "*",
    }),
    Object.freeze({
      Sid: "DenyCloudTrailMutations",
      Effect: "Deny",
      Action: Object.freeze([
        "cloudtrail:DeleteTrail",
        "cloudtrail:StopLogging",
        "cloudtrail:UpdateTrail",
        "cloudtrail:PutEventSelectors",
        "cloudtrail:PutInsightSelectors",
      ]),
      Resource: "*",
    }),
  ]),
});

const SUSPENDED_SCP_DOCUMENT = Object.freeze({
  Version: "2012-10-17",
  Statement: Object.freeze([
    Object.freeze({
      Sid: "DenyAllSuspendedAccountActions",
      Effect: "Deny",
      Action: "*",
      Resource: "*",
    }),
  ]),
});

const S3_PUBLIC_ACCESS_BLOCK_DOCUMENT = Object.freeze({
  s3_attributes: Object.freeze({
    public_access_block_configuration: Object.freeze({ "@@assign": "all" }),
  }),
});

module.exports = Object.freeze({
  BASELINE_SCP_DOCUMENT,
  S3_PUBLIC_ACCESS_BLOCK_DOCUMENT,
  SUSPENDED_SCP_DOCUMENT,
});
