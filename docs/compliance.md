# Continuous Compliance

The `compliance` stack deploys the AWS Config conformance pack covering the
high-leverage CIS/NIST controls and (optionally) an AWS Audit Manager
assessment for SOC 2 evidence collection.

## Conformance pack

`Pulumi.compliance.yaml.example` deploys an organization conformance pack
with rules for:

- CloudTrail enabled, multi-region, log file validation, encryption.
- S3: public read/write prohibited, SSL only, default encryption.
- RDS: storage encrypted, no public access, deletion protection.
- EKS: no public endpoint, secrets encrypted.
- IAM: no inline user policies, root MFA, KMS rotation.
- EC2: EBS default encryption, IMDSv2, no SSH ingress, VPC Flow Logs.

Findings flow into Security Hub. The `detection` stack's
`config-noncompliant-resource` EventBridge rule alerts on every transition to
`NON_COMPLIANT`.

## SOC 2 evidence

To activate Audit Manager evidence collection:

1. Pick the SOC 2 framework in Audit Manager (`AWS::AuditManager::Framework/<id>`).
2. Create or select an S3 bucket for evidence reports.
3. Set:

```yaml
secure-saas-infra:compliance:
  deployConformancePack: true
  createAuditManagerAssessment: true
  auditManagerFrameworkArn: arn:aws:auditmanager:us-east-1:aws:assessmentFramework/<framework-id>
  auditEvidenceBucket: deus-soc2-evidence
  auditManagerAccountIds: ["111122223333", "111122223334", ...]
  auditManagerRoleArns:
    - arn:aws:iam::111122223333:role/audit-manager-evidence-collector
```

Audit Manager runs the framework on the listed accounts, collects evidence
into the S3 bucket, and produces SOC 2 Type II ready reports.

## Manual evidence

Evidence that AWS Config and Audit Manager don't capture:

- GitHub rulesets, required checks, CODEOWNERS enforcement
  (`docs/github-security.md`).
- Tabletop exercise records (`docs/incident-response.md`).
- Quarterly DR restore drills (`docs/disaster-recovery.md`).
- Penetration test reports.
- Vendor security questionnaires (E2B BYOC, model providers).
- Customer DPA signatures.

These belong in a separate evidence repository (Drata, Vanta, or a private S3
bucket) tagged to the SOC 2 trust criteria.
