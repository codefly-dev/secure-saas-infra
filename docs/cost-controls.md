# Cost Controls and Abuse Defense

Crypto-mining and runaway agent loops are the two most common failure modes of
"customer code in the cloud". The `cost-controls` stack deploys per-tenant AWS
Budgets and Cost Anomaly Detection so they show up in minutes, not days.

## Per-tenant budgets

Each entry in `costControls.tenantBudgets` becomes an AWS Budgets `Budget`
with:

- monthly cost limit, threshold percent (default 80), and email
  notifications;
- cost filter on the `TenantId` cost allocation tag — every workload that
  runs customer code must tag its resources with
  `{Key: "TenantId", Value: <tenantId>}` so the budget filter matches.

```yaml
secure-saas-infra:costControls:
  notificationEmails:
    - finops@your-org.example
    - security-alerts@your-org.example
  enableAnomalyDetection: true
  anomalyMinImpactUsd: 100
  tenantBudgets:
    - tenantId: enterprise-tenant-1
      monthlyLimitUsd: 50000
      thresholdPercent: 80
    - tenantId: free-tier-tenant
      monthlyLimitUsd: 25
      thresholdPercent: 90
```

## Cost Anomaly Detection

The stack also deploys a `DIMENSIONAL` cost anomaly monitor scoped to
`SERVICE` plus a daily subscription that emails the notification list when
anomaly impact crosses `anomalyMinImpactUsd`.

This catches:

- a single tenant suddenly spending $X on Bedrock or EC2;
- crypto-miners that escape the sandbox and start consuming GPU-class
  instances;
- accidental costly mistakes (e.g., NAT data transfer due to a misconfigured
  egress proxy).

## Application-layer enforcement

AWS Budgets is the _floor_, not the _ceiling_. The agent broker enforces:

- per-tenant token budget (`agenticAi.perTenantTokenBudget`);
- per-tenant inference timeout (`agenticAi.perTenantInferenceTimeoutSeconds`);
- per-tenant ResourceQuota in Kubernetes (extend
  `gitops/base/quotas/execution-limits.yaml` to include per-tenant LimitRange
  objects when tenant-aware namespaces ship).

## Tag policy

Add a Pulumi-managed tag policy in the management account that requires the
`TenantId` tag on EC2, RDS, S3, and EKS resources allocated to customer-code
workloads. This isn't in the baseline yet — it's the next iteration of
tenant-aware FinOps.
