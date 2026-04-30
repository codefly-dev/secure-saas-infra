# Operations

## Egress Changes

The default stance is allowlisted internet egress. New domains should be added through Pulumi config under:

```yaml
secure-saas-infra:network:
  egress:
    allowedDomains:
      - example.com
```

For production, pair domain allowlists with application-level egress proxies where client code can request temporary access grants.

AWS service endpoint policies are generated in code. When a workload needs a
new AWS API action through a private endpoint, update the endpoint action set in
`src/network.ts`, add or adjust unit tests, and run `npm test`. Do not switch a
VPC endpoint back to the default full-access policy.

Endpoint policies are scoped to same-account principals and same-account
resources where AWS exposes the `aws:ResourceAccount` global key. Cross-account
artifact or storage access should use explicit broker roles and a reviewed
endpoint-policy change.

## Network Evidence

Centralized egress and workload spokes emit VPC Flow Logs to CloudWatch Logs.
AWS Network Firewall emits FLOW and ALERT logs when enabled. Production log
forwarding should route these log groups into the immutable log archive or the
security tooling account before customer-code workloads are admitted.

`network.egress.networkFirewallEnabled` is required (validated at preview) for
any `network-hub` or `single-account` stack whose `secure-saas-infra:environment`
is `production`/`prod`/`prd`/`staging` or any `*-prod`/`*-staging` value. Dev
stacks may disable the firewall, but the centralized inspection path must be on
in every other environment.

## Account Deployment

Run the stacks in this order:

1. `management`: creates OUs, member accounts, RAM organization sharing, and SCP guardrails.
2. `network`: creates centralized egress and shares the Transit Gateway to the organization.
3. account-specific `platform-*` and `execution-*`: create private spoke VPCs and EKS clusters in each workload account.
4. `network-routing`: accepts, associates, and routes the cross-account Transit Gateway attachments from the network account.
5. `dev`: optional single-account EKS baseline for validation.

Do not deploy workload stacks from the management account.

## Cluster Access

Use EKS Access Entries. Do not rely on the legacy `aws-auth` ConfigMap for human administration.

Add administrator role ARNs through:

```yaml
secure-saas-infra:adminRoleArns:
  - arn:aws:iam::123456789012:role/platform-admin
```

Platform, execution, and single-account stacks with private EKS endpoints are
rejected at preview time when `adminRoleArns` is empty. With
`bootstrapClusterCreatorAdminPermissions: false` and no Access Entries, no
human can administer the cluster after deploy. Populate at least one IAM
Identity Center or break-glass role ARN before previewing.

## Tailscale Instead of Bastions

Do not deploy SSH bastion hosts. Use Tailscale for private operator access.

The initial path is:

1. Apply the tailnet policy from `tailscale/policy.example.hujson` after replacing placeholder access rules.
2. Create a Tailscale OAuth client tagged `tag:k8s-operator` with the scopes required by the Kubernetes Operator.
3. Inject the OAuth credentials through Vault or another approved secret path.
4. Sync `gitops/bootstrap/argocd/tailscale-operator.application.yaml`.
5. Sync the platform cluster baseline so `platform-private-access` advertises the platform VPC CIDR.

Public SSH and public RDP should remain blocked by policy and Security Groups.

## Execution Plane

The preferred production execution path is E2B BYOC in a dedicated execution
AWS account. Keep the `execution` cluster as orchestration and fallback
infrastructure, not the normal hard boundary for arbitrary code. Use
[e2b-byoc.md](e2b-byoc.md) for the BYOC and self-hosting specification.

The execution GitOps baseline declares a `deus-microvm` RuntimeClass mapped to
the `kata-clh` handler and labels its scheduling target
`deus.dev/sandbox-runtime=microvm`. Kyverno denies execution pods unless they use
that RuntimeClass, disable service account token automount, and declare CPU,
memory, and ephemeral-storage limits. Execution pods must also include tenant
ID, job ID, source revision, egress profile, and sandbox-provider metadata, and
the namespace has ResourceQuota and LimitRange controls. Install the backing
runtime on labeled nodes before admitting fallback customer-code jobs; without
it, workloads fail closed.

Use [mind-server-security.md](mind-server-security.md) as the production gate for customer-code handling. The execution plane is not production-ready for customer code until the sandbox, egress, supply-chain, tenant isolation, and evidence requirements in that document are satisfied.

## Artifact Admission

Application pods must use digest-pinned images with Sigstore keyless signatures
from GitHub Actions, SLSA provenance attestations, and SPDX SBOM attestations.
The current policy trusts workflow identities under `refs/heads/main` and
version tags. If release signing moves to AWS KMS or a private Sigstore
deployment, update
`gitops/base/kyverno/verify-signed-provenance.yaml` and keep admission in
`Enforce` mode.

## Break-Glass

Break-glass roles should be:

- Outside normal SSO groups.
- MFA protected.
- Heavily alerted.
- Time limited.
- Logged into the central security account.
