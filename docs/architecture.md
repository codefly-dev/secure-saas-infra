# Architecture Baseline

## Security Boundary

Client code is untrusted. It must not run in the same trust boundary as the SaaS control plane or persistent customer data services.

The account model separates:

- management account: AWS Organizations and account vending;
- security tooling account: detection and security administration;
- log archive account: immutable audit logs;
- network account: centralized egress, Transit Gateway, and inspection;
- shared-services account: Vault and shared internal services;
- platform accounts: SaaS control plane workloads by environment;
- execution accounts: client-code execution by environment.

The single-account dev implementation starts with two workload spokes:

- `platform`: SaaS control plane, internal services, GitOps agents, policy controllers.
- `execution`: isolated compute plane for untrusted or semi-trusted client code.

Production should run customer-code execution through E2B BYOC in dedicated
execution accounts. High-risk tenants should receive dedicated execution
accounts, dedicated KMS keys, and dedicated egress policy. Fully self-hosted E2B
is the fallback for tenants that cannot accept the BYOC control-plane model.

The modular multi-account path uses separate Pulumi stacks for the network hub, each platform/execution spoke account, and the network-account routing resources that accept and route cross-account Transit Gateway attachments.

## Network Pattern

The network uses centralized inspection and egress:

```text
Private workload VPCs
        |
        v
Transit Gateway
        |
        v
Central egress / inspection VPC
        |
AWS Network Firewall
        |
NAT Gateway
        |
Internet Gateway
```

Workload VPCs have no direct Internet Gateway and no NAT Gateway. Their default
route goes to Transit Gateway. AWS service access uses private VPC endpoints
with explicit endpoint policies, including the EKS Auth endpoint required for
EKS Pod Identity in private clusters. Endpoint policies scope access to
same-account principals and same-account resources where AWS exposes the
`aws:ResourceAccount` global key.

The network layer emits VPC Flow Logs for the egress VPC and each workload
spoke. When AWS Network Firewall is enabled, it emits FLOW and ALERT logs to
CloudWatch Logs for security review and later forwarding to the log archive.

## Private Access Pattern

There are no bastion hosts in the baseline. Tailscale is the private access layer for operators and administrators.

Use the Tailscale Kubernetes Operator for API server proxying, private service exposure, and subnet-router style access to the platform VPC. Keep execution-plane Tailscale access disabled by default or restricted to an explicit break-glass tag.

Tailscale must not become the normal internet egress path for client code. Client-code egress stays on the centralized inspection and egress VPC path.

## Identity Pattern

Human AWS access uses IAM Identity Center permission sets assigned to groups. IAM users are not part of the baseline. Use an external IdP with SCIM for real users, keep break-glass membership empty by default, and add only the required IAM Identity Center role ARNs to EKS Access Entries.

GitHub Actions access uses OIDC roles in each target AWS account. Trust policies are constrained to `sts.amazonaws.com`, explicit repositories, and explicit refs or protected GitHub environments. No long-lived AWS keys should be stored in GitHub.

## Kubernetes Pattern

EKS clusters are private endpoint clusters by default. The scaffold enables:

- EKS Auto Mode.
- EKS Access Entries instead of the legacy `aws-auth` ConfigMap.
- EKS Pod Identity Agent.
- Kubernetes control plane logs.
- VPC CNI network policy in strict mode.
- GitOps-managed namespace, network policy, and Kyverno baseline.

Namespaces are not treated as hard security boundaries. For client code, use
E2B BYOC or a fully self-hosted equivalent in dedicated execution accounts; use
microVM-backed Kubernetes execution only as a fail-closed fallback.

The execution baseline includes a fail-closed sandbox admission path: execution
pods must request the `deus-microvm` RuntimeClass, which maps to Kata Cloud
Hypervisor on nodes labeled `deus.dev/sandbox-runtime=microvm`. The RuntimeClass
declaration and admission policy prevent regular-container execution if the
backing runtime is not installed. Execution pods also require tenant/job/source
metadata, egress-profile metadata, service-account token automount disabled,
resource limits, and namespace quota controls.

Application images are admitted only after digest pinning, Sigstore keyless
signature verification, SLSA provenance verification, and SPDX SBOM attestation
verification. The trusted identity is GitHub Actions OIDC for main-branch and
version-tag release workflows.

For Mind server's customer-code threat model, use [mind-server-security.md](mind-server-security.md) as the normative security baseline and production-readiness checklist.

## Secrets Pattern

Vault should run outside the workload cluster trust boundary, preferably in a dedicated shared-services or security account. Kubernetes workloads should consume short-lived dynamic secrets through Vault Secrets Operator, CSI, or direct Vault API access depending on workload risk.
