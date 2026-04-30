# E2B BYOC Execution Specification

Mind server should use E2B BYOC as the preferred production execution path for
customer code. The in-cluster `deus-microvm` RuntimeClass remains a fail-closed
fallback and validation layer, not the primary isolation model for arbitrary
customer repositories.

## Decision

Use E2B BYOC in a dedicated `execution-*` AWS account for production customer
code. Use fully self-hosted E2B only when the customer or compliance profile
cannot accept an E2B-managed control-plane relationship.

Do not use public managed E2B for production customer code unless a customer
explicitly approves that data path.

## Vendor Facts To Track

The current E2B BYOC documentation says BYOC deploys sandboxes into the
customer cloud VPC and is available for AWS and GCP. It also says sandbox
templates, snapshots, and runtime logs stay in the customer BYOC VPC, while
anonymized system metrics are sent to E2B Cloud for observability and cluster
management.

The same docs describe BYOC components as orchestrators, edge controllers,
monitoring, and storage. They also say onboarding requires a dedicated AWS
account and region, a management IAM role, Terraform configuration, and machine
images. The FAQ says the sandbox load balancer can be internal and private
connectivity can keep sandbox traffic inside the customer network.

Sources:

- [E2B BYOC documentation](https://e2b.dev/docs/byoc)
- [E2B open-source infra repository](https://github.com/e2b-dev/infra)

## Target AWS Boundary

- Run BYOC in the existing dedicated execution account model:
  `execution-dev`, `execution-staging`, and `execution-prod`.
- Use a dedicated BYOC VPC or a clearly isolated execution spoke VPC. Do not
  colocate BYOC workers with the SaaS control plane.
- Require private load balancers or private connectivity for sandbox traffic.
- Route sandbox internet egress through the centralized egress VPC and AWS
  Network Firewall.
- Store templates, snapshots, runtime logs, and image registries in the
  execution account with customer-managed KMS keys.
- Forward runtime logs, lifecycle events, VPC Flow Logs, and Network Firewall
  logs to the immutable log archive.
- Deny direct sandbox access to instance metadata unless a reviewed brokered
  identity flow exists.

## Broker Contract

The Mind platform talks to a broker service, not directly to customer-code
workers. The broker owns sandbox lifecycle calls and must record:

- tenant ID;
- job ID;
- source repository and immutable revision;
- sandbox provider and template version;
- egress profile and temporary grants;
- credential grants issued to the job;
- artifact locations and retention class;
- sandbox start, stop, timeout, and failure events.

The broker must issue only scoped, time-bound credentials. Customer code must
not receive platform deploy credentials, cloud admin roles, GitHub deploy keys,
or long-lived customer integration secrets.

Persist approved artifacts through the customer-data artifact-store contract in
[customer-data.md](customer-data.md). Customer code must not choose final object
keys or bypass the broker's tenant prefix and manifest rules.

## BYOC Control Plane Acceptance

E2B BYOC still involves E2B Cloud for management and observability. Accept this
only with:

- a reviewed vendor access role with least privilege, external ID, session
  tagging, and CloudTrail coverage;
- a written list of metrics that can leave the execution account;
- proof that source files, sandbox traffic, build logs, runtime logs, templates,
  and snapshots stay in the BYOC data path;
- alerting on vendor role use and unexpected network paths to or from sandbox
  components.

If those controls are not acceptable for a tenant, use fully self-hosted E2B in
that tenant's dedicated execution account. The open-source E2B infra repository
uses Terraform and currently marks AWS support as beta, so treat self-hosting as
owned production infrastructure with pinned releases, private state, image
hardening, patch SLAs, and independent red-team coverage.

## Stack Specification

Execution stack examples now include:

```yaml
secure-saas-infra:executionSandbox:
  provider: e2b-byoc
  dedicatedAccountRequired: true
  privateLoadBalancerRequired: true
  centralizedEgressRequired: true
  maxSandboxDurationMinutes: 1440
  allowExternalControlPlane: true
  allowAnonymizedMetricsExport: true
  requirePerJobAuditMetadata: true
  requireBrokeredCredentials: true
secure-saas-infra:e2bByocAccess:
  createVendorRole: false
  vendorPrincipalArns: []
  managedPolicyArns: []
  maxSessionDurationSeconds: 3600
```

The Pulumi config validator rejects execution stacks that disable the sandbox
provider, omit the dedicated account/private connectivity/centralized egress
requirements for any isolated provider (`e2b-byoc`, `e2b-self-hosted`, or
`microvm-runtimeclass`), exceed a 24-hour sandbox lifetime, omit per-job audit
metadata, or permit direct unbrokered credentials.

When onboarding requires an E2B vendor access role, set
`e2bByocAccess.createVendorRole: true` only after review. The scaffold requires
vendor principals to be IAM role ARNs, requires a 16-character or longer
external ID, caps the role session at one hour, and rejects AWS administrator
managed policies. Attach only reviewed least-privilege account-local policies.

## Kubernetes Fallback Controls

The `execution` namespace is still locked down so accidental in-cluster customer
code does not become a regular-container workload:

- pods must use the `deus-microvm` RuntimeClass;
- service account token automount must be disabled;
- CPU, memory, and ephemeral-storage limits are required;
- tenant ID, job ID, source revision, egress profile, and sandbox provider
  metadata are required;
- namespace ResourceQuota and LimitRange cap blast radius.

## Production Gate

Before running production customer code on E2B BYOC:

- BYOC is deployed in a dedicated execution AWS account and region.
- The sandbox load balancer is private or reachable only through private
  connectivity.
- Sandbox egress is observed through VPC Flow Logs and AWS Network Firewall
  FLOW plus ALERT logs.
- The broker records the full per-job audit contract.
- Vendor access roles, OAuth provider details, and control-plane network paths
  are reviewed and monitored.
- Egress-deny, metadata-deny, credential-deny, and artifact-deletion tests pass
  in the deployed environment.
