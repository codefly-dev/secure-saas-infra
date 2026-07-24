# Cloud IaC / in-cluster platform boundary

## Decision

This repository qualifies and releases cloud infrastructure only. Its governed
AWS bootstrap path must not install or test Helm charts, reconcile Argo CD
Applications, or create workload resources inside Kubernetes.

This does **not** mean that only Organizations/IAM are infrastructure. The
current seed-only executable is wave zero: it establishes the accounts and
guardrails needed to deploy the later networking, cluster, data, edge, and
security waves with bounded member-account roles. Those later waves stay on
the IaC roadmap, but they must earn their own positive source/test/release
inventories before they can be admitted to an AWS preview.

Cloud IaC owns:

- AWS Organizations, accounts, organization guardrails, IAM, KMS, audit, and
  security-service delegation;
- VPCs, routing, DNS, certificates, load-balancer prerequisites, EKS control
  planes/node infrastructure, RDS, backups, and cloud observability sinks;
- EKS access entries, Pod Identity/IAM roles, security groups, and the exact
  credential-free outputs needed by the platform layer; and
- a versioned handoff describing cluster endpoint/CA, authorized bootstrap
  identity, cloud resource IDs, and policy/evidence digests.

The platform/GitOps layer owns everything reconciled through the Kubernetes
API after that handoff, including Argo CD configuration, Helm releases,
Kyverno, Istio, namespaces, NetworkPolicy, rollout resources, operators, and
application/database migration workloads.

The only bootstrap exception is the future, separately reviewed mechanism that
installs or activates Argo CD itself. That mechanism must be minimal and end by
handing ownership to GitOps; it is not part of the organization seed preview.

## Cloud infrastructure waves

| Wave                          | IaC responsibility                                                                                                        | Current state                                                                                                                 |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| 0 — management seed           | Rootless access roles, organization, OUs, accounts, deny-only SCPs, native S3 policy, trusted-service access, RAM sharing | Governed locally in organization-only and quota-gated full waves; next boundary is real bootstrap federation/IAM provisioning |
| 1 — account foundation        | Scoped provider roles, audit/log archive, KMS, security services, budgets, backup foundations                             | Planned; blocked on real seed outputs                                                                                         |
| 2 — network                   | Inspection/egress and spoke VPCs, Transit Gateway, endpoints, DNS and routing                                             | Planned cloud IaC                                                                                                             |
| 3 — compute and data          | EKS control planes/node infrastructure/access entries/Pod Identity and RDS/Aurora/Proxy/backups                           | Planned cloud IaC                                                                                                             |
| 4 — edge                      | Route 53, ACM, WAF, CloudFront and AWS load-balancer prerequisites                                                        | Planned cloud IaC                                                                                                             |
| Handoff — platform activation | Minimal cluster bootstrap plus signed, credential-free cloud outputs                                                      | Contract and owner must be separately qualified                                                                               |

An AWS load balancer and its AWS-side prerequisites are cloud IaC. An Istio
route, Argo CD Application, Helm release, or Kubernetes Gateway/Ingress object
is platform desired state. The handoff between them is an explicit versioned
contract, not shared ownership of the same resource.

## Governed validation

`npm run verify:all`, `npm run gates:local`, and bootstrap qualification run
only from the sealed fixed execution root on a dedicated native Linux qualifier
and bind exactly five cloud-IaC gates. Ordinary source and promotion CI run
`npm run validate:source` and may emit explicitly unqualified source-release
evidence; they cannot emit or consume production local-gate evidence:

1. clean dependency installation with lifecycle scripts disabled;
2. formatting, type/build, Pulumi policy, public-contract, and management-seed
   policy validation;
3. the explicitly scoped cloud-IaC unit/hostile inventory selected by
   `scripts/run-iac-unit-tests.mjs`;
4. dependency security audit; and
5. SPDX SBOM generation.

They do not invoke Docker, Helm, kubectl, K3s, or GitOps rendering. The root
package exposes no platform validation command; legacy platform files are
outside the positive seed source, test, contract, dependency, and release
inventories.

## Extraction debt

The existing `gitops/`, disposable-cluster scripts, and Kubernetes/Helm Argo CD
material predate this boundary. They remain temporarily so the move can retain
history and tests, but they are excluded from the AWS release archive and
qualification inventory. Do not add new in-cluster behavior here.

Before any post-seed EKS deployment is enabled:

- [ ] create the platform/GitOps repository and ownership rules;
- [ ] move `gitops/`, its static validator, and disposable-cluster tests there;
- [ ] move Kubernetes/Helm Argo CD reconciliation out of the Pulumi cloud
      program;
- [ ] define and schema-check the credential-free cloud-to-platform handoff;
- [ ] implement the minimal Argo CD activation mechanism in its declared
      owner;
- [ ] make platform CI reconcile a disposable Git remote through Argo CD and
      run its own K3s/Kubernetes hostile tests; and
- [ ] delete the temporary `platform:*` commands and legacy files from this
      repository after the receiving repository proves parity.

Application schema/data migrations remain application code and are never an
IaC responsibility.
