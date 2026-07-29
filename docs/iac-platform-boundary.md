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

The only bootstrap exception is the separately reviewed mechanism in
[`codefly-dev/secure-saas-platform`](https://github.com/codefly-dev/secure-saas-platform)
that activates Argo CD from a signed handoff and then hands ownership to Git.
It is not part of the organization seed preview.

## Cloud infrastructure waves

| Wave                          | IaC responsibility                                                                                                        | Current state                                                                                                                 |
| ----------------------------- | ------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| 0 — management seed           | Rootless access roles, organization, OUs, accounts, deny-only SCPs, native S3 policy, trusted-service access, RAM sharing | Governed locally in organization-only and quota-gated full waves; next boundary is real bootstrap federation/IAM provisioning |
| 1 — account foundation        | Scoped provider roles, audit/log archive, KMS, security services, budgets, backup foundations                             | Planned; blocked on real seed outputs                                                                                         |
| 2 — network                   | Inspection/egress and spoke VPCs, Transit Gateway, endpoints, DNS and routing                                             | Planned cloud IaC                                                                                                             |
| 3 — compute and data          | EKS control planes/node infrastructure/access entries/Pod Identity and RDS/Aurora/Proxy/backups                           | Planned cloud IaC                                                                                                             |
| 4 — edge                      | Route 53, ACM, WAF, CloudFront and AWS load-balancer prerequisites                                                        | Planned cloud IaC                                                                                                             |
| Handoff — platform activation | Minimal cluster bootstrap plus signed, credential-free cloud outputs                                                      | Versioned contract emitted here and consumed by the protected platform owner                                                  |

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

They do not invoke Docker, Helm, kubectl, K3s, or GitOps rendering. The
separate `npm run validate:handoff` gate compiles the quarantined handoff
schema, verifies its signed fixture, and exercises publication from a Pulumi
stack-output document without admitting any platform input to the management
seed. The root package contains no Kubernetes or Helm dependency.

## Platform handoff

This repository owns the
`platform-iac-handoff-v1.schema.json` contract and its credential-free cloud
inputs. The contract binds the cluster role, endpoint and CA reference,
bootstrap identity reference, cloud resource IDs, and policy/evidence digests.
`npm run handoff:publish -- --stack-outputs <file> --private-key <file>
--output <file>` materializes that document from the
`platformIacHandoff` Pulumi stack output, replaces the inline cluster CA with
its content digest, and signs the canonical spec with an external ECDSA P-256
key. Its signed example and qualification test remain quarantined from the
management-seed release inventory.

The production GitOps tree, Argo CD activation, disposable-cluster validation,
promotion evidence, CODEOWNERS, and release controls live in
[`codefly-dev/secure-saas-platform`](https://github.com/codefly-dev/secure-saas-platform).
That repository retained the relevant history and proved exact-revision
reconciliation on AMD64 and ARM64 before the legacy platform paths were removed
here.

Application schema/data migrations remain application code and are never an
IaC responsibility.
