# Operations

## Current executable scope

The only qualified operation is the AWS Organizations management seed. The
first apply creates only the Organization and enables the reviewed
`SERVICE_CONTROL_POLICY` and `S3_POLICY` types. The future `full` graph may be
previewed against an exact organization-only baseline, but cannot be applied.

Run the complete credential-free local gate with:

```sh
npm run validate:local
```

That command validates the management-seed source closure, contracts, policy
pack, tests, dependency audit inputs, release evidence, and SBOM. It is not a
Codefly, GitOps, Helm, Kubernetes, network, EKS, or full-repository validation
command.

All AWS access must use the authenticated native runtime and the procedures in
[management-seed-runbook.md](management-seed-runbook.md). Raw credentialed
Node, npm, Pulumi, or AWS deployment commands are not supported operator paths.

## Deferred operations

Networking, VPC endpoint changes, member-account access, EKS access entries,
Tailscale, Argo CD, cluster admission, execution sandboxes, artifact admission,
RDS, backup, ingress, application deployment, and Codefly runtime operations
remain design/backlog material. No command for those areas in older documents
is executable or release-qualified from this repository today.

When a later cloud wave is admitted, it must have a separate least-privilege
role, exact provider/config binding, saved-plan review, independent live
pre/post-state observation, rollback/recovery procedure, and evidence schema.
Kubernetes reconciliation and database migrations remain application/platform
work outside cloud IaC.

## Incident and destruction boundary

The current apply role cannot delete, detach, move, update, or leave
Organizations resources. There is no qualified destroy path. Treat teardown,
role revocation, retained-resource cleanup, and organization deletion as new
incident/change designs requiring separate authority and review; do not use raw
`pulumi destroy` as a workaround.
