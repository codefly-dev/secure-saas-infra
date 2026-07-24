# Incident Response Runbooks

These runbooks cover the customer-code execution threat model. Use the security
tooling account as the coordination point and preserve evidence before cleanup.

## Common First Actions

1. Open an incident with severity, owner, affected tenant IDs, and start time.
2. Freeze related deploys and disable nonessential execution jobs.
3. Preserve CloudTrail, EKS audit logs, VPC Flow Logs, Network Firewall logs,
   sandbox lifecycle logs, admission-controller events, and broker audit events.
4. Snapshot relevant configuration: E2B BYOC settings, egress grants, image
   digests, GitHub workflow run IDs, and Pulumi stack versions.
5. Decide whether customer notification, legal review, or regulator notice is
   required.

## Customer Code Exposure

Trigger examples: wrong tenant receives source files, logs contain repository
contents, artifact path crosses tenant boundary.

Containment:

- stop affected jobs and revoke broker-issued credentials;
- block affected artifact prefixes and storage grants;
- disable export/download endpoints for affected tenants if needed;
- preserve source revision, artifact object versions, access logs, and broker
  events.

Eradication and recovery:

- rotate any customer or platform credential that may have reached the wrong
  trust boundary;
- delete or quarantine incorrectly placed artifacts under legal hold guidance;
- validate tenant authorization tests before re-enabling execution;
- provide tenant-specific impact data: files, revisions, timestamps, identities,
  artifact paths, and remediation.

## Sandbox Escape

Trigger examples: sandbox process reaches host namespace, metadata endpoint,
or other tenant network; E2B BYOC node shows unexpected process or kernel event.

Containment:

- quarantine the affected execution account, cluster, node pool, or BYOC worker;
- stop new sandbox creation for the affected template/runtime;
- revoke job credentials and egress grants;
- preserve node disk, sandbox image/template, runtime logs, and network flow
  records.

Eradication and recovery:

- rebuild worker nodes from known-good images;
- patch or roll back sandbox runtime and templates;
- rotate any identity reachable from the compromised runtime;
- run metadata-deny, egress-deny, and cross-tenant isolation tests before
  reopening the execution pool.

## Suspicious Egress

Trigger examples: Network Firewall alert, deny spike, non-allowlisted domain,
large upload, or destination associated with malware.

Containment:

- disable the tenant/job egress profile;
- stop matching jobs and quarantine artifacts created after the first alert;
- preserve packet metadata, domain/SNI, job IDs, source revision, and sandbox
  provider metadata.

Eradication and recovery:

- inspect customer code and dependencies involved in the job;
- update egress allowlists or broker rules only after review;
- add detection for the destination and rerun deny-path tests.

## Leaked Deploy Credential

Trigger examples: static AWS key found, GitHub secret exposed, Pulumi token
leaked, OIDC role used from unexpected subject.

Containment:

- revoke the credential or disable the role session path immediately;
- pause deployments for affected accounts;
- inspect CloudTrail and GitHub audit logs for use since last known-good time;
- rotate adjacent credentials and signing material.

Eradication and recovery:

- replace static credentials with OIDC, workload identity, or brokered dynamic
  credentials;
- tighten trust policy subjects and protected environment reviewers;
- require a fresh credential-free bootstrap candidate and a governed
  `npm run bootstrap -- --preview` saved plan before redeploy.

## Tenant Deletion Or Export Failure

Trigger examples: deletion misses derived indexes, export omits artifacts, or
retention class is wrong.

Containment:

- pause deletion/export workflows for the affected tenant class;
- preserve workflow logs and object-version inventory;
- block new writes to affected prefixes if integrity is uncertain.

Eradication and recovery:

- reconcile source, artifacts, logs, indexes, snapshots, and backups;
- rerun deletion/export with a tracked manifest;
- produce evidence showing every retained object and its legal/contractual
  retention reason.
