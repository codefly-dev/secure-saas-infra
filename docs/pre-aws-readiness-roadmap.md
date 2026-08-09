# Pre-AWS Readiness Roadmap

Status: dependency-ordered issue map
Scope: current state to the first governed AWS mutation (management seed only)

This is the sequenced roadmap from the current local-platform state to the first
governed AWS mutation. It replaces "read the TODO and infer the order" with a
tracked, dependency-ordered map of issues.

The stage numbering and gate wording come from the operator checklist in
[pre-aws-readiness-todo.md](pre-aws-readiness-todo.md); this file records which
tracked issue owns each stage and what blocks what. When the two disagree about
detail, the checklist is authoritative for the stage's exact gate and this file
is authoritative for the ordering.

**The project is at a healthy local-platform stage, not at the AWS deployment
stage.** The AWS account and the Pulumi backend exist. The governed release,
signer, recovery, review, native-Linux, and pre-mutation gates are the boundary,
and none of them has passed. Never mark a stage complete because the code exists;
mark it complete only when the required live control and its evidence pass.

## Stage-to-issue map

| Issue | Stage | Work |
| --- | --- | --- |
| [#35](https://github.com/codefly-dev/secure-saas-infra/issues/35) | prerequisite | Reconcile the dirty working checkout; carry the hardware-signer plan forward onto `origin/main`. |
| [#36](https://github.com/codefly-dev/secure-saas-infra/issues/36) | prerequisite | `infra-ci` produced zero jobs. Root cause: all three workflows used `pulumi/actions`, which the Actions allow-list forbids — not a billing problem. |
| [#38](https://github.com/codefly-dev/secure-saas-infra/issues/38) | 1 | Establish two independent encrypted recovery-media copies. |
| [#39](https://github.com/codefly-dev/secure-saas-infra/issues/39) | 2 | Configure and qualify the independent hardware signer. |
| [#37](https://github.com/codefly-dev/secure-saas-infra/issues/37) | 3 | Decide the public-repository governance question and establish the protected review path. |
| [#40](https://github.com/codefly-dev/secure-saas-infra/issues/40) | 4 | Configure the public trust root and freeze `REVIEWED_SOURCE_REVISION`. |
| [#41](https://github.com/codefly-dev/secure-saas-infra/issues/41) | 5 | Perform the exact-tree reviews and record `RELEASE_REVISION`. |
| [#45](https://github.com/codefly-dev/secure-saas-infra/issues/45) | 6 | Build and publish the protected immutable release on `RELEASE_REVISION`. |
| [#42](https://github.com/codefly-dev/secure-saas-infra/issues/42) | 7 | Verify the native Linux `amd64` and `arm64` host kits. |
| [#43](https://github.com/codefly-dev/secure-saas-infra/issues/43) | 8 | Record the pre-mutation GO decision. |
| [#44](https://github.com/codefly-dev/secure-saas-infra/issues/44) | 9 | Establish governed AWS access and the first management-seed apply. |

## Ordering

```text
#35 reconcile checkout ─┐
#36 infra-ci green ─────┼─> #40 stage 4 ─> #41 stage 5 ─> #45 stage 6 ─> #42 stage 7 ─┐
#37 stage 3 governance ─┤                                                              ├─> #43 stage 8 GO ─> #44 stage 9
#39 stage 2 signer ─────┘                                                              │
#38 stage 1 recovery ──────────────────────────────────────────────────────────────────┘
```

| Issue | Depends on |
| --- | --- |
| #40 stage 4 | #35, #36, #37, #39 |
| #41 stage 5 | #40 |
| #45 stage 6 | #41, #37 |
| #42 stage 7 | #45 |
| #43 stage 8 | everything above, plus #38 |
| #44 stage 9 | #43 |

## Critical path — no hardware, no purchase, no AWS mutation required

Stage 4 (#40) cannot start until #35, #36, and #37 are all resolved.

- **#36** is resolved. The three workflows were guarded against the Actions
  allow-list; `infra-ci` no longer fails at startup with zero jobs.
- **#35** carries the hardware-signer plan onto `origin/main`. This plan exists
  only as uncommitted local work in `pre-aws-readiness-todo.md`; if the checkout
  is reset before #35 lands, stage 2 loses its written definition entirely. Do
  not perform a destructive Git operation against the dirty checkout.
- **#37** is on the critical path, not parked. The decision to defer *paying*
  for GitHub stands, but stage 4 requires a signed commit created through a
  protected review path, and `main` currently has no branch protection and no
  rulesets. Designing that path for the current public/Free configuration is
  unblocked work and requires no purchase.

## Blocked on physical hardware

Both are deliberately deferred.

| Issue | Blocker |
| --- | --- |
| #38 stage 1 | Two encrypted USB recovery drives, not yet obtained. |
| #39 stage 2 | The YubiKey 5C NFC, not yet configured. Also depends on #35, because the hardware-signer plan currently lives only as uncommitted local work. |

## Current gate evidence

The redacted offline bootstrap doctor snapshot recorded 7 pass, 1 warning, and
3 failures. Every failure maps to an issue in this roadmap:

```text
FAIL  release.signer-trust        -> #39 (no trust root; no signer key exists)
FAIL  release.worktree            -> #35 (checkout is dirty)
FAIL  release.adversarial-review  -> #41 (no exact-tree dispositions)
WARN  release.production-host     -> #42 (Darwin cannot give native Linux evidence)
```

## Out of scope for this repository

In-cluster GitOps and local k3d belong to
[`secure-saas-platform`](https://github.com/codefly-dev/secure-saas-platform).
The promotion driver belongs to [`codefly-dev/cli`](https://github.com/codefly-dev/cli).
Do not reintroduce that work here.
[iac-platform-boundary.md](iac-platform-boundary.md) forbids it, and the
extraction on `origin/main` removed it deliberately.

## Standing constraints

Until stage 8 (#43) records an explicit GO:

- no `pulumi up`, no `aws organizations create-organization`, no access
  provisioning, no EKS or network creation;
- no release tag;
- no AWS access keys, and no root credentials in CLI tooling;
- no private signing key configured on this Mac;
- no GitHub, Pulumi, or AWS purchases without a new explicit instruction;
- no Pulumi state migration from Pulumi Cloud to S3;
- no destructive Git operation against the dirty checkout.
