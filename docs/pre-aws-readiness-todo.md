# Pre-AWS Readiness TODO

Status: active operator checklist  
Last live-state verification: 2026-07-25  
Scope: AWS Organizations management seed only

This is the short, dependency-ordered checklist for returning to the first AWS
bootstrap. It does not authorize an AWS call or mutation. Do not skip forward:
each numbered stage is a gate for the next one.

The exact commands and security requirements remain in the
[management-seed runbook](management-seed-runbook.md). The larger
[validation-first backlog](iac-validation-first-execution-todo.md) records
implementation detail and later work; this file records the immediate operator
sequence.

## Current checkpoint

At the start of this checklist edit:

- [x] The two earlier CI defects were fixed in signed commits and pushed.
- [x] The latest `infra-ci` run for `5dbf193` passed.
- [x] Linux source CI has passed on the admitted workflow, including its
      `amd64` and `arm64` lanes.
- [x] Pulumi Cloud Individual is selected at
      `toussaint-antoine-gmail-com/secure-saas-infra/management`; the stack is
      empty.
- [x] Pulumi account recovery is documented, the Pulumi passkey is registered,
      and the owner reports Google 2-Step Verification enabled.
- [x] GitHub immutable releases, vulnerability alerts, Dependabot security
      fixes, selected Actions, SHA pinning, and read-only default workflow
      permissions are enabled.
- [x] The GitHub organization member previously lacking 2FA was removed.
- [x] GitHub organization-wide 2FA enforcement is enabled. The live API
      reported `true` on 2026-07-25, with no remaining member listed without
      2FA.
- [x] `antoine-p1` was deliberately removed after enforcement; the account is
      neither an organization member nor outside collaborator and has no
      repository permission.
- [x] The `platform-security` team referenced by `.github/CODEOWNERS` exists.
      `AntoineToussaint` is its maintainer, `dpsommer` and `gxmas` are its
      independent reviewer members, and the team has write access to this
      repository.
- [ ] Paid private-repository GitHub governance is enabled. The organization
      remains on GitHub Free.
- [ ] The independent Ed25519 public trust root is configured.
- [ ] Architecture, security, and validation have recorded fresh GO
      dispositions for one exact source tree.
- [ ] A release tag or GitHub release exists.
- [ ] Native Linux host-kit qualification is complete.
- [ ] An AWS account or AWS configuration is in scope.

The offline doctor currently has three expected blockers: missing real AWS
onboarding configuration, missing Ed25519 trust, and unresolved exact-tree
reviews. Darwin also cannot provide the final native Linux host evidence.

## 1. Finish free account and recovery controls

- [x] Recheck every remaining `codefly-dev` organization member has 2FA, then
      enable organization-wide 2FA enforcement and verify it from the live
      organization settings.
- [x] Create the `codefly-dev/platform-security` team, select its independent
      reviewers, grant the team explicit access to this repository, and verify
      GitHub recognizes it as the `.github/CODEOWNERS` owner.
- [x] Confirm the Google identity has at least two independent second-factor
      methods, current recovery email/phone, and stored backup codes.
- [x] Confirm the Pulumi passkey and the password manager's recovery material
      are recoverable without the primary development computer.
- [x] Perform a private-browser Pulumi login drill. Record the date and result
      outside this repository; never store recovery secrets here.
- [ ] Export the empty Pulumi management stack to encrypted storage using the
      [Pulumi recovery procedure](pulumi-cloud-recovery.md), verify its
      checksum, and retain two copies in separate failure domains.

Stop if any recovery path depends only on this development computer.

## 2. Prepare the independent signer for later

This stage is free and may be deferred, but stages 4 onward cannot complete
without it.

- [ ] Obtain a separate credential-free computer for signing. Do not use this
      development Mac, the future AWS execution host, or a VM controlled by
      either host.
- [ ] Prepare two encrypted removable-media copies for the private-key backup.
- [ ] Generate one dedicated Ed25519 qualification keypair on the signing
      computer. Do not reuse a Git, SSH, login, or application key.
- [ ] Keep `qualification-private.pem` encrypted on the offline media and keep
      its passphrase separately. Never copy the private key into GitHub,
      Pulumi, AWS, cloud-sync storage, or this repository.
- [ ] Transfer only `qualification-public.pem` to the development environment.
- [ ] Run a signing and verification self-test on the separate computer and
      confirm the detached Ed25519 signature is exactly 64 bytes.

Generating the private key here and deleting it later does not satisfy this
gate: SSD deletion cannot exclude snapshots, swap, backups, or prior capture.

## 3. Cross the deliberate paid GitHub gate

Do this only when ready to move from the free preparation phase toward a real
release.

- [ ] Upgrade the GitHub organization to at least Team before relying on a
      private-repository branch or tag protection claim.
- [ ] Protect `main`: require pull requests, CODEOWNERS review, `infra-ci`,
      conversation resolution, linear history, and no force-push or deletion.
- [ ] Protect `v*.*.*` tags against unauthorized creation, deletion, or
      retargeting.
- [ ] Limit bypass authority and retain the live ruleset export or screenshots.
- [ ] Configure the `production` environment and its permitted deployment
      branches/tags.
- [ ] Resolve the production-reviewer plan boundary. GitHub-hosted required
      environment reviewers for this private repository require Enterprise
      Cloud; do not claim that control while remaining on Team or Free.
- [ ] Deliberately purchase and enable GitHub Code Security and Secret
      Protection if those GitHub-native private-repository controls remain a
      requirement. Until then, retain the repository's credential-free secret
      scan and dependency checks without representing them as GitHub code or
      secret scanning.
- [ ] Reverify immutable releases, Dependabot, Actions restrictions, workflow
      token permissions, branch/tag rules, CODEOWNERS enforcement, and
      production controls from live GitHub settings.

Do not create a production tag while this stage is incomplete.

## 4. Commit the public trust root and freeze the source tree

- [ ] Derive the exact DER SPKI public key, SHA-256 `keyId`, and base64url
      `publicKeySpki` from `qualification-public.pem`.
- [ ] Set `configured: true` in
      `security/bootstrap-qualification-trust.json`; commit no private
      material.
- [ ] Run the offline doctor and require `release.signer-trust` to pass.
      Missing AWS onboarding remains expected before the AWS account exists.
- [ ] Run complete source validation and secret scanning.
- [ ] Create a signed source commit through the protected pull-request path and
      require green CI.
- [ ] Record that commit as `REVIEWED_SOURCE_REVISION`.
- [ ] Freeze the tree. Any subsequent source, workflow, mode, dependency, or
      trust-root change invalidates the review and restarts this stage.

The public trust root must be part of the reviewed source parent; it cannot be
added after the exact-tree reviews.

## 5. Perform the exact-tree reviews

- [ ] Review `REVIEWED_SOURCE_REVISION` independently for architecture.
- [ ] Review the same revision independently for security.
- [ ] Review the same revision independently for validation and hostile-test
      credibility.
- [ ] Resolve every blocking finding and restart at stage 4 if resolution
      changes the tree.
- [ ] Obtain all three fresh GO dispositions within their seven-day validity
      window. Keep authenticated reviewer approval or signed attestations
      separately; names inside the JSON are routing labels, not identities.
- [ ] Create exactly one non-merge child commit that changes only
      `security/adversarial-review-disposition.json`.
- [ ] Record that child as `RELEASE_REVISION` and verify its sole parent is
      `REVIEWED_SOURCE_REVISION`.
- [ ] Require the `review-promotion` workflow and repeated source validation to
      pass on the evidence-only child.

If any file other than the disposition changes in the child, do not tag it.

## 6. Build and publish the protected immutable release

- [ ] Create the protected semantic tag `vX.Y.Z` on `RELEASE_REVISION`.
- [ ] Let `.github/workflows/release.yml` build the source artifact, run the
      exact AWS provider smoke job, and build native `amd64` and `arm64` host
      kits. Never replace these with a kit built from a local mutable checkout.
- [ ] Require both host-kit jobs and both SLSA provenance jobs to pass.
- [ ] Let the workflow publish the release only after every required job
      succeeds.
- [ ] Verify the live tag still resolves to `RELEASE_REVISION`.
- [ ] Verify the release is marked immutable and contains the source archive,
      both host kits, both provenance statements, SBOM, release manifest,
      contract validation, and explicitly unqualified source evidence.
- [ ] Save the workflow URLs, release URL, tag/revision, and artifact hashes as
      external release evidence.

The workflow intentionally builds both kits before its final publish job; the
immutable GitHub release is therefore the output of the successful
two-architecture build, not its input.

## 7. Verify the native Linux host kits

- [ ] On native Linux `amd64`, verify the release identity, tag, revision,
      archive inventory, checksums, SLSA provenance, provider smoke, systemd,
      Landlock, sudoers, credential-pipe, and denial-path tests.
- [ ] Repeat on native Linux `arm64`; emulation or a Darwin container is not
      final evidence.
- [ ] Install only an architecture-matched, fully verified kit into its
      root-owned fixed paths.
- [ ] Retain evidence from both architectures and resolve every failure by
      returning to stage 4 and issuing a new reviewed release.

Do not create the final signed bootstrap candidate yet. That candidate binds
the real management account, roles, emails, configuration, and backend, which
do not exist before AWS onboarding.

## 8. Pre-account GO decision

Create the AWS account only after stages 1 through 7 are complete and a final
review confirms:

- [ ] GitHub governance and immutable release evidence are complete.
- [ ] The independent private key remains recoverable and has never entered a
      development or AWS execution environment.
- [ ] The exact public trust root is committed in the reviewed release.
- [ ] Both native host kits and their provenance pass.
- [ ] Pulumi login and independent state-backup recovery paths pass.
- [ ] There are no unresolved exact-tree findings.
- [ ] No AWS access key, Pulumi token, signing key, recovery material, or
      customer credential exists in the repository.

At this point the remaining offline-doctor onboarding failure is expected: it
is the explicit boundary where the real AWS account ID and role decisions
become necessary.

## 9. After the GO: create and secure AWS

This is the next roadmap, not permission to execute it early.

- [ ] Create the dedicated AWS management account and immediately secure the
      root user with multiple hardware MFA devices; never create a root access
      key.
- [ ] Configure billing/security contacts and retain the account ID plus
      globally unique member-account emails.
- [ ] Perform the separately reviewed, two-person, console-only initial SAML
      federation ceremony from the management-seed runbook.
- [ ] Create only ignored `onboarding.local.json` and
      `Pulumi.management.yaml` from their examples; never commit real account
      identifiers, emails, or confidential metadata.
- [ ] Render and verify the deterministic access bundle before any governed AWS
      mutation.
- [ ] Re-run qualification from the authenticated native Linux kit, review the
      real-account payload on the independent signer, and return only its
      detached signature.
- [ ] Finalize the signed candidate, then perform the governed read-only
      `organization-only` preview.
- [ ] Apply only a separately reviewed saved plan with explicit operator
      confirmation. The first seed apply may create only the AWS Organization
      and enable the two admitted policy types.

All account-foundation, network, EKS, RDS, Tailscale runtime, and application
deployment waves remain blocked until the management seed produces verified
outputs and each later wave is separately qualified.
