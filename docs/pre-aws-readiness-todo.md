# Pre-AWS Readiness TODO

Status: active operator checklist  
Last live-state verification: 2026-07-28
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
- [x] The SLSA reusable-workflow identity regression was fixed in signed,
      GitHub-verified commit `739c2ef`; the two generator jobs use the required
      exact `v2.1.0` tag while ordinary Actions remain SHA-pinned.
- [x] Signed commit `4647d31` is GitHub-verified and its complete `infra-ci`
      workflow passed.
- [x] Linux source CI has passed on the admitted workflow, including its
      `amd64` and `arm64` lanes.
- [ ] The current exact commit has green CI. The `infra-ci` run for `c5c08eb`
      ended in `startup_failure` with zero jobs because the free Actions budget
      was exhausted. Because the public trust root will change the exact tree,
      preserve the allowance and run final CI on that trust-root commit after
      the allowance resets on 2026-08-01.
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
- [x] The dedicated AWS account exists, ignored onboarding/backend configuration
      is complete, the deterministic access bundle verifies, and no long-lived
      AWS credential is present locally.
- [x] The operator reports the root account has multiple separately held MFA
      devices, no root access key, current recovery details, and configured
      billing/security/operations alternate contacts. Do not repeat this setup;
      retain the independent evidence below.
- [x] The doctor has a redacted, fail-closed live AWS account-audit mode bound
      to the exact preview role. It validates AWS-reported root MFA/access-key
      posture, contact completeness, and post-cutoff root activity across all
      enabled Regions without changing AWS configuration.
- [ ] Root-account safety is independently evidenced: multiple separately held
      MFA devices, zero root access keys, current recovery email/phone, and
      billing/security/operations alternate contacts.

The offline doctor currently has two expected blockers: missing Ed25519 trust
and unresolved exact-tree reviews. Darwin also cannot provide the final native
Linux host evidence. The already-created AWS account must remain empty except
for root safety controls until the pre-mutation GO gate below passes.

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
- [ ] Complete the independent Pulumi/recovery-media handoff:
  - [ ] **Deferred by the operator on 2026-07-25 until the USB hardware is
        available.** Stage 2 planning may proceed, but this stage remains open
        and no pre-account GO decision may pass until both USB copies are
        verified.
  - [x] Create temporary FileVault-protected staging at
        `~/Downloads/secure-saas-recovery-staging`; restrict every directory to
        `0700` and every file to `0600`.
  - [x] Move the Google backup-code file into private staging without reading
        it.
  - [x] Export the empty Pulumi management stack into staging using the
        [Pulumi recovery procedure](pulumi-cloud-recovery.md) and verify its
        SHA-256 sidecar.
  - [x] Generate a complete relative-path SHA-256 staging manifest so future
        copies can be verified without opening credential files.
  - [ ] Acquire two encrypted USB-C/USB-A recovery drives.
  - [ ] Copy the complete staging directory to recovery USB 1 and verify the
        staging manifest plus the Pulumi state sidecar on that drive.
  - [ ] Copy the complete staging directory to recovery USB 2 and repeat both
        verifications.
  - [ ] Store the two verified drives in separate physical locations.
  - [ ] With explicit approval, remove the temporary local staging copy only
        after both independent copies pass.

Stop if any recovery path depends only on this development computer.

## 2. Prepare the independent signer for later

This stage is free and may be deferred, but stages 4 onward cannot complete
without it.

- [ ] **Deferred by the operator on 2026-07-25 because no separate physical
      signing computer is currently available.** Do not substitute this
      development Mac or a VM it controls. Resume only with a separate
      credential-free computer or a separately reviewed non-exportable signing
      service.
- [ ] Obtain a separate credential-free computer for signing. Do not use this
      development Mac, the future AWS execution host, or a VM controlled by
      either host.
- [ ] Prepare two encrypted signing-only removable-media copies for the
      private-key backup. These are a different pair from the recovery drives
      in stage 1 and must never connect to this development Mac.
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

- [ ] **Deferred by the operator on 2026-07-25.** Keep the organization on
      GitHub Free and do not purchase Team, Enterprise Cloud, Code Security, or
      Secret Protection now. Non-authorizing review and engineering may
      continue, but stages 4 through 8 remain formal release/AWS blockers until
      this paid-control decision is deliberately resumed or the governance
      requirement is replaced by a separately reviewed equivalent.
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

## 8. Pre-mutation GO decision

The AWS account was created before this formal gate. Do not perform governed
IAM, Organizations, Pulumi, or workload mutation until stages 1 through 7 are
complete and a final review confirms:

- [ ] GitHub governance and immutable release evidence are complete.
- [ ] The independent private key remains recoverable and has never entered a
      development or AWS execution environment.
- [ ] The exact public trust root is committed in the reviewed release.
- [ ] Both native host kits and their provenance pass.
- [ ] Pulumi login and independent state-backup recovery paths pass.
- [ ] There are no unresolved exact-tree findings.
- [ ] No AWS access key, Pulumi token, signing key, recovery material, or
      customer credential exists in the repository.

The account and ignored onboarding decisions already exist. Passing this gate
is the explicit boundary where they may first be used by governed AWS tooling.

## 9. After the GO: establish governed AWS access

This is the next roadmap, not permission to execute it early.

- [x] Create the dedicated AWS management account and retain its account ID plus
      globally unique member-account emails only in ignored local configuration.
- [x] The operator reports root is protected by multiple separately held MFA
      devices, has no root access key, and has current recovery email/phone.
      Independent machine/witness verification remains tracked below.
- [x] The operator reports billing, security, and operations alternate contacts
      are configured. The live doctor must still verify all three records.
- [ ] Perform the separately reviewed, two-person, console-only initial SAML
      federation ceremony from the management-seed runbook.
- [x] Create only ignored `onboarding.local.json` and
      `Pulumi.management.yaml` from their examples; no real account identifier,
      email, or confidential metadata is committed.
- [x] Render and verify the deterministic access bundle without a governed AWS
      mutation.
- [ ] After the reviewed preview policy is installed and the provisioner is
      retired, run `npm run validate:aws-account` with the independently
      recorded root-ceremony UTC cutoff. Require every machine-verifiable check
      to pass and separately retain the witnessed multiple-MFA/root-email
      evidence.
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
