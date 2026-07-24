# GitHub Security Mode

Use GitHub like a private code-hosting platform for customer-code infrastructure:
repository settings are part of the production control plane.

## Required Repository Rules

The active AWS management seed does not mutate GitHub. Configure these rules
directly in the `codefly-dev` organization (or admit a separately qualified
GitHub-governance stack later):

- require pull requests into `main`;
- require CODEOWNERS review for all infrastructure, GitOps, policy, and security
  documentation paths;
- require linear history or merge queue;
- block force pushes and branch deletion on protected branches;
- require `infra-ci` on source pull requests and `review-promotion` on the
  separate evidence-only child pull request;
- require signed commits or verified release provenance for production deploy
  workflows;
- require conversation resolution before merge;
- restrict who can bypass rulesets;
- protect `v*.*.*` tags against deletion/retargeting and allow release creation
  only from protected `main`;
- enable GitHub immutable releases before publishing any management-seed
  release, so the release tag and assets are locked at publication; and
- require independent reviewers on the `production` release environment.

Also enable vulnerability alerts, Dependabot security updates, selected Actions
allowlists, SHA-pinned ordinary Actions requirements, protected deployment
environments, and push rules that block secret-like files and large files. The
SLSA generic generator is the one reviewed exception: its reusable workflow
must use an exact `vX.Y.Z` tag so `slsa-verifier` can authenticate the builder
identity. Keep that exact tag allowlisted and review every version change.

## Required Security Features

Enable these at the organization or repository level:

- secret scanning and push protection;
- Dependabot security updates and version updates;
- code scanning for TypeScript, IaC, and workflow files;
- private vulnerability reporting if external contributors can report issues;
- organization-level audit log streaming into the security account or SIEM.

## Actions Hardening

- Set default `GITHUB_TOKEN` permissions to read-only.
- Grant `id-token: write` only to jobs that assume AWS roles through OIDC.
- Bind deploy jobs to protected GitHub environments with required reviewers.
- Use separate AWS roles for plan and deploy.
- Pin ordinary third-party actions by SHA for production release workflows.
  Permit only the exact-tag SLSA reusable-workflow exception described above.
- Disable or tightly restrict self-hosted runners for this repository.
- Do not store AWS access keys, Pulumi access tokens, signing keys, or customer
  credentials as repository secrets unless there is a documented exception and
  rotation owner.

## Current Repo Artifacts

- `.github/CODEOWNERS` names `@codefly-dev/platform-security`; create that team,
  grant it repository access, and verify GitHub recognizes it before relying on
  CODEOWNERS enforcement.
- `.github/dependabot.yml` enables weekly npm and GitHub Actions update PRs.
- `.github/pull_request_template.md` adds a security checklist for reviewers.
- `.github/workflows/infra-ci.yml` provides the pinned source-validation check.
- `.github/workflows/review-promotion.yml` proves the disposition-only commit is
  a direct child of the protected base before rerunning complete source
  validation and emitting explicitly unqualified source-release evidence. It
  cannot produce sealed-host production qualification.
- `Pulumi.github-governance.yaml.example` is legacy/planned platform material,
  not part of the qualified AWS management-seed release.
- `Pulumi.github-oidc.yaml.example` scopes AWS access to explicit repositories,
  refs, and protected environments.

## Evidence To Capture

For SOC 2 and customer reviews, export or screenshot:

- active rulesets for `main`;
- required status checks;
- CODEOWNERS review enforcement;
- protected environment reviewers;
- immutable-releases enabled state and the published release's immutable
  marker;
- secret scanning and push-protection status;
- Dependabot enablement;
- OIDC deploy role trust policy and the matching GitHub environment settings.
