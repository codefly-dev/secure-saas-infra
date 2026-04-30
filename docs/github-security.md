# GitHub Security Mode

Use GitHub like a private code-hosting platform for customer-code infrastructure:
repository settings are part of the production control plane.

## Required Repository Rules

Apply the `github-governance` Pulumi stack before production deploy. It manages:

- require pull requests into `main`;
- require CODEOWNERS review for all infrastructure, GitOps, policy, and security
  documentation paths;
- require linear history or merge queue;
- block force pushes and branch deletion on protected branches;
- require status checks for `npm test` and `pulumi preview --policy-pack
./policy`;
- require signed commits or verified release provenance for production deploy
  workflows;
- require conversation resolution before merge;
- restrict who can bypass rulesets.

The stack also enables repository vulnerability alerts, Dependabot security
updates, selected Actions allowlists, SHA-pinned Actions requirements, protected
deployment environments, and push rules that block secret-like files and large
files. Keep `manageOrganizationSettings: false` until a GitHub organization
owner approves the org-wide defaults.

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
- Pin third-party actions by SHA for production release workflows.
- Disable or tightly restrict self-hosted runners for this repository.
- Do not store AWS access keys, Pulumi access tokens, signing keys, or customer
  credentials as repository secrets unless there is a documented exception and
  rotation owner.

## Current Repo Artifacts

- `.github/CODEOWNERS` marks security/platform ownership for infra paths.
- `.github/dependabot.yml` enables weekly npm and GitHub Actions update PRs.
- `.github/pull_request_template.md` adds a security checklist for reviewers.
- `.github/workflows/infra-ci.yml` provides the pinned `npm test` required check.
- `Pulumi.github-governance.yaml.example` applies repository rulesets,
  protected environments, Actions SHA pinning, selected Actions allowlists,
  Dependabot security updates, and vulnerability alerts.
- `Pulumi.github-oidc.yaml.example` scopes AWS access to explicit repositories,
  refs, and protected environments.

## Evidence To Capture

For SOC 2 and customer reviews, export or screenshot:

- active rulesets for `main`;
- required status checks;
- CODEOWNERS review enforcement;
- protected environment reviewers;
- secret scanning and push-protection status;
- Dependabot enablement;
- OIDC deploy role trust policy and the matching GitHub environment settings.
