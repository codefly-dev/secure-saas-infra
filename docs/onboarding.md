# Onboarding

Use the onboarding helper to turn the example files into local stack files with
your GitHub org, Pulumi org, account email domain, CODEOWNERS team, and GitOps
repository URL already filled in.

Start from the example config:

```sh
cp onboarding.config.example.json onboarding.local.json
npm run onboard -- --config onboarding.local.json
npm run onboard -- --config onboarding.local.json --write
```

Run it without `--write` first to see the files it would create. Existing stack
files are not overwritten unless `--force` is provided.

The helper creates `Pulumi.*.yaml` files from the `.example` templates, updates
`.github/CODEOWNERS`, replaces the Argo CD GitOps repository URLs, and writes
`ONBOARDING.generated.md` with the customized first commands. It does not create
AWS accounts, GitHub teams, Pulumi stacks, or AWS Identity Center.

After running it:

```sh
npm run preflight
npm run preflight:strict
npm run verify:onboarding -- --config onboarding.local.json
npm test
```

The verifier checks that generated stack files exist, placeholders are gone,
account emails use the configured domain, stack references use the configured
Pulumi org/project, CODEOWNERS points at the configured team, and GitOps repo
URLs match the configured GitHub org/repo.

Before the first deploy, still decide these manually:

- AWS management account root email, MFA, and support/contact settings.
- IAM Identity Center region and external IdP/SCIM source.
- GitHub protected-environment reviewer team IDs if you want numeric reviewers.
- Account-local Pulumi deployer policy ARNs in `Pulumi.github-oidc.yaml`.
- EKS admin role ARNs in platform and execution stack files.
- E2B BYOC vendor principal ARNs and external ID after E2B onboarding.
