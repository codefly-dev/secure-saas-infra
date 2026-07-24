# Identity Baseline

Human AWS access is managed through IAM Identity Center, not IAM users. The `identity` stack creates group-based permission sets and account assignments so access stays centralized, temporary, and auditable.

## Workforce Access

- Use an external IdP such as Okta, Microsoft Entra ID, or Google Workspace with SCIM provisioning when available.
- Assign groups, not individual users, to AWS accounts.
- Keep `BreakGlassAdministrator` membership empty by default and review it separately from normal engineering access.
- Prefer short sessions for privileged access. The template uses one hour for break-glass, two hours for platform operations, and four hours for read-only access.
- Refer to IAM Identity Center permission-set names in `eks.accessGrants`; the
  workload-account stack resolves the generated role's random suffix and
  creates scoped EKS Access Entries. Do not copy `AWSReservedSSO_*` ARNs by
  hand.

The stack follows AWS IAM guidance to use federation and temporary credentials for people, and IAM Identity Center permission sets for centralized multi-account access.

The Pulumi policy pack inspects IAM Identity Center permission set inline
policies for the same wildcard, `NotAction`, and unbounded
privilege-escalation rules it applies to plain IAM policies, so SSO inline
policies cannot smuggle in `Action: "*"` or unscoped `iam:PassRole`.

## GitHub Actions Access

The `github-oidc` stack creates an AWS OIDC provider and repository-scoped IAM roles for GitHub Actions. It does not create long-lived AWS access keys.

Trust policies are constrained by:

- audience: `sts.amazonaws.com`;
- repository owner and name;
- explicit Git refs such as `refs/heads/main`;
- explicit GitHub environments such as `production`.

Use separate roles for planning and deployment. Deployment roles should be bound to GitHub protected environments with required reviewers and branch restrictions. The example includes `infra-plan` and `infra-deploy-production` role entries.

## GitHub-Side Controls

The `github-governance` stack manages repository-side controls through the GitHub provider. Use [github-security.md](github-security.md) as the required GitHub mode before production deployment.

At minimum, enforce:

- branch protection or rulesets on `main`;
- required pull requests and CODEOWNERS review for infrastructure paths;
- required status checks for `npm test` and policy previews;
- protected deployment environments for staging and production;
- secret scanning, push protection, Dependabot, and code scanning;
- OIDC token permissions only on jobs that assume AWS roles.
