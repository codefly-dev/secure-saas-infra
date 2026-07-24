# Management-seed onboarding

This repository currently qualifies only the AWS Organizations management
seed. It does not qualify Codefly, GitOps, Kubernetes, network, EKS, database,
or application onboarding.

Create the ignored local inputs from the reviewed examples:

```sh
cp onboarding.config.example.json onboarding.local.json
cp Pulumi.management.yaml.example Pulumi.management.yaml
```

Set the real commercial-AWS management account ID, globally unique member
account emails, Pulumi Cloud organization/backend, and exact pre-existing SAML
source-role ARNs. Bind `managementBootstrapSamlMetadataSha256` to the exact
UTF-8 metadata returned by `iam:GetSAMLProvider`; the provider must have no
tags or private keys and must report `Allowed` assertion-encryption mode. Keep
`seedWave: organization-only`; `full` is preview-only and its apply is
machine-blocked.

Run the credential-free checks that actually exist in this release:

```sh
npm run bootstrap:doctor
npm run bootstrap:access-bundle -- --config onboarding.local.json
npm run bootstrap:verify-access-bundle
npm run validate:local
```

These commands make no AWS call. The complete independent-signing, native
runtime, exact access-provisioning, preview, and apply sequence is in
[management-seed-runbook.md](management-seed-runbook.md). The separately
governed initial SAML/role/boundary foundation is the irreducible external AWS
prerequisite. For a truly new account, use only the runbook's two-person,
console-only root ceremony; it forbids root access keys, CLI/API use, and any
resource outside the exact reviewed foundation. The first repository-governed AWS mutation is access
CloudFormation change-set preparation; the first seed apply creates only the
Organization and enables the two reviewed policy types.

Do not run the legacy `onboard`, `preflight`, `verify:onboarding`, raw Pulumi,
GitOps, Helm, or Kubernetes commands described in historical platform plans.
They are outside the qualified management-seed release.
