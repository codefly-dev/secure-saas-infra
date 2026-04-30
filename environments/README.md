# Pulumi ESC Environment Templates

These are Pulumi ESC environment templates for `dev`, `staging`, and `production`.

They are examples because ESC environments live in Pulumi Cloud. Create them with names like:

- `secure-saas-infra/dev`
- `secure-saas-infra/staging`
- `secure-saas-infra/production`

Then reference them from stack YAML using:

```yaml
environment:
  - secure-saas-infra/dev
```

Keep secrets and dynamic AWS credentials in ESC or Vault-backed providers, not in `Pulumi.*.yaml` files.
