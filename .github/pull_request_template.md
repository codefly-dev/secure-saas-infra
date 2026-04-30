## Security Checklist

- [ ] `npm test` passes locally or in CI.
- [ ] Infrastructure changes were previewed with `pulumi preview --policy-pack ./policy`.
- [ ] Customer-code execution changes preserve E2B BYOC or `deus-microvm` isolation.
- [ ] New AWS permissions avoid wildcard Allow, unbounded `iam:PassRole`, and long-lived keys.
- [ ] New Kubernetes workloads use digest-pinned, signed, attested images.
- [ ] New customer data paths document tenant scope, retention, deletion, and audit events.
