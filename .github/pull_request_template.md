## Security Checklist

- [ ] This is either a source-change PR with no disposition edit, or a separate
      evidence-only promotion PR that changes only
      `security/adversarial-review-disposition.json` against its reviewed
      parent. Source qualification and promotion evidence are never collapsed
      into one commit.

- [ ] `npm test` passes locally or in CI.
- [ ] If AWS preview evidence is required, it was produced by `/usr/local/bin/deus-aws-bootstrap bootstrap --preview` from the sealed candidate, and its candidate/plan digests are attached.
- [ ] New AWS permissions avoid wildcard Allow, unbounded `iam:PassRole`, and long-lived keys.
- [ ] The management-seed positive inventory contains no Kubernetes, GitOps, Codefly, database, or application path.
- [ ] Post-seed authority remains blocked and delegated-admin/maintenance work is separate.
