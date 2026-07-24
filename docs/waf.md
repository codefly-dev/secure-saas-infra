# WAF and DDoS Defense

Public ingress (the customer-facing API gateway, the model gateway, the
control-plane web UI) is protected by an AWS WAFv2 Web ACL deployed by the
`waf` stack.

## Web ACL composition

`Pulumi.waf.yaml.example` defaults to:

- `defaultAction: allow`;
- per-IP rate-based statement (2,000 requests / 5 min) — priority 0, action
  `block`;
- AWS managed rule sets at priorities 1-4:
  `AWSManagedRulesCommonRuleSet`, `AWSManagedRulesKnownBadInputsRuleSet`,
  `AWSManagedRulesAmazonIpReputationList`, `AWSManagedRulesAnonymousIpList`;
- optional `AWSManagedRulesBotControlRuleSet` (BotControl COMMON inspection)
  at priority 5;
- optional model-gateway rate-based statement at priority 6, scoped via a
  `regexMatchStatement` that matches the configured URI prefixes (default
  `/v1/models`, `/v1/agents`). Tighter rate limit (200 req / 5 min by default)
  to defend the model-gateway path against credential stuffing and inference
  flooding.

The mandatory policy pack (`policy/index.ts`) rejects WAFv2 Web ACLs without a
rate-based statement or with `cloudwatchMetricsEnabled` disabled.

## Logging

- WebAcl logging is wired to a 365-day CloudWatch log group
  (`aws-waf-logs-<acl-name>`), required by AWS WAF for visibility into
  blocked/allowed requests.
- `authorization`, `cookie`, and `x-api-key` headers are redacted in the
  logging configuration.

Forward the log group into the security tooling account (subscription filter
to a Kinesis Firehose stream into the log archive bucket) once the SIEM is up.

## Association

WebACL ARN is exported as `wafWebAclArn`. Attach it to the public ALB / API
Gateway / CloudFront distribution from the platform stack.

For CloudFront, set `waf.scope: CLOUDFRONT` and deploy in `us-east-1` (CloudFront
Web ACLs must be there). For ALB / API Gateway, keep `REGIONAL`.

## Shield

Shield Standard is on for free in every AWS account. Shield Advanced is
recommended for the public ingress endpoint when you have a contractual SLA
that depends on availability under attack. Shield Advanced is _not_ deployed
by this stack — it requires a subscription decision.
