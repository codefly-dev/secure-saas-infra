# Public Ingress Architecture

Mind's public-facing API uses a **single edge hub**: CloudFront + AWS WAFv2 +
ACM, talking through a CloudFront **VPC Origin** to an **internal NLB** in
the platform spoke. Istio ambient handles in-mesh mTLS and per-tenant
authorization. No public IP exists in any VPC we own.

## Request path

```
customer browser
  ↓ HTTPS (TLS 1.3 minimum, enforced by ACM viewer policy)
Amazon CloudFront                 — edge PoPs, DDoS, TLS termination, edge cache
  ↓ AWS WAFv2 (CLOUDFRONT scope)  — managed rule sets + bot control + per-IP and
                                    per-path rate limits, redacts auth headers
  ↓ Strict response headers       — HSTS, frame-deny, no-sniff, referrer policy,
                                    CSP baseline (default-src 'none')
  ↓ VPC Origin (PrivateLink)      — AWS-managed private link, no public IP
internal NLB (private subnets)    — provisioned by AWS LB Controller (EKS Auto
                                    Mode), targets are Istio ingress-gateway pods
  ↓
istio-ingress-gateway pod
  ↓ ambient ztunnel (mTLS STRICT)
  ↓ Gateway API HTTPRoute
Mind backend pods                 — control plane in platform-prod
```

## Why CloudFront + VPC Origin instead of a public ALB

| Criterion             | Public ALB in network/ingress account         | CloudFront + VPC Origin                                                           |
| --------------------- | --------------------------------------------- | --------------------------------------------------------------------------------- |
| Public IP in your VPC | yes (the ALB)                                 | **no**                                                                            |
| DDoS protection       | Shield Standard on ALB                        | Shield Standard at edge (further out)                                             |
| L7 inspection         | WAF on ALB                                    | WAF on CloudFront (same engine, edge-attached)                                    |
| TGW data-transfer     | every customer byte traverses TGW (~$0.02/GB) | CloudFront → spoke via VPC Origin **bypasses TGW**                                |
| Latency               | extra hop through TGW                         | edge PoP closer to user                                                           |
| Per-spoke isolation   | shared ALB, complex security groups           | each spoke has its own internal NLB; CloudFront origin group routes per host/path |
| TLS cert mgmt         | one ALB cert                                  | one CloudFront cert (us-east-1)                                                   |

The "hub" you want is at the AWS edge (CloudFront + WAF), not in a hub VPC.

## Controller and routing ownership

The EKS clusters use Auto Mode, so the AWS-managed load-balancing capability is
the only controller allowed to reconcile the internal NLB. The Istio gateway
Service declares `loadBalancerClass: eks.amazonaws.com/nlb`, internal scheme,
IP targets, cross-zone balancing, and the Envoy readiness endpoint. Do not
install the self-managed AWS Load Balancer Controller into these clusters.

Argo CD owns the pinned Istio/Gateway API installation. Istio owns L7 routing
through `Gateway`/`HTTPRoute`; application delivery owns only its authorized
routes and backends. Pulumi owns CloudFront, WAF, ACM, logs, and the VPC Origin.
An ALB is an explicit alternative for a service that intentionally bypasses
Istio—it is not another L7 hop in front of the same Istio gateway.

AWS currently recommends its load-balancer controller model over the legacy
in-tree service controller, and EKS Auto Mode provides that capability without
a separate installation. Istio intends Kubernetes Gateway API to become its
default traffic API. See the AWS [EKS load-balancing guidance](https://docs.aws.amazon.com/eks/latest/best-practices/load-balancing.html),
[Auto Mode networking constraints](https://docs.aws.amazon.com/eks/latest/userguide/auto-networking.html),
and Istio [Gateway API deployment model](https://istio.io/latest/docs/tasks/traffic-management/ingress/gateway-api/).
This pattern centralizes everything that benefits from centralization
(inspection, TLS, DDoS, log sink) and skips centralization of the L4 LB,
which would only add TGW cost and latency.

## What the `ingress` Pulumi stack creates

`Pulumi.ingress.yaml.example` deploys (all in us-east-1, the CloudFront/WAF
home region, regardless of workload region):

- **ACM certificate** for the public hostname(s), DNS-validated via Route 53.
- **CloudFront VPC Origin** pointing at the internal NLB ARN exported by the
  platform stack.
- **CloudFront Distribution**:
  - HTTP/3 + IPv6 enabled.
  - Minimum TLS 1.3 (configurable; rejects 2018/2019 viewer policies).
  - WAF web ACL attached (the `waf` stack with `scope: CLOUDFRONT`).
  - Default `viewerProtocolPolicy: redirect-to-https`.
  - Caching disabled by default — every tenant sees their own response.
    Per-route caching can be added via `orderedCacheBehaviors`.
  - `orderedCacheBehaviors` for the model gateway URI prefixes
    (`/v1/models*`, `/v1/agents*`) — `https-only`, no cache, paired with the
    WAF model-gateway sub-rate-limit.
  - Geo restriction (off by default; whitelist or blacklist supported).
  - Access logs to a KMS-encrypted S3 bucket with 365-day retention.
- **Strict response headers** policy: HSTS (2 years, preload), frame-deny,
  content-type sniffing off, strict referrer policy, configurable CSP.
- **Route 53 alias record** pointing the apex/SAN names at the distribution.

The mandatory Pulumi policy pack rejects:

- CloudFront distributions without WAF, without logging, with weak TLS
  (`< TLSv1.2_2021`), or with public-IP origins (`customOriginConfig`).
- ACM certificates not using DNS validation.

## Required wiring

`Pulumi.ingress.yaml` needs:

- `domainName` and optional `subjectAlternativeNames`.
- `hostedZoneId` (Route 53) for cert validation + the alias record.
- `internalNlbArn` and `originDomainName` from a post-Argo observation of the
  exact `istio-ingress/istio-ingress` Service provisioned by EKS Auto Mode.
- `webAclArn` from the `waf` stack (with `scope: CLOUDFRONT`).

Workflow:

1. Run the platform cluster and Argo CD stacks, wait for the exact Istio
   gateway Service to report an internal EKS Auto Mode NLB, and record its ARN
   and DNS name as the reviewed runtime handoff.
2. Run the `waf` stack with `scope: CLOUDFRONT` — that web ACL must live in
   us-east-1 because CloudFront-scope WAF is global.
3. Run the `ingress` stack with the values from steps 1 and 2.

## ExternalDNS and Argo Rollouts

The GitOps baseline now runs:

- **ExternalDNS** in the `external-dns` namespace, watching `Service`,
  `Ingress`, and Gateway API resources (`HTTPRoute`, `GRPCRoute`,
  `TLSRoute`, `TCPRoute`, `UDPRoute`). When you add a Gateway with a
  hostname annotation, ExternalDNS creates the Route 53 record automatically.
  The TXT-registry pattern protects against drift.
- **Argo Rollouts** in the `argo-rollouts` namespace, with the dashboard as
  ClusterIP only (reachable via Tailscale operator). Use the `Rollout`
  CRD instead of `Deployment` for production services to get canary or
  blue-green deploys with metric-based promotion.

Both run with Pod Security `restricted`, dropped capabilities, read-only
root filesystem, RuntimeDefault seccomp.

## Threat model summary

| Threat                                      | Control                                                                                                                 |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| DDoS                                        | CloudFront edge + Shield Standard (Advanced optional)                                                                   |
| Credential stuffing / brute force           | WAF rate-based statement (per-IP)                                                                                       |
| Inference flooding                          | WAF model-gateway rate-based statement (per-IP, scoped to `/v1/models*`, `/v1/agents*`)                                 |
| OWASP Top 10                                | AWSManagedRulesCommonRuleSet + KnownBadInputs + IpReputation + AnonymousIp + BotControl                                 |
| TLS downgrade                               | `MinimumProtocolVersion: TLSv1.3_2021`                                                                                  |
| Header injection / CSP bypass               | Strict response headers policy with HSTS preload                                                                        |
| Origin discovery / direct-to-origin attacks | VPC Origin = no public IP for the NLB; origin not reachable from the internet                                           |
| Cross-tenant cache poisoning                | Caching disabled by default; tenant-aware caching requires explicit per-route cache key configuration                   |
| Header smuggling for auth                   | WAF redacts `authorization`, `cookie`, `x-api-key` in logs; Istio AuthorizationPolicy enforces tenant scope per request |
| Geographic restriction                      | Optional `geoRestrictionType: whitelist` for regulated tenants                                                          |
