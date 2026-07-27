import test from "node:test";
import assert from "node:assert/strict";
import {
  IngressConfig,
  validateIngressConfig,
} from "../src/config";
import {
  flushPulumiMocks,
  installPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";

const baseline: IngressConfig = {
  domainName: "api.example.com",
  subjectAlternativeNames: ["app.example.com"],
  hostedZoneId: "Z00000000000000000000",
  internalNlbArn:
    "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/net/k8s-istio-ingress/0123456789abcdef",
  originDomainName:
    "k8s-istio-ingress-0123456789.elb.us-east-1.amazonaws.com",
  webAclArn:
    "arn:aws:wafv2:us-east-1:111111111111:global/webacl/deus-public-ingress-waf/abcd1234",
  priceClass: "PriceClass_100",
  minimumTlsVersion: "TLSv1.3_2021",
  geoRestrictionType: "none",
  geoRestrictionLocations: [],
  modelGatewayPathPrefixes: ["/v1/models", "/v1/agents"],
  contentSecurityPolicy:
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  logRetentionDays: 365,
};

test("validateIngressConfig accepts the modern baseline", () => {
  assert.doesNotThrow(() => validateIngressConfig(baseline));
});

test("validateIngressConfig rejects weak TLS, wrong NLB, and missing logging", () => {
  assert.throws(
    () =>
      validateIngressConfig({
        ...baseline,
        minimumTlsVersion: "TLSv1.2_2018",
      }),
    /TLSv1\.2_2021 or stronger/,
  );

  assert.throws(
    () =>
      validateIngressConfig({
        ...baseline,
        internalNlbArn:
          "arn:aws:elasticloadbalancing:us-east-1:111111111111:loadbalancer/app/some-alb/0123456789abcdef",
      }),
    /Network Load Balancer/,
  );

  assert.throws(
    () =>
      validateIngressConfig({
        ...baseline,
        domainName: "not-a-hostname",
      }),
    /valid DNS hostname/,
  );

  assert.throws(
    () =>
      validateIngressConfig({
        ...baseline,
        geoRestrictionType: "whitelist",
        geoRestrictionLocations: [],
      }),
    /geoRestrictionLocations/,
  );

  assert.throws(
    () => validateIngressConfig({ ...baseline, logRetentionDays: 30 }),
    /logRetentionDays/,
  );

  assert.throws(
    () =>
      validateIngressConfig({ ...baseline, contentSecurityPolicy: "" }),
    /contentSecurityPolicy/,
  );
});

test("ingress stack creates CloudFront with VPC Origin, WAF, ACM, hardened headers, and KMS-encrypted access logs", async () => {
  const { resources } = await installPulumiMocks();
  const { createPublicIngress } = await import("../src/ingress.js");

  createPublicIngress(baseline);

  await flushPulumiMocks();

  const distribution = resourcesOfType(
    resources,
    "aws:cloudfront/distribution:Distribution",
  )[0];
  assert.ok(distribution);
  assert.equal(distribution.inputs.enabled, true);
  assert.equal(distribution.inputs.httpVersion, "http2and3");
  assert.equal(distribution.inputs.isIpv6Enabled, true);
  assert.equal(
    distribution.inputs.viewerCertificate.minimumProtocolVersion,
    "TLSv1.3_2021",
  );
  assert.match(
    distribution.inputs.webAclId,
    /^arn:aws:wafv2:us-east-1:.+:global\/webacl\//,
  );
  assert.equal(
    distribution.inputs.defaultCacheBehavior.viewerProtocolPolicy,
    "redirect-to-https",
  );
  assert.equal(distribution.inputs.origins.length, 1);
  const origin = distribution.inputs.origins[0];
  assert.ok(origin.vpcOriginConfig);
  assert.equal(origin.customOriginConfig, undefined);
  assert.equal(distribution.inputs.loggingConfig.includeCookies, false);

  const orderedCacheBehaviors =
    distribution.inputs.orderedCacheBehaviors as Array<Record<string, any>>;
  assert.equal(orderedCacheBehaviors.length, 2);
  assert.ok(
    orderedCacheBehaviors.every(
      (entry) => entry.viewerProtocolPolicy === "https-only",
    ),
  );
  assert.deepEqual(
    orderedCacheBehaviors.map((entry) => entry.pathPattern),
    ["/v1/models*", "/v1/agents*"],
  );

  const vpcOrigin = resourcesOfType(
    resources,
    "aws:cloudfront/vpcOrigin:VpcOrigin",
  )[0];
  assert.ok(vpcOrigin);
  assert.equal(
    vpcOrigin.inputs.vpcOriginEndpointConfig.originProtocolPolicy,
    "https-only",
  );
  assert.match(
    vpcOrigin.inputs.vpcOriginEndpointConfig.arn,
    /:loadbalancer\/net\//,
  );

  const responseHeaders = resourcesOfType(
    resources,
    "aws:cloudfront/responseHeadersPolicy:ResponseHeadersPolicy",
  )[0];
  assert.ok(responseHeaders);
  assert.equal(
    responseHeaders.inputs.securityHeadersConfig.strictTransportSecurity
      .accessControlMaxAgeSec,
    63072000,
  );
  assert.equal(
    responseHeaders.inputs.securityHeadersConfig.frameOptions.frameOption,
    "DENY",
  );
  assert.equal(
    responseHeaders.inputs.securityHeadersConfig.contentTypeOptions.override,
    true,
  );

  const certificate = resourcesOfType(
    resources,
    "aws:acm/certificate:Certificate",
  )[0];
  assert.ok(certificate);
  assert.equal(certificate.inputs.validationMethod, "DNS");
  assert.deepEqual(certificate.inputs.subjectAlternativeNames, [
    "app.example.com",
  ]);

  const aliasRecord = resourcesOfType(
    resources,
    "aws:route53/record:Record",
  ).find((record) => record.inputs.aliases);
  assert.ok(aliasRecord);

  const logBuckets = resourcesOfType(resources, "aws:s3/bucket:Bucket");
  assert.equal(logBuckets.length, 1);
  assert.equal(logBuckets[0].inputs.forceDestroy, false);

  const encryption = resourcesOfType(
    resources,
    "aws:s3/bucketServerSideEncryptionConfiguration:BucketServerSideEncryptionConfiguration",
  )[0];
  assert.equal(
    encryption.inputs.rules[0].applyServerSideEncryptionByDefault.sseAlgorithm,
    "aws:kms",
  );
  assert.equal(encryption.inputs.rules[0].blockedEncryptionTypes[0], "SSE-C");

  const lifecycle = resourcesOfType(
    resources,
    "aws:s3/bucketLifecycleConfiguration:BucketLifecycleConfiguration",
  )[0];
  assert.equal(lifecycle.inputs.rules[0].expiration.days, 365);
});

test("ExternalDNS and Argo Rollouts Argo CD applications are wired in", async () => {
  const { readFileSync } = await import("node:fs");

  const externalDns = readFileSync(
    "gitops/bootstrap/argocd/base/apps/external-dns.application.yaml",
    "utf8",
  );
  assert.match(externalDns, /chart: external-dns/);
  assert.match(externalDns, /provider: aws/);
  assert.match(externalDns, /gateway-httproute/);
  assert.match(externalDns, /readOnlyRootFilesystem: true/);

  const rollouts = readFileSync(
    "gitops/bootstrap/argocd/base/apps/argo-rollouts.application.yaml",
    "utf8",
  );
  assert.match(rollouts, /chart: argo-rollouts/);
  assert.match(rollouts, /dashboard:/);
  assert.match(rollouts, /type: ClusterIP/);
  assert.match(rollouts, /readOnlyRootFilesystem: true/);

  const kustomization = readFileSync(
    "gitops/bootstrap/argocd/base/kustomization.yaml",
    "utf8",
  );
  assert.match(kustomization, /apps\/external-dns\.application\.yaml/);
  assert.match(kustomization, /apps\/argo-rollouts\.application\.yaml/);
});
