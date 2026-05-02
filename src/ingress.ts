import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";
import { IngressConfig, baseTags, named } from "./config";

export interface IngressResult {
  certificate: aws.acm.Certificate;
  certificateValidation?: aws.acm.CertificateValidation;
  vpcOrigin: aws.cloudfront.VpcOrigin;
  distribution: aws.cloudfront.Distribution;
  responseHeadersPolicy: aws.cloudfront.ResponseHeadersPolicy;
  logBucket: aws.s3.Bucket;
  logBucketKey: aws.kms.Key;
  aliasRecord?: aws.route53.Record;
  validationRecords?: aws.route53.Record[];
}

export function createPublicIngress(config: IngressConfig): IngressResult {
  // CloudFront and its WAF web ACL must live in us-east-1. Use a dedicated
  // provider so this module works regardless of the workload region.
  const usEast1Provider = new aws.Provider(named("ingress-us-east-1"), {
    region: "us-east-1",
  });
  const edgeOptions = { provider: usEast1Provider };

  const partition = aws.getPartitionOutput({});
  const current = aws.getCallerIdentityOutput({});

  // KMS key + S3 bucket for CloudFront access logs.
  const logBucketKey = new aws.kms.Key(
    named("ingress-cf-logs-key"),
    {
      description: "KMS key for CloudFront access logs.",
      enableKeyRotation: true,
      deletionWindowInDays: 30,
      policy: pulumi
        .all([current.accountId, partition.partition])
        .apply(([accountId, partitionName]) =>
          JSON.stringify({
            Version: "2012-10-17",
            Statement: [
              {
                Sid: "EnableRootAccountAdministration",
                Effect: "Allow",
                Principal: {
                  AWS: `arn:${partitionName}:iam::${accountId}:root`,
                },
                Action: "kms:*",
                Resource: "*",
              },
              {
                Sid: "AllowCloudFrontDeliveryService",
                Effect: "Allow",
                Principal: { Service: "delivery.logs.amazonaws.com" },
                Action: ["kms:GenerateDataKey*", "kms:Decrypt"],
                Resource: "*",
              },
            ],
          }),
        ),
      tags: tag("ingress-cf-logs-key"),
    },
    edgeOptions,
  );

  const logBucket = new aws.s3.Bucket(
    named("ingress-cf-logs"),
    {
      forceDestroy: false,
      tags: tag("ingress-cf-logs", { EvidenceClass: "cloudfront-access" }),
    },
    edgeOptions,
  );

  const logBucketPublicAccessBlock = new aws.s3.BucketPublicAccessBlock(
    named("ingress-cf-logs-public-access-block"),
    {
      bucket: logBucket.id,
      blockPublicAcls: true,
      blockPublicPolicy: true,
      ignorePublicAcls: true,
      restrictPublicBuckets: true,
    },
    edgeOptions,
  );

  new aws.s3.BucketOwnershipControls(
    named("ingress-cf-logs-ownership"),
    {
      bucket: logBucket.id,
      rule: { objectOwnership: "BucketOwnerPreferred" },
    },
    edgeOptions,
  );

  new aws.s3.BucketServerSideEncryptionConfiguration(
    named("ingress-cf-logs-encryption"),
    {
      bucket: logBucket.id,
      rules: [
        {
          applyServerSideEncryptionByDefault: {
            kmsMasterKeyId: logBucketKey.arn,
            sseAlgorithm: "aws:kms",
          },
          bucketKeyEnabled: true,
          blockedEncryptionTypes: ["SSE-C"],
        },
      ],
    },
    edgeOptions,
  );

  new aws.s3.BucketLifecycleConfiguration(
    named("ingress-cf-logs-lifecycle"),
    {
      bucket: logBucket.id,
      rules: [
        {
          id: "expire-cf-access-logs",
          status: "Enabled",
          filter: {},
          expiration: { days: config.logRetentionDays },
          abortIncompleteMultipartUpload: { daysAfterInitiation: 7 },
        },
      ],
    },
    edgeOptions,
  );

  new aws.s3.BucketPolicy(
    named("ingress-cf-logs-policy"),
    {
      bucket: logBucket.id,
      policy: logBucket.arn.apply((bucketArn) =>
        JSON.stringify({
          Version: "2012-10-17",
          Statement: [
            {
              Sid: "DenyInsecureTransport",
              Effect: "Deny",
              Principal: "*",
              Action: "s3:*",
              Resource: [bucketArn, `${bucketArn}/*`],
              Condition: { Bool: { "aws:SecureTransport": "false" } },
            },
            {
              Sid: "AllowCloudFrontLogDelivery",
              Effect: "Allow",
              Principal: { Service: "delivery.logs.amazonaws.com" },
              Action: ["s3:PutObject"],
              Resource: `${bucketArn}/*`,
              Condition: {
                StringEquals: {
                  "s3:x-amz-acl": "bucket-owner-full-control",
                },
              },
            },
          ],
        }),
      ),
    },
    { provider: usEast1Provider, dependsOn: [logBucketPublicAccessBlock] },
  );

  const certificate = new aws.acm.Certificate(
    named("ingress-cert"),
    {
      domainName: config.domainName,
      subjectAlternativeNames: config.subjectAlternativeNames,
      validationMethod: "DNS",
      tags: tag("ingress-cert"),
    },
    edgeOptions,
  );

  let validationRecords: aws.route53.Record[] | undefined;
  let certificateValidation: aws.acm.CertificateValidation | undefined;

  const allDomains = [config.domainName, ...config.subjectAlternativeNames];

  if (config.hostedZoneId) {
    validationRecords = allDomains.map((domain, index) => {
      const validationOption = certificate.domainValidationOptions.apply(
        (options) =>
          options.find((option) => option.domainName === domain) ?? options[0],
      );
      return new aws.route53.Record(
        named(`ingress-cert-validation-${index + 1}`),
        {
          zoneId: config.hostedZoneId!,
          name: validationOption.resourceRecordName.apply((value) => value!),
          type: validationOption.resourceRecordType.apply((value) => value!),
          records: [
            validationOption.resourceRecordValue.apply((value) => value!),
          ],
          ttl: 60,
          allowOverwrite: true,
        },
      );
    });

    certificateValidation = new aws.acm.CertificateValidation(
      named("ingress-cert-validation"),
      {
        certificateArn: certificate.arn,
        validationRecordFqdns: validationRecords.map((record) => record.fqdn),
      },
      edgeOptions,
    );
  }

  // Hardened response headers: HSTS, frame-deny, content-type sniffing off,
  // referrer-policy, COOP/COEP off (we'll add per-Gateway policies for
  // browser apps that need them), CSP-report-only baseline.
  const responseHeadersPolicy = new aws.cloudfront.ResponseHeadersPolicy(
    named("ingress-headers"),
    {
      comment: "Strict baseline security headers for Mind public ingress.",
      securityHeadersConfig: {
        strictTransportSecurity: {
          accessControlMaxAgeSec: 63072000,
          includeSubdomains: true,
          preload: true,
          override: true,
        },
        contentTypeOptions: { override: true },
        frameOptions: { frameOption: "DENY", override: true },
        referrerPolicy: {
          referrerPolicy: "strict-origin-when-cross-origin",
          override: true,
        },
        xssProtection: {
          modeBlock: true,
          protection: true,
          override: true,
        },
        contentSecurityPolicy: {
          contentSecurityPolicy: config.contentSecurityPolicy,
          override: false,
        },
      },
    },
    edgeOptions,
  );

  // VPC Origin: AWS-managed PrivateLink to the internal NLB in the platform
  // spoke. No public IP, no IGW, no public subnets.
  const vpcOrigin = new aws.cloudfront.VpcOrigin(
    named("ingress-vpc-origin"),
    {
      vpcOriginEndpointConfig: {
        name: named("ingress-vpc-origin"),
        arn: config.internalNlbArn,
        httpPort: 80,
        httpsPort: 443,
        originProtocolPolicy: "https-only",
        originSslProtocols: { items: ["TLSv1.2"], quantity: 1 },
      },
      tags: tag("ingress-vpc-origin"),
    },
    edgeOptions,
  );

  const distribution = new aws.cloudfront.Distribution(
    named("ingress-distribution"),
    {
      enabled: true,
      isIpv6Enabled: true,
      httpVersion: "http2and3",
      priceClass: config.priceClass,
      aliases: [config.domainName, ...config.subjectAlternativeNames],
      webAclId: config.webAclArn,
      origins: [
        {
          originId: "internal-nlb",
          domainName: config.originDomainName,
          vpcOriginConfig: {
            vpcOriginId: vpcOrigin.id,
            originReadTimeout: 30,
            originKeepaliveTimeout: 5,
          },
        },
      ],
      defaultCacheBehavior: {
        targetOriginId: "internal-nlb",
        viewerProtocolPolicy: "redirect-to-https",
        allowedMethods: [
          "GET",
          "HEAD",
          "OPTIONS",
          "PUT",
          "POST",
          "PATCH",
          "DELETE",
        ],
        cachedMethods: ["GET", "HEAD"],
        compress: true,
        // CachingDisabled — Mind's API surfaces are dynamic; tenants must not
        // see another tenant's cached response. Per-route caching can be
        // added with cacheBehaviors later.
        cachePolicyId: "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
        // AllViewerExceptHostHeader — forwards everything except Host so the
        // origin sees its own hostname, required for VPC Origins.
        originRequestPolicyId: "b689b0a8-53d0-40ab-baf2-68738e2966ac",
        responseHeadersPolicyId: responseHeadersPolicy.id,
      },
      orderedCacheBehaviors: config.modelGatewayPathPrefixes.map(
        (prefix, index): aws.types.input.cloudfront.DistributionOrderedCacheBehavior => ({
          pathPattern: prefix.endsWith("*") ? prefix : `${prefix}*`,
          targetOriginId: "internal-nlb",
          viewerProtocolPolicy: "https-only",
          allowedMethods: ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"],
          cachedMethods: ["GET", "HEAD"],
          compress: true,
          cachePolicyId: "4135ea2d-6df8-44a3-9df3-4b5a84be39ad",
          originRequestPolicyId: "b689b0a8-53d0-40ab-baf2-68738e2966ac",
          responseHeadersPolicyId: responseHeadersPolicy.id,
          // realtime metrics get expensive; rely on WAF + access logs for
          // model-gateway forensics.
        }),
      ),
      restrictions: {
        geoRestriction: {
          restrictionType: config.geoRestrictionType,
          locations: config.geoRestrictionLocations,
        },
      },
      viewerCertificate: {
        acmCertificateArn: certificateValidation
          ? certificateValidation.certificateArn
          : certificate.arn,
        sslSupportMethod: "sni-only",
        minimumProtocolVersion: config.minimumTlsVersion,
      },
      loggingConfig: {
        bucket: logBucket.bucketDomainName,
        includeCookies: false,
        prefix: `cloudfront-access/${named("ingress")}/`,
      },
      defaultRootObject: "",
      tags: tag("ingress-distribution", { EvidenceClass: "public-ingress" }),
    },
    {
      provider: usEast1Provider,
      dependsOn: certificateValidation ? [certificateValidation] : [],
    },
  );

  let aliasRecord: aws.route53.Record | undefined;
  if (config.hostedZoneId) {
    aliasRecord = new aws.route53.Record(named("ingress-alias"), {
      zoneId: config.hostedZoneId,
      name: config.domainName,
      type: "A",
      aliases: [
        {
          name: distribution.domainName,
          zoneId: distribution.hostedZoneId,
          evaluateTargetHealth: false,
        },
      ],
    });
  }

  return {
    certificate,
    certificateValidation,
    vpcOrigin,
    distribution,
    responseHeadersPolicy,
    logBucket,
    logBucketKey,
    aliasRecord,
    validationRecords,
  };
}

function tag(name: string, extra: Record<string, string> = {}) {
  return {
    ...baseTags,
    Name: named(name),
    ...extra,
  };
}
