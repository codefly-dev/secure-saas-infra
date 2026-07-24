import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  compileAwsIam,
  compileAwsWorkloadIdentityBinding,
  type AwsIamProviderExtensions,
} from "../src/adapters/aws";
import {
  createReferenceBlueprint,
  parseWorkloadIdentityBinding,
  workloadIdentityBindingDigest,
  type WorkloadIdentityBinding,
} from "../src/core";

const prerequisites = {
  computeMode: "eks-auto-mode" as const,
  podIdentityAgent: "built-in" as const,
  networkAttachmentMode: "node-class-pod-security-group" as const,
  dedicatedNodeClassRequired: true,
} as const;

function extensions(): AwsIamProviderExtensions {
  return {
    accountId: "123456789012",
    organizationId: "o-example123456",
    identities: {
      "tenant-a-workload": {
        roleArn: "arn:aws:iam::123456789012:role/tenant-a-workload",
        podIdentity: { namespace: "mind", serviceAccount: "tenant-a" },
      },
      "tenant-b-workload": {
        roleArn: "arn:aws:iam::123456789012:role/tenant-b-workload",
        podIdentity: { namespace: "mind", serviceAccount: "tenant-b" },
      },
    },
    resources: {
      "tenant-a-data": {
        kind: "data",
        bucketArn: "arn:aws:s3:::tenant-a-data",
        prefixByTenant: { "tenant-a": "tenants/tenant-a/" },
        keyArnByTenant: {
          "tenant-a": "arn:aws:kms:us-east-1:123456789012:key/tenant-a-key",
        },
      },
      "tenant-b-data": {
        kind: "data",
        bucketArn: "arn:aws:s3:::tenant-b-data",
        prefixByTenant: { "tenant-b": "tenants/tenant-b/" },
        keyArnByTenant: {
          "tenant-b": "arn:aws:kms:us-east-1:123456789012:key/tenant-b-key",
        },
      },
    },
  };
}

function binding(mutate?: (candidate: any) => void): WorkloadIdentityBinding {
  const candidate = JSON.parse(
    readFileSync("contracts/workload-identity-binding-v1alpha1.json", "utf8"),
  );
  candidate.allowedResourceIds = ["tenant-a-data"];
  mutate?.(candidate);
  const { evidence: _evidence, ...subject } = candidate;
  candidate.evidence.bindingDigest = workloadIdentityBindingDigest(subject);
  return parseWorkloadIdentityBinding(candidate);
}

test("AWS compiler joins exact KSA, EKS Pod Identity role, IAM resources, and Auto Mode NodeClass network attachment", () => {
  const iam = compileAwsIam(
    createReferenceBlueprint("dedicated-data"),
    extensions(),
  );
  const plan = compileAwsWorkloadIdentityBinding(binding(), iam, prerequisites);
  assert.equal(
    plan.roleArn,
    extensions().identities["tenant-a-workload"].roleArn,
  );
  assert.deepEqual(plan.allowedResourceIds, ["tenant-a-data"]);
  assert.deepEqual(plan.serviceAccount, {
    apiVersion: "v1",
    kind: "ServiceAccount",
    metadata: {
      name: "tenant-a",
      namespace: "mind",
      labels: {
        "security.deus.dev/workload-identity-binding": "tenant-a-runtime",
      },
      annotations: {
        "security.deus.dev/workload-identity-mode": "eks-pod-identity",
        "security.deus.dev/workload-identity-audience":
          "pods.eks.amazonaws.com",
        "security.deus.dev/workload-identity-binding-digest":
          binding().evidence.bindingDigest,
        "security.deus.dev/cloud-identity-provider": "aws",
        "security.deus.dev/cloud-role-reference":
          "arn:aws:iam::123456789012:role/tenant-a-workload",
      },
    },
    automountServiceAccountToken: false,
  });
  assert.deepEqual(plan.podIdentityAssociation, {
    namespace: "mind",
    serviceAccount: "tenant-a",
    roleArn: "arn:aws:iam::123456789012:role/tenant-a-workload",
    disableSessionTags: false,
  });
  assert.equal(plan.credentialMode, "eks-pod-identity");
  assert.equal(plan.audience, "pods.eks.amazonaws.com");
  assert.equal(
    "eks.amazonaws.com/role-arn" in plan.serviceAccount.metadata.annotations,
    false,
  );
  assert.deepEqual(plan.nodeClassNetworkAttachment, {
    apiVersion: "eks.amazonaws.com/v1",
    kind: "NodeClass",
    granularity: "dedicated-node-class",
    securityGroupId: "sg-0123456789abcdef0",
    schedulingBindingRequired: true,
  });
});

test("AWS compiler rejects role, subject, audience, resource, network, session, and prerequisite substitutions", () => {
  const iam = compileAwsIam(
    createReferenceBlueprint("dedicated-data"),
    extensions(),
  );
  const cases: Array<[WorkloadIdentityBinding, RegExp]> = [
    [
      binding((candidate) => {
        candidate.cloud.roleRef =
          "arn:aws:iam::123456789012:role/tenant-a-other";
      }),
      /does not match its exact role/,
    ],
    [
      binding((candidate) => {
        candidate.kubernetes.namespace = "other";
        candidate.kubernetes.oidcSubject =
          "system:serviceaccount:other:tenant-a";
        candidate.kubernetes.spiffeId =
          "spiffe://cluster.local/ns/other/sa/tenant-a";
      }),
      /does not match its exact role, namespace, ServiceAccount/,
    ],
    [
      binding((candidate) => {
        candidate.kubernetes.audience = "sts.amazonaws.com";
      }),
      /audience must be exactly/,
    ],
    [
      binding((candidate) => {
        candidate.allowedResourceIds = ["tenant-b-data"];
      }),
      /does not match its exact allowed resource/,
    ],
    [
      binding((candidate) => {
        candidate.networkBoundary.providerResourceRef =
          "aws://ec2/security-group/not-an-sg";
      }),
      /exact EC2 security group/,
    ],
    [
      binding((candidate) => {
        candidate.cloud.maxSessionDurationSeconds = 1800;
      }),
      /does not match its exact session duration/,
    ],
  ];
  for (const [candidate, error] of cases) {
    assert.throws(
      () => compileAwsWorkloadIdentityBinding(candidate, iam, prerequisites),
      error,
    );
  }
  assert.throws(
    () =>
      compileAwsWorkloadIdentityBinding(binding(), iam, {
        ...prerequisites,
        dedicatedNodeClassRequired: false,
      } as any),
    /requires EKS Auto Mode built-in Pod Identity/,
  );
});
