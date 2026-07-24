import {
  parseWorkloadIdentityBinding,
  type WorkloadIdentityBinding,
} from "../../core";
import type { AwsIamPlan } from "./iamAdapter";

export interface AwsWorkloadIdentityPrerequisites {
  computeMode: "eks-auto-mode";
  podIdentityAgent: "built-in";
  networkAttachmentMode: "node-class-pod-security-group";
  dedicatedNodeClassRequired: true;
}

export interface AwsWorkloadIdentityBindingPlan {
  cloud: "aws";
  credentialMode: "eks-pod-identity";
  bindingId: string;
  bindingDigest: string;
  identityId: string;
  roleArn: string;
  oidcSubject: string;
  audience: "pods.eks.amazonaws.com";
  allowedResourceIds: readonly string[];
  networkBoundary: {
    id: string;
    securityGroupId: string;
    enforcingMode: "strict";
  };
  prerequisites: AwsWorkloadIdentityPrerequisites;
  podIdentityAssociation: {
    namespace: string;
    serviceAccount: string;
    roleArn: string;
    disableSessionTags: false;
  };
  serviceAccount: {
    apiVersion: "v1";
    kind: "ServiceAccount";
    metadata: {
      name: string;
      namespace: string;
      labels: Readonly<Record<string, string>>;
      annotations: Readonly<Record<string, string>>;
    };
    automountServiceAccountToken: false;
  };
  nodeClassNetworkAttachment: {
    apiVersion: "eks.amazonaws.com/v1";
    kind: "NodeClass";
    granularity: "dedicated-node-class";
    securityGroupId: string;
    schedulingBindingRequired: true;
  };
}

export function compileAwsWorkloadIdentityBinding(
  value: WorkloadIdentityBinding,
  iamPlan: AwsIamPlan,
  prerequisites: AwsWorkloadIdentityPrerequisites,
): AwsWorkloadIdentityBindingPlan {
  const binding = parseWorkloadIdentityBinding(value);
  if (binding.cloud.provider !== "aws") {
    throw new Error(
      `AWS workload identity compiler cannot compile provider '${binding.cloud.provider}'.`,
    );
  }
  const roleArn = exactRoleArn(binding.cloud.roleRef);
  if (binding.kubernetes.audience !== "pods.eks.amazonaws.com") {
    throw new Error(
      "AWS EKS Pod Identity audience must be exactly 'pods.eks.amazonaws.com'.",
    );
  }
  if (
    prerequisites.computeMode !== "eks-auto-mode" ||
    prerequisites.podIdentityAgent !== "built-in" ||
    prerequisites.networkAttachmentMode !== "node-class-pod-security-group" ||
    !prerequisites.dedicatedNodeClassRequired
  ) {
    throw new Error(
      "AWS workload identity binding requires EKS Auto Mode built-in Pod Identity and a dedicated NodeClass Pod security-group attachment.",
    );
  }
  const association = iamPlan.workloadIdentityAssociations.filter(
    (candidate) => candidate.identityId === binding.identityId,
  );
  if (association.length !== 1) {
    throw new Error(
      `AWS workload identity '${binding.identityId}' must resolve to exactly one IAM association; found ${association.length}.`,
    );
  }
  const selected = association[0];
  if (
    selected.roleArn !== roleArn ||
    selected.namespace !== binding.kubernetes.namespace ||
    selected.serviceAccount !== binding.kubernetes.serviceAccount ||
    selected.mode !== "eks-pod-identity" ||
    selected.sessionTagsEnabled !== true
  ) {
    throw new Error(
      `AWS Pod Identity association for '${binding.identityId}' does not match its exact role, namespace, ServiceAccount, and session-tag binding.`,
    );
  }
  const trust = iamPlan.trustPolicies.filter(
    (candidate) => candidate.identityId === binding.identityId,
  );
  if (
    trust.length !== 1 ||
    trust[0].maxSessionDurationSeconds !==
      binding.cloud.maxSessionDurationSeconds
  ) {
    throw new Error(
      `AWS trust plan for '${binding.identityId}' does not match its exact session duration.`,
    );
  }
  const policy = iamPlan.identityPolicies.filter(
    (candidate) => candidate.identityId === binding.identityId,
  );
  if (
    policy.length !== 1 ||
    !sameSet(policy[0].resourceIds, binding.allowedResourceIds)
  ) {
    throw new Error(
      `AWS identity policy for '${binding.identityId}' does not match its exact allowed resource identities.`,
    );
  }
  const securityGroupId = securityGroupIdFromReference(
    binding.networkBoundary.providerResourceRef,
  );
  const bindingLabel = "security.deus.dev/workload-identity-binding";
  const labels = { [bindingLabel]: binding.id };
  return {
    cloud: "aws",
    credentialMode: "eks-pod-identity",
    bindingId: binding.id,
    bindingDigest: binding.evidence.bindingDigest,
    identityId: binding.identityId,
    roleArn,
    oidcSubject: binding.kubernetes.oidcSubject,
    audience: "pods.eks.amazonaws.com",
    allowedResourceIds: [...binding.allowedResourceIds].sort(),
    networkBoundary: {
      id: binding.networkBoundary.id,
      securityGroupId,
      enforcingMode: "strict",
    },
    prerequisites,
    podIdentityAssociation: {
      namespace: binding.kubernetes.namespace,
      serviceAccount: binding.kubernetes.serviceAccount,
      roleArn,
      disableSessionTags: false,
    },
    serviceAccount: {
      apiVersion: "v1",
      kind: "ServiceAccount",
      metadata: {
        name: binding.kubernetes.serviceAccount,
        namespace: binding.kubernetes.namespace,
        labels,
        annotations: {
          "security.deus.dev/workload-identity-mode": "eks-pod-identity",
          "security.deus.dev/workload-identity-audience":
            binding.kubernetes.audience,
          "security.deus.dev/workload-identity-binding-digest":
            binding.evidence.bindingDigest,
          "security.deus.dev/cloud-identity-provider": "aws",
          "security.deus.dev/cloud-role-reference": roleArn,
        },
      },
      automountServiceAccountToken: false,
    },
    nodeClassNetworkAttachment: {
      apiVersion: "eks.amazonaws.com/v1",
      kind: "NodeClass",
      granularity: "dedicated-node-class",
      securityGroupId,
      schedulingBindingRequired: true,
    },
  };
}

function exactRoleArn(value: string): string {
  if (
    !/^arn:(?:aws|aws-us-gov|aws-cn):iam::\d{12}:role\/[A-Za-z0-9+=,.@_\/-]+$/.test(
      value,
    ) ||
    value.includes("*") ||
    value.includes("..")
  ) {
    throw new Error(
      "AWS workload identity role must be one exact IAM role ARN.",
    );
  }
  return value;
}

function securityGroupIdFromReference(value: string): string {
  const match = /^aws:\/\/ec2\/security-group\/(sg-[a-f0-9]{8,17})$/.exec(
    value,
  );
  if (!match) {
    throw new Error(
      "AWS network boundary must reference one exact EC2 security group.",
    );
  }
  return match[1];
}

function sameSet(left: readonly string[], right: readonly string[]): boolean {
  return (
    left.length === right.length &&
    [...left].sort().every((entry, index) => entry === [...right].sort()[index])
  );
}
