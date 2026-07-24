import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  parseWorkloadIdentityBinding,
  parseWorkloadIdentityBindingCatalog,
  selectWorkloadIdentityBinding,
  workloadIdentityBindingDigest,
  type WorkloadIdentityBinding,
} from "../src/core";

function fixture(): WorkloadIdentityBinding {
  return parseWorkloadIdentityBinding(
    JSON.parse(
      readFileSync("contracts/workload-identity-binding-v1alpha1.json", "utf8"),
    ),
  );
}

function changed(
  mutate: (binding: any) => void,
  resign = false,
): WorkloadIdentityBinding {
  const binding: any = structuredClone(fixture());
  mutate(binding);
  if (resign) {
    const { evidence: _evidence, ...subject } = binding;
    binding.evidence.bindingDigest = workloadIdentityBindingDigest(subject);
  }
  return binding;
}

test("workload identity binding is exact, closed, content-addressed, and credential-free", () => {
  const binding = fixture();
  const { evidence: _evidence, ...subject } = binding;
  assert.equal(
    binding.evidence.bindingDigest,
    workloadIdentityBindingDigest(subject),
  );
  assert.equal(binding.kubernetes.automountServiceAccountToken, false);
  assert.equal(binding.cloud.administrator, false);
  assert.equal(binding.cloud.shared, false);

  assert.throws(
    () => parseWorkloadIdentityBinding({ ...binding, extra: true }),
    /contain exactly/,
  );
  assert.throws(
    () =>
      parseWorkloadIdentityBinding(
        changed((candidate) => {
          candidate.cloud.roleRef = "arn:aws:iam::123456789012:role/tenant-a-*";
        }),
      ),
    /exact credential-free provider resource/,
  );
  assert.throws(
    () =>
      parseWorkloadIdentityBinding(
        changed((candidate) => {
          candidate.evidence.verificationEvidenceRef =
            "https://user:password@example.invalid/evidence";
        }),
      ),
    /credential-free exact reference/,
  );
});

test("namespace, ServiceAccount, OIDC, and SPIFFE substitutions fail closed", () => {
  assert.throws(
    () =>
      parseWorkloadIdentityBinding(
        changed((candidate) => {
          candidate.kubernetes.namespace = "other";
        }, true),
      ),
    /oidcSubject must exactly match/,
  );
  assert.throws(
    () =>
      parseWorkloadIdentityBinding(
        changed((candidate) => {
          candidate.kubernetes.serviceAccount = "other";
        }, true),
      ),
    /oidcSubject must exactly match/,
  );
  assert.throws(
    () =>
      parseWorkloadIdentityBinding(
        changed((candidate) => {
          candidate.kubernetes.oidcSubject = "system:serviceaccount:mind:*";
        }),
      ),
    /exact Kubernetes OIDC subject/,
  );
  assert.throws(
    () =>
      parseWorkloadIdentityBinding(
        changed((candidate) => {
          candidate.kubernetes.spiffeId =
            "spiffe://cluster.local/ns/mind/sa/other";
        }, true),
      ),
    /spiffeId must exactly match/,
  );
});

test("role, audience, tenant, environment, resource, and network substitutions invalidate evidence", () => {
  const mutations = [
    (binding: any) => {
      binding.cloud.roleRef = "arn:aws:iam::123456789012:role/tenant-a-other";
    },
    (binding: any) => {
      binding.kubernetes.audience = "other.example";
    },
    (binding: any) => {
      binding.platformTenantId = "tenant-b";
    },
    (binding: any) => {
      binding.environment = "production";
    },
    (binding: any) => {
      binding.allowedResourceIds = ["tenant-b-data"];
    },
    (binding: any) => {
      binding.networkBoundary.providerResourceRef =
        "aws://ec2/security-group/sg-0fedcba9876543210";
    },
  ];
  for (const mutate of mutations) {
    assert.throws(
      () => parseWorkloadIdentityBinding(changed(mutate)),
      /bindingDigest does not match/,
    );
  }
});

test("catalog rejects shared subjects, roles, ServiceAccounts, and network boundaries", () => {
  const first = fixture();
  const second = changed((binding) => {
    binding.id = "tenant-b-runtime";
    binding.platformTenantId = "tenant-b";
    binding.identityId = "tenant-b-workload";
    binding.kubernetes.serviceAccount = "tenant-b";
    binding.kubernetes.oidcSubject = "system:serviceaccount:mind:tenant-b";
    binding.kubernetes.spiffeId = "spiffe://cluster.local/ns/mind/sa/tenant-b";
    binding.cloud.roleRef = "arn:aws:iam::123456789012:role/tenant-b-workload";
    binding.allowedResourceIds = ["tenant-b-data"];
    binding.networkBoundary.id = "tenant-b-runtime-db-access";
    binding.networkBoundary.providerResourceRef =
      "aws://ec2/security-group/sg-0fedcba9876543210";
    binding.evidence.verificationEvidenceRef =
      "evidence://workload-identity/tenant-b-runtime/verification-01";
  }, true);
  const catalog = {
    apiVersion: first.apiVersion,
    kind: "WorkloadIdentityBindingCatalog",
    bindings: [first, second],
  };
  assert.equal(parseWorkloadIdentityBindingCatalog(catalog).bindings.length, 2);

  for (const mutate of [
    (binding: any) => {
      binding.kubernetes.serviceAccount = first.kubernetes.serviceAccount;
      binding.kubernetes.oidcSubject = first.kubernetes.oidcSubject;
      binding.kubernetes.spiffeId = first.kubernetes.spiffeId;
    },
    (binding: any) => {
      binding.cloud.roleRef = first.cloud.roleRef;
    },
    (binding: any) => {
      binding.networkBoundary.providerResourceRef =
        first.networkBoundary.providerResourceRef;
    },
  ]) {
    const duplicate = changed((binding) => {
      Object.assign(binding, structuredClone(second));
      mutate(binding);
    }, true);
    assert.throws(
      () =>
        parseWorkloadIdentityBindingCatalog({
          ...catalog,
          bindings: [first, duplicate],
        }),
      /is shared by bindings/,
    );
  }
});

test("placement selects one exact binding and rejects any substituted dimension", () => {
  const binding = fixture();
  const catalog = parseWorkloadIdentityBindingCatalog({
    apiVersion: binding.apiVersion,
    kind: "WorkloadIdentityBindingCatalog",
    bindings: [binding],
  });
  const placement = {
    organizationId: binding.organizationId,
    platformTenantId: binding.platformTenantId,
    applicationId: binding.applicationId,
    environment: binding.environment,
    cloudContextId: binding.cloudContext.id,
    cloudContextGeneration: binding.cloudContext.generation,
    identityId: binding.identityId,
    namespace: binding.kubernetes.namespace,
    serviceAccount: binding.kubernetes.serviceAccount,
  };
  assert.equal(
    selectWorkloadIdentityBinding(catalog, placement).id,
    binding.id,
  );
  for (const [field, value] of [
    ["organizationId", "other"],
    ["platformTenantId", "tenant-b"],
    ["applicationId", "warden"],
    ["environment", "production"],
    ["cloudContextId", "other"],
    ["cloudContextGeneration", 8],
    ["identityId", "other"],
    ["namespace", "other"],
    ["serviceAccount", "other"],
  ] as const) {
    assert.throws(
      () =>
        selectWorkloadIdentityBinding(catalog, {
          ...placement,
          [field]: value,
        }),
      /exactly one binding; found 0/,
    );
  }
});

test("verification evidence must have a positive validity interval", () => {
  assert.throws(
    () =>
      parseWorkloadIdentityBinding(
        changed((binding) => {
          binding.evidence.expiresAt = binding.evidence.verifiedAt;
        }),
      ),
    /expiresAt must be after/,
  );
});

test("verification evidence rejects impossible calendar timestamps", () => {
  assert.throws(
    () =>
      parseWorkloadIdentityBinding(
        changed((binding) => {
          binding.evidence.verifiedAt = "2026-02-30T12:00:00.000Z";
        }),
      ),
    /canonical calendar timestamp/,
  );
});
