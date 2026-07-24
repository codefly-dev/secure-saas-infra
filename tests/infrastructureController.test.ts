import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import {
  INFRASTRUCTURE_CONTROLLER_API_VERSION,
  authorizeInfrastructureControllerRequest,
  createInfrastructureStackOwnership,
  createReferenceInfrastructureControllerRequest,
  infrastructureAction,
  infrastructureClaimResourcePrefix,
  infrastructureResource,
  infrastructureStackOwnershipDigest,
  parseInfrastructureControllerRequest,
  type InfrastructureAuthorizationState,
  type InfrastructureControllerRequest,
  type InfrastructureOperation,
} from "../src/core";

const now = 1_800_000_000;

function state(
  redeemedCapabilityIds: ReadonlySet<string> = new Set(),
): InfrastructureAuthorizationState {
  return {
    nowEpochSeconds: now,
    expectedAudience: "infrastructure-controller",
    trustedCapabilityIssuers: ["https://auth.infrastructure.invalid"],
    redeemedCapabilityIds,
    maxCapabilityTtlSeconds: 600,
  };
}

test("controller contract authorizes every exact operation and redeems only mutation capabilities", () => {
  for (const operation of [
    "plan",
    "reconcile",
    "observe",
    "cancel",
    "delete",
  ] as const) {
    const request = createReferenceInfrastructureControllerRequest(operation);
    const decision = authorizeInfrastructureControllerRequest(request, state());
    assert.equal(decision.allowed, true, operation);
    assert.deepEqual(decision.reasonCodes, [], operation);
    assert.equal(
      decision.capabilityToRedeem,
      ["reconcile", "cancel", "delete"].includes(operation)
        ? request.capability.capabilityId
        : null,
      operation,
    );
    assert.equal(decision.audit.decision, "allow", operation);
    assert.equal(decision.audit.planDigest, request.plan?.planDigest ?? null);
  }
});

test("production reconciliation requires an independent plan approver", () => {
  const request = createReferenceInfrastructureControllerRequest(
    "reconcile",
    "production",
  );
  assert.equal(
    authorizeInfrastructureControllerRequest(request, state()).allowed,
    true,
  );

  request.approvals = [];
  const missing = authorizeInfrastructureControllerRequest(request, state());
  assert.equal(missing.allowed, false);
  assert.ok(missing.reasonCodes.includes("INFRA_APPROVAL_INSUFFICIENT"));

  request.approvals = [
    {
      approvalId: "self-approval",
      approverPrincipalId: request.actor.principalId,
      planDigest: request.plan!.planDigest,
      approvedAtEpochSeconds: now - 1,
    },
  ];
  const selfApproved = authorizeInfrastructureControllerRequest(
    request,
    state(),
  );
  assert.equal(selfApproved.allowed, false);
  assert.ok(selfApproved.reasonCodes.includes("INFRA_APPROVAL_INSUFFICIENT"));
});

test("protected deletion requires two distinct independent approvers", () => {
  const request = createReferenceInfrastructureControllerRequest("delete");
  assert.equal(
    authorizeInfrastructureControllerRequest(request, state()).allowed,
    true,
  );

  request.approvals = request.approvals.slice(0, 1);
  const decision = authorizeInfrastructureControllerRequest(request, state());
  assert.equal(decision.allowed, false);
  assert.ok(decision.reasonCodes.includes("INFRA_APPROVAL_INSUFFICIENT"));

  const duplicate = createReferenceInfrastructureControllerRequest("delete");
  duplicate.approvals = [
    duplicate.approvals[0],
    {
      ...duplicate.approvals[1],
      approverPrincipalId: duplicate.approvals[0].approverPrincipalId,
    },
  ];
  assert.throws(
    () => parseInfrastructureControllerRequest(duplicate),
    /must not contain duplicates/,
  );
});

test("controller authorization fails closed across every authority layer", () => {
  const cases: readonly [
    string,
    InfrastructureOperation,
    (request: InfrastructureControllerRequest) => void,
    string,
    InfrastructureAuthorizationState?,
  ][] = [
    [
      "missing mTLS",
      "plan",
      (request) => {
        request.actor.authenticationMethods = ["oidc"];
      },
      "INFRA_AUTHENTICATION_INSUFFICIENT",
    ],
    [
      "organization mismatch",
      "plan",
      (request) => {
        request.capability.organizationId = "org-attacker";
      },
      "INFRA_ORGANIZATION_MISMATCH",
    ],
    [
      "tenant mismatch",
      "plan",
      (request) => {
        request.capability.tenantId = "mind";
      },
      "INFRA_TENANT_MISMATCH",
    ],
    [
      "manifest omits permission",
      "plan",
      (request) => {
        request.plugin.permissions = [
          {
            action: "infra.claim.observe",
            resourcePrefix: request.plugin.permissions[0]!.resourcePrefix,
          },
        ];
      },
      "INFRA_PLUGIN_MANIFEST_DENIED",
    ],
    [
      "role grant omits action",
      "plan",
      (request) => {
        request.grant.actions = ["infra.claim.observe"];
      },
      "INFRA_ROLE_GRANT_DENIED",
    ],
    [
      "expired grant",
      "plan",
      (request) => {
        request.grant.expiresAtEpochSeconds = now;
      },
      "INFRA_ROLE_GRANT_EXPIRED",
    ],
    [
      "unverified signature",
      "plan",
      (request) => {
        request.capability.cryptographicallyVerified = false;
      },
      "INFRA_CAPABILITY_UNVERIFIED",
    ],
    [
      "untrusted issuer",
      "plan",
      (request) => {
        request.capability.issuer = "https://attacker.example";
      },
      "INFRA_CAPABILITY_ISSUER_UNTRUSTED",
    ],
    [
      "wrong audience",
      "plan",
      (request) => {
        request.capability.audience = "application-plugin";
      },
      "INFRA_CAPABILITY_AUDIENCE_MISMATCH",
    ],
    [
      "wrong principal",
      "plan",
      (request) => {
        request.capability.subjectId = "attacker-1";
      },
      "INFRA_CAPABILITY_BINDING_MISMATCH",
    ],
    [
      "wrong generation",
      "plan",
      (request) => {
        request.capability.claimGeneration += 1;
      },
      "INFRA_CAPABILITY_BINDING_MISMATCH",
    ],
    [
      "expired capability",
      "plan",
      (request) => {
        request.capability.expiresAtEpochSeconds = now;
      },
      "INFRA_CAPABILITY_TIME_INVALID",
    ],
    [
      "excessive capability TTL",
      "plan",
      (request) => {
        request.capability.issuedAtEpochSeconds = now - 601;
        request.capability.notBeforeEpochSeconds = now - 601;
      },
      "INFRA_CAPABILITY_TTL_EXCEEDED",
    ],
    [
      "reusable mutation capability",
      "reconcile",
      (request) => {
        request.capability.oneUse = false;
      },
      "INFRA_CAPABILITY_NOT_ONE_USE",
    ],
    [
      "replayed capability",
      "reconcile",
      () => {},
      "INFRA_CAPABILITY_REPLAYED",
      state(new Set(["cap-reconcile-1"])),
    ],
    [
      "missing idempotency key",
      "cancel",
      (request) => {
        request.idempotencyKey = null;
      },
      "INFRA_IDEMPOTENCY_KEY_MISSING",
    ],
    [
      "deadline after capability",
      "plan",
      (request) => {
        request.deadlineEpochSeconds =
          request.capability.expiresAtEpochSeconds + 1;
      },
      "INFRA_DEADLINE_INVALID",
    ],
    [
      "missing reviewed plan",
      "reconcile",
      (request) => {
        request.plan = null;
      },
      "INFRA_PLAN_REQUIRED",
    ],
    [
      "unexpected plan",
      "observe",
      (request) => {
        request.plan = {
          ...createReferenceInfrastructureControllerRequest("reconcile").plan!,
        };
      },
      "INFRA_PLAN_UNEXPECTED",
    ],
    [
      "changed desired state",
      "reconcile",
      (request) => {
        request.plan!.desiredStateDigest = "c".repeat(64);
      },
      "INFRA_PLAN_INVALID",
    ],
    [
      "plan digest substitution",
      "reconcile",
      (request) => {
        request.capability.planDigest = "c".repeat(64);
      },
      "INFRA_PLAN_DIGEST_MISMATCH",
    ],
    [
      "policy checks failed",
      "reconcile",
      (request) => {
        request.plan!.policyChecksPassed = false;
      },
      "INFRA_POLICY_CHECKS_FAILED",
    ],
  ];

  for (const [name, operation, mutate, expected, authorizationState] of cases) {
    const request = createReferenceInfrastructureControllerRequest(operation);
    mutate(request);
    const decision = authorizeInfrastructureControllerRequest(
      request,
      authorizationState ?? state(),
    );
    assert.equal(decision.allowed, false, name);
    assert.ok(decision.reasonCodes.includes(expected as any), name);
    assert.equal(decision.audit.decision, "deny", name);
  }
});

test("strict parser rejects unknown fields, wildcard resources, unsafe plugin privilege, and legacy tokens", () => {
  const cases: readonly [string, (request: any) => void, RegExp][] = [
    [
      "unknown authority",
      (request) => {
        request.awsCredentials = "embedded";
      },
      /awsCredentials is not allowed/,
    ],
    [
      "wildcard resource",
      (request) => {
        request.capability.resource =
          "organization/org-deus/tenant/warden/context/aws-platform-dev/claim/*";
      },
      /exact infrastructure resource/,
    ],
    [
      "provider credentials",
      (request) => {
        request.plugin.sandbox.providerCredentials = true;
      },
      /providerCredentials must be 'false'/,
    ],
    [
      "Pulumi backend access",
      (request) => {
        request.plugin.sandbox.pulumiBackendAccess = true;
      },
      /pulumiBackendAccess must be 'false'/,
    ],
    [
      "host socket",
      (request) => {
        request.plugin.sandbox.unixSockets = true;
      },
      /unixSockets must be 'false'/,
    ],
    [
      "legacy HMAC",
      (request) => {
        request.capability.format = "v1-hmac";
      },
      /format must be 'v2-ed25519'/,
    ],
    [
      "credential-bearing issuer",
      (request) => {
        request.capability.issuer = "https://user:password@auth.example";
      },
      /credential-free HTTPS URL/,
    ],
    [
      "manifest global wildcard",
      (request) => {
        request.plugin.permissions[0].resourcePrefix = "*";
      },
      /exact tenant\/context claim prefix/,
    ],
  ];

  for (const [name, mutate, expected] of cases) {
    const request: any = createReferenceInfrastructureControllerRequest();
    mutate(request);
    assert.throws(
      () => parseInfrastructureControllerRequest(request),
      expected,
      name,
    );
    const decision = authorizeInfrastructureControllerRequest(request, state());
    assert.deepEqual(decision.reasonCodes, ["INFRA_REQUEST_INVALID"], name);
  }
});

test("resource names and manifest prefixes are exact and tenant/context scoped", () => {
  assert.equal(infrastructureAction("delete"), "infra.claim.delete");
  assert.equal(
    infrastructureResource("org-deus", "warden", "aws-platform-dev", "db-1"),
    "organization/org-deus/tenant/warden/context/aws-platform-dev/claim/db-1",
  );
  assert.equal(
    infrastructureClaimResourcePrefix("org-deus", "warden", "aws-platform-dev"),
    "organization/org-deus/tenant/warden/context/aws-platform-dev/claim/",
  );
  assert.throws(
    () => infrastructureResource("org-deus", "*", "context", "claim"),
    /exact identifier/,
  );
});

test("claim-owned Pulumi stack metadata is deterministic, protected, and tamper evident", () => {
  const request = createReferenceInfrastructureControllerRequest("reconcile");
  const ownership = createInfrastructureStackOwnership(request, {
    stackId: "warden-aws-platform-dev-postgres-warden",
    providerId: "aws-managed-postgres",
    controllerVersion: "1.0.0",
    createdAt: "2027-01-15T08:00:00Z",
  });
  assert.equal(ownership.deletionProtection, true);
  assert.equal(ownership.ownershipDigest.length, 64);
  assert.equal(
    infrastructureStackOwnershipDigest(ownership),
    ownership.ownershipDigest,
  );

  const same = createInfrastructureStackOwnership(request, {
    stackId: "warden-aws-platform-dev-postgres-warden",
    providerId: "aws-managed-postgres",
    controllerVersion: "1.0.0",
    createdAt: "2027-01-15T08:00:00Z",
  });
  assert.deepEqual(same, ownership);

  const tampered = structuredClone(ownership);
  tampered.tenantId = "mind";
  assert.notEqual(
    infrastructureStackOwnershipDigest(tampered),
    tampered.ownershipDigest,
  );
});

test("published infrastructure controller contract and schema are strict and version aligned", () => {
  const contract = JSON.parse(
    readFileSync(
      "contracts/infrastructure-controller-request-v1alpha1.json",
      "utf8",
    ),
  );
  assert.deepEqual(
    contract,
    createReferenceInfrastructureControllerRequest("reconcile", "production"),
  );
  assert.deepEqual(parseInfrastructureControllerRequest(contract), contract);

  const schema = JSON.parse(
    readFileSync(
      "schemas/infrastructure-controller-request-v1alpha1.schema.json",
      "utf8",
    ),
  );
  assert.equal(
    schema.properties.apiVersion.const,
    INFRASTRUCTURE_CONTROLLER_API_VERSION,
  );
  assert.equal(schema.additionalProperties, false);
  for (const definition of [
    "actor",
    "claim",
    "plugin",
    "sandbox",
    "permission",
    "grant",
    "capability",
    "plan",
    "approval",
  ]) {
    assert.equal(schema.$defs[definition].additionalProperties, false);
  }
  assert.equal(
    schema.$defs.sandbox.properties.providerCredentials.const,
    false,
  );
  assert.equal(
    schema.$defs.sandbox.properties.pulumiBackendAccess.const,
    false,
  );
  assert.equal(schema.$defs.capability.properties.format.const, "v2-ed25519");
});

test("infrastructure controller contract renderer is deterministic and offline", () => {
  const source = readFileSync(
    "scripts/render-infrastructure-controller-contract.mjs",
    "utf8",
  );
  assert.doesNotMatch(source, /curl\s|fetch\(|https\.get/);
  const rendered = spawnSync(
    process.execPath,
    [
      "scripts/render-infrastructure-controller-contract.mjs",
      "--operation",
      "reconcile",
      "--environment-class",
      "production",
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(rendered.status, 0, rendered.stderr);
  assert.deepEqual(
    JSON.parse(rendered.stdout),
    JSON.parse(
      readFileSync(
        "contracts/infrastructure-controller-request-v1alpha1.json",
        "utf8",
      ),
    ),
  );
  const rejected = spawnSync(
    process.execPath,
    [
      "scripts/render-infrastructure-controller-contract.mjs",
      "--operation",
      "raw-pulumi",
    ],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.notEqual(rejected.status, 0);
  assert.match(rejected.stderr, /Unsupported operation/);
});
