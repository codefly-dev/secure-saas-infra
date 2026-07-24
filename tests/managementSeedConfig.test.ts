import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  OrganizationConfig,
  validateOrganizationTopology,
} from "../src/managementSeedConfig";

const baseline: OrganizationConfig = {
  createOrganization: true,
  defaultAccountRoleName: "DeusOrganizationBootstrap",
  enableRamSharing: true,
  enableSecurityDelegatedAdmin: false,
  serviceAccessPrincipals: [
    "cloudtrail.amazonaws.com",
    "config.amazonaws.com",
    "config-multiaccountsetup.amazonaws.com",
    "guardduty.amazonaws.com",
    "securityhub.amazonaws.com",
    "inspector2.amazonaws.com",
  ],
  enabledPolicyTypes: ["SERVICE_CONTROL_POLICY", "S3_POLICY"],
  organizationalUnits: [
    { name: "Security" },
    { name: "Infrastructure" },
    { name: "Workloads" },
    { name: "NonProd", parent: "Workloads" },
    { name: "PreProd", parent: "Workloads" },
    { name: "Prod", parent: "Workloads" },
    { name: "Suspended" },
  ],
  accounts: [
    {
      name: "security-tooling",
      email: "security-tooling@aws.deus.internal",
      ou: "Security",
      kind: "security",
    },
    {
      name: "log-archive",
      email: "log-archive@aws.deus.internal",
      ou: "Security",
      kind: "log-archive",
    },
    {
      name: "network",
      email: "network@aws.deus.internal",
      ou: "Infrastructure",
      kind: "network",
    },
    {
      name: "shared-services",
      email: "shared-services@aws.deus.internal",
      ou: "Infrastructure",
      kind: "shared-services",
    },
    {
      name: "platform-dev",
      email: "platform-dev@aws.deus.internal",
      ou: "NonProd",
      kind: "workload",
    },
    {
      name: "execution-dev",
      email: "execution-dev@aws.deus.internal",
      ou: "NonProd",
      kind: "execution",
    },
    {
      name: "platform-staging",
      email: "platform-staging@aws.deus.internal",
      ou: "PreProd",
      kind: "workload",
      create: false,
    },
    {
      name: "execution-staging",
      email: "execution-staging@aws.deus.internal",
      ou: "PreProd",
      kind: "execution",
      create: false,
    },
    {
      name: "platform-prod",
      email: "platform-prod@aws.deus.internal",
      ou: "Prod",
      kind: "workload",
    },
    {
      name: "execution-prod",
      email: "execution-prod@aws.deus.internal",
      ou: "Prod",
      kind: "execution",
    },
  ],
  guardrailScpsEnabled: true,
  guardrailTargetOuNames: ["Security", "Infrastructure", "Workloads"],
};

test("management seed accepts only the reviewed greenfield topology", () => {
  assert.doesNotThrow(() => validateOrganizationTopology(baseline));
});

test("management seed rejects alternate ownership and incomplete controls", () => {
  for (const mutation of [
    { createOrganization: false },
    { enableRamSharing: false },
    { enableSecurityDelegatedAdmin: true },
    { guardrailScpsEnabled: false },
    { guardrailTargetOuNames: [] },
    { enabledPolicyTypes: ["SERVICE_CONTROL_POLICY"] },
    { serviceAccessPrincipals: ["cloudtrail.amazonaws.com"] },
  ] as Partial<OrganizationConfig>[]) {
    assert.throws(
      () => validateOrganizationTopology({ ...baseline, ...mutation }),
      /Management seed topology denied/,
    );
  }
});

test("management seed rejects identity, hierarchy, and account drift", () => {
  const forwardOu = structuredClone(baseline);
  [forwardOu.organizationalUnits[2], forwardOu.organizationalUnits[3]] = [
    forwardOu.organizationalUnits[3],
    forwardOu.organizationalUnits[2],
  ];
  assert.throws(
    () => validateOrganizationTopology(forwardOu),
    /unknown or later parent OU/,
  );

  const duplicateEmail = structuredClone(baseline);
  duplicateEmail.accounts[1].email = duplicateEmail.accounts[0].email;
  assert.throws(
    () => validateOrganizationTopology(duplicateEmail),
    /duplicate account email/,
  );

  const incomplete = structuredClone(baseline);
  incomplete.accounts = incomplete.accounts.filter(
    (account) => account.name !== "execution-dev",
  );
  assert.throws(
    () => validateOrganizationTopology(incomplete),
    /exactly 10 baseline accounts/,
  );
});

test("management seed rejects destructive lifecycle and unreviewed tag fields", () => {
  const destructive = structuredClone(baseline);
  destructive.accounts[0].closeOnDeletion = true;
  assert.throws(
    () => validateOrganizationTopology(destructive),
    /closeOnDeletion must be false/,
  );

  const unreviewedTag = structuredClone(baseline) as typeof baseline & {
    accounts: Array<(typeof baseline.accounts)[number] & { tags?: object }>;
  };
  unreviewedTag.accounts[0].tags = { Owner: "attacker" };
  assert.throws(
    () => validateOrganizationTopology(unreviewedTag),
    /contains unknown fields: tags/,
  );

  const enabledStaging = structuredClone(baseline);
  enabledStaging.accounts[6].create = true;
  enabledStaging.accounts[7].create = true;
  assert.throws(
    () => validateOrganizationTopology(enabledStaging),
    /must remain disabled until quota evidence is governed/,
  );
});

test("only organization-only is admitted for management seed apply", () => {
  const script = String.raw`
    import assert from "node:assert/strict";
    import { assertManagementSeedWaveOperation } from "./scripts/management-seed-contract.mjs";
    assert.doesNotThrow(() => assertManagementSeedWaveOperation("organization-only", "preview"));
    assert.doesNotThrow(() => assertManagementSeedWaveOperation("organization-only", "apply"));
    assert.doesNotThrow(() => assertManagementSeedWaveOperation("full", "preview"));
    assert.throws(
      () => assertManagementSeedWaveOperation("full", "apply"),
      /full apply is blocked.*member-access installation.*DeusOrganizationBootstrap retirement/,
    );
    assert.throws(
      () => assertManagementSeedWaveOperation("future", "preview"),
      /seedWave must be organization-only or full/,
    );
  `;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    {
      cwd: process.cwd(),
      encoding: "utf8",
    },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("full seed requires live account capacity and an exact existing subset", () => {
  const script = String.raw`
    import assert from "node:assert/strict";
    import {
      attestManagementSeedAccountCapacity,
      verifyManagementSeedAccountCapacityAttestation,
    } from "./scripts/management-seed-capacity.mjs";
    const organization = ${JSON.stringify(baseline)};
    const onboarding = { managementAccountId: "111111111111" };
    const binding = { bootstrapCandidateDigest: "${"a".repeat(64)}" };
    const attestCapacity = (organizationValue, observe, wave) =>
      attestManagementSeedAccountCapacity(
        organizationValue,
        onboarding,
        observe,
        wave,
        binding,
      );
    const responses = {
      "service-quotas list-service-quotas --service-code organizations --region us-east-1": {
        Quotas: [{ QuotaName: "Maximum number of accounts", Adjustable: true, Value: 9 }],
      },
      "organizations list-accounts": {
        Accounts: [{ Id: "111111111111", Name: "management", Email: "management@aws.deus.internal", State: "ACTIVE" }],
      },
      "organizations list-create-account-status --states IN_PROGRESS": { CreateAccountStatuses: [] },
      "organizations list-handshakes-for-organization --filter ActionType=INVITE": { Handshakes: [] },
    };
    const observe = (args) => structuredClone(responses[args.join(" ")]);
    const exact = attestCapacity(organization, observe, "full");
    assert.equal(exact.requiredAccounts, 9);
    assert.equal(exact.pass, true);
    assert.equal(exact.managementAccountId, onboarding.managementAccountId);
    assert.equal(exact.bootstrapCandidateDigest, binding.bootstrapCandidateDigest);
    assert.equal(exact.observationRequired, true);
    assert.match(exact.configurationDigest, /^[a-f0-9]{64}$/);
    assert.match(exact.attestationDigest, /^[a-f0-9]{64}$/);
    const organizationOnly = attestCapacity(
      organization,
      () => { throw new Error("AWS called"); },
      "organization-only",
    );
    assert.equal(organizationOnly.wave, "organization-only");
    assert.equal(organizationOnly.requiredAccounts, 1);
    assert.equal(organizationOnly.observationRequired, false);
    assert.equal(organizationOnly.managementAccountId, onboarding.managementAccountId);
    assert.equal(organizationOnly.bootstrapCandidateDigest, binding.bootstrapCandidateDigest);
    assert.match(organizationOnly.configurationDigest, /^[a-f0-9]{64}$/);
    assert.match(organizationOnly.attestationDigest, /^[a-f0-9]{64}$/);
    assert.doesNotThrow(() =>
      verifyManagementSeedAccountCapacityAttestation(organizationOnly, {
        managementAccountId: onboarding.managementAccountId,
        bootstrapCandidateDigest: binding.bootstrapCandidateDigest,
      }),
    );

    const substitutedAttestation = structuredClone(organizationOnly);
    substitutedAttestation.configurationDigest = "${"b".repeat(64)}";
    assert.throws(
      () => verifyManagementSeedAccountCapacityAttestation(substitutedAttestation, {
        managementAccountId: onboarding.managementAccountId,
        bootstrapCandidateDigest: binding.bootstrapCandidateDigest,
      }),
      /attestation digest is invalid/,
    );
    const otherCandidate = attestManagementSeedAccountCapacity(
      organization,
      onboarding,
      () => { throw new Error("AWS called"); },
      "organization-only",
      { bootstrapCandidateDigest: "${"b".repeat(64)}" },
    );
    assert.throws(
      () => verifyManagementSeedAccountCapacityAttestation(otherCandidate, {
        managementAccountId: onboarding.managementAccountId,
        bootstrapCandidateDigest: binding.bootstrapCandidateDigest,
      }),
      /not bound to this management account and bootstrap candidate/,
    );

    const changedConfiguration = structuredClone(organization);
    changedConfiguration.accounts[0].email = "security-tooling-2@aws.deus.internal";
    const changed = attestCapacity(
      changedConfiguration,
      () => { throw new Error("AWS called"); },
      "organization-only",
    );
    assert.notEqual(changed.configurationDigest, organizationOnly.configurationDigest);
    assert.notEqual(changed.attestationDigest, organizationOnly.attestationDigest);
    assert.throws(
      () => attestManagementSeedAccountCapacity(
        organization,
        onboarding,
        observe,
        "full",
        { bootstrapCandidateDigest: "substituted" },
      ),
      /exact bootstrap candidate digest/,
    );

    responses["service-quotas list-service-quotas --service-code organizations --region us-east-1"].Quotas[0].Value = 8;
    assert.throws(
      () => attestCapacity(organization, observe, "full"),
      /quota.*at or above 9/,
    );
    responses["service-quotas list-service-quotas --service-code organizations --region us-east-1"].Quotas[0].Value = 9;
    responses["organizations list-accounts"].Accounts.push({
      Id: "222222222222", Name: "attacker", Email: "attacker@example.net", State: "ACTIVE",
    });
    assert.throws(
      () => attestCapacity(organization, observe, "full"),
      /outside the reviewed seed/,
    );
    responses["organizations list-accounts"].Accounts.pop();

    responses["organizations list-create-account-status --states IN_PROGRESS"].CreateAccountStatuses = [{ Id: "car-example" }];
    assert.throws(
      () => attestCapacity(organization, observe, "full"),
      /concurrent.*creation.*forbidden/,
    );
    responses["organizations list-create-account-status --states IN_PROGRESS"].CreateAccountStatuses = [];

    responses["organizations list-handshakes-for-organization --filter ActionType=INVITE"].Handshakes = [{ State: "OPEN" }];
    assert.throws(
      () => attestCapacity(organization, observe, "full"),
      /pending.*invitation.*quota/,
    );
    responses["organizations list-handshakes-for-organization --filter ActionType=INVITE"].Handshakes = [{ State: "REQUESTED" }];
    assert.throws(
      () => attestCapacity(organization, observe, "full"),
      /pending.*invitation.*quota/,
    );
    responses["organizations list-handshakes-for-organization --filter ActionType=INVITE"].Handshakes = [{ State: "FUTURE_STATE" }];
    assert.throws(
      () => attestCapacity(organization, observe, "full"),
      /unknown.*invitation.*quota/,
    );
    responses["organizations list-handshakes-for-organization --filter ActionType=INVITE"].Handshakes = [];

    responses["organizations list-accounts"].Accounts[0].State = "SUSPENDED";
    assert.throws(
      () => attestCapacity(organization, observe, "full"),
      /non-active account/,
    );
    responses["organizations list-accounts"].Accounts[0].State = "ACTIVE";

    responses["organizations list-accounts"].Accounts[0] = {
      Id: "222222222222", Name: "platform-dev", Email: "platform-dev@aws.deus.internal", State: "ACTIVE",
    };
    assert.throws(
      () => attestCapacity(organization, observe, "full"),
      /inventory exceeds the reviewed seed/,
    );
    responses["organizations list-accounts"].Accounts[0] = {
      Id: "111111111111", Name: "management", Email: "management@aws.deus.internal", State: "ACTIVE",
    };

    responses["service-quotas list-service-quotas --service-code organizations --region us-east-1"].Quotas.push({
      QuotaName: "Maximum number of accounts", Adjustable: true, Value: 9,
    });
    assert.throws(
      () => attestCapacity(organization, observe, "full"),
      /quota.*at or above 9/,
    );
  `;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.equal(result.status, 0, result.stderr);
});

test("organization state proves the standalone-to-exact-baseline transition", () => {
  const script = String.raw`
    import assert from "node:assert/strict";
    import {
      attestManagementSeedOrganizationState,
      verifyManagementSeedOrganizationStateAttestation,
    } from "./scripts/management-seed-organization-state.mjs";
    const organization = ${JSON.stringify(baseline)};
    const onboarding = { managementAccountId: "111111111111" };
    const binding = { bootstrapCandidateDigest: "${"a".repeat(64)}" };
    const orgId = "o-abcdefghij";
    const rootId = "r-abcd";
    const values = new Map([
      ["organizations describe-organization --region us-east-1", { Organization: {
        Id: orgId,
        Arn: "arn:aws:organizations::111111111111:organization/" + orgId,
        FeatureSet: "ALL",
        ManagementAccountId: "111111111111",
      }}],
      ["organizations list-roots --region us-east-1", { Roots: [{
        Id: rootId,
        Arn: "arn:aws:organizations::111111111111:root/" + orgId + "/" + rootId,
        Name: "Root",
        PolicyTypes: [
          { Type: "SERVICE_CONTROL_POLICY", Status: "ENABLED" },
          { Type: "S3_POLICY", Status: "ENABLED" },
        ],
      }]}],
      ["organizations list-tags-for-resource --resource-id " + rootId + " --region us-east-1", { Tags: [] }],
      ["organizations list-accounts --region us-east-1", { Accounts: [{
        Id: "111111111111", Name: "management", Email: "management@example.com", State: "ACTIVE",
      }]}],
      ["organizations list-tags-for-resource --resource-id 111111111111 --region us-east-1", { Tags: [] }],
      ["organizations list-organizational-units-for-parent --parent-id " + rootId + " --region us-east-1", { OrganizationalUnits: [] }],
      ["organizations list-aws-service-access-for-organization --region us-east-1", { EnabledServicePrincipals: [] }],
      ["organizations list-delegated-administrators --region us-east-1", { DelegatedAdministrators: [] }],
      ["organizations list-policies --filter SERVICE_CONTROL_POLICY --region us-east-1", { Policies: [{
        Id: "p-FullAWSAccess",
        Arn: "arn:aws:organizations::aws:policy/service_control_policy/p-FullAWSAccess",
        Name: "FullAWSAccess", Type: "SERVICE_CONTROL_POLICY", AwsManaged: true,
      }]}],
      ["organizations list-policies --filter S3_POLICY --region us-east-1", { Policies: [] }],
      ["organizations list-targets-for-policy --policy-id p-FullAWSAccess --region us-east-1", { Targets: [{
        TargetId: rootId, Type: "ROOT",
      }]}],
      ["organizations list-create-account-status --states IN_PROGRESS --region us-east-1", { CreateAccountStatuses: [] }],
      ["organizations list-handshakes-for-organization --filter ActionType=INVITE --region us-east-1", { Handshakes: [] }],
    ]);
    const success = (args) => args.join(" ") === "organizations describe-resource-policy --region us-east-1"
      ? { ok: false, errorCode: "ResourcePolicyNotFoundException" }
      : { ok: true, value: structuredClone(values.get(args.join(" "))) };
    const absent = (args) => {
      assert.equal(args.join(" "), "organizations describe-organization --region us-east-1");
      return { ok: false, errorCode: "AWSOrganizationsNotInUseException" };
    };
    const standalone = attestManagementSeedOrganizationState(
      organization, onboarding, absent, "standalone", binding,
    );
    assert.equal(standalone.organizationPresent, false);
    assert.doesNotThrow(() => verifyManagementSeedOrganizationStateAttestation(
      standalone, { ...binding, managementAccountId: onboarding.managementAccountId },
    ));
    const baselineState = attestManagementSeedOrganizationState(
      organization, onboarding, success, "organization-baseline", binding,
    );
    assert.equal(baselineState.organizationPresent, true);
    assert.equal(baselineState.organizationId, orgId);
    assert.deepEqual(baselineState.rootPolicyTypes, ["S3_POLICY", "SERVICE_CONTROL_POLICY"]);
    assert.deepEqual(baselineState.rootTags, []);
    assert.deepEqual(baselineState.managementAccount.tags, []);
    assert.notEqual(baselineState.attestationDigest, standalone.attestationDigest);

    const hostileCases = [
      ["organizations list-organizational-units-for-parent --parent-id " + rootId + " --region us-east-1", "OrganizationalUnits", [{ Id: "ou-abcd-attacker00" }]],
      ["organizations list-tags-for-resource --resource-id " + rootId + " --region us-east-1", "Tags", [{ Key: "Owner", Value: "attacker" }]],
      ["organizations list-tags-for-resource --resource-id 111111111111 --region us-east-1", "Tags", [{ Key: "Access", Value: "foreign" }]],
      ["organizations list-aws-service-access-for-organization --region us-east-1", "EnabledServicePrincipals", [{ ServicePrincipal: "attacker.amazonaws.com" }]],
      ["organizations list-delegated-administrators --region us-east-1", "DelegatedAdministrators", [{ Id: "222222222222" }]],
      ["organizations list-policies --filter S3_POLICY --region us-east-1", "Policies", [{ Id: "p-attacker000" }]],
      ["organizations list-create-account-status --states IN_PROGRESS --region us-east-1", "CreateAccountStatuses", [{ Id: "car-example" }]],
      ["organizations list-handshakes-for-organization --filter ActionType=INVITE --region us-east-1", "Handshakes", [{ State: "OPEN" }]],
    ];
    for (const [command, key, hostile] of hostileCases) {
      const original = values.get(command)[key];
      values.get(command)[key] = hostile;
      assert.throws(
        () => attestManagementSeedOrganizationState(
          organization, onboarding, success, "organization-baseline", binding,
        ),
      );
      values.get(command)[key] = original;
    }
    assert.throws(
      () => attestManagementSeedOrganizationState(
        organization,
        onboarding,
        () => ({ ok: false, errorCode: "AccessDeniedException" }),
        "standalone",
        binding,
      ),
      /AWSOrganizationsNotInUseException/,
    );
    assert.throws(
      () => attestManagementSeedOrganizationState(
        organization,
        onboarding,
        (args) => args.join(" ") === "organizations describe-resource-policy --region us-east-1"
          ? { ok: true, value: { ResourcePolicy: { Content: "{}" } } }
          : success(args),
        "organization-baseline",
        binding,
      ),
      /must not contain a resource policy/,
    );
  `;
  const result = spawnSync(
    process.execPath,
    ["--input-type=module", "-e", script],
    {
      cwd: process.cwd(),
      encoding: "utf8",
    },
  );
  assert.equal(result.status, 0, result.stderr);
});
