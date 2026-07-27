import test from "node:test";
import assert from "node:assert/strict";
import {
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const script = "scripts/validate-contract-schemas.mjs";

test("management-seed schemas compile strictly from the positive inventory", () => {
  const result = runValidator({ SOURCE_DATE_EPOCH: "0" });
  assert.equal(result.status, 0, result.stderr);
  const report = JSON.parse(result.stdout);
  assert.equal(
    report.apiVersion,
    "evidence.security.deus.dev/contract-schema-validation/v1",
  );
  assert.equal(report.generatedAt, "1970-01-01T00:00:00.000Z");
  assert.deepEqual(report.validator, {
    engine: "ajv-2020",
    strict: true,
    allErrors: true,
    formats: true,
  });
  assert.equal(report.validatedContracts.length, 0);
  assert.equal(report.publishedSchemas.length, 18);
  assert.equal(
    report.publishedSchemas.filter(
      (entry: any) => entry.validationMode === "checked-contract",
    ).length,
    0,
  );
  assert.equal(
    report.publishedSchemas.filter(
      (entry: any) => entry.validationMode === "schema-only",
    ).length,
    18,
  );
  assert.ok(
    report.publishedSchemas.every(
      (entry: any) => typeof entry.owner === "string" && entry.owner.length > 0,
    ),
  );
  for (const entry of [
    ...report.publishedSchemas,
    ...report.validatedContracts,
  ]) {
    for (const [key, value] of Object.entries(entry)) {
      if (key.toLowerCase().includes("sha256")) {
        assert.match(String(value), /^[a-f0-9]{64}$/);
      }
    }
  }
});

test("contract schema gate rejects a malformed governed bootstrap schema", () => {
  withContractCopies((directory) => {
    mutateJson(
      path.join(directory.schemas, "bootstrap-candidate-v1.schema.json"),
      (schema: any) => {
        schema.unknownStrictKeyword = true;
      },
    );
    const result = runValidator({}, directory);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /\[VAL_SCHEMA_COMPILE_FAILED\]/);
    assert.match(result.stderr, /unknownStrictKeyword|strict mode/i);
  });
});

test("contract schema gate rejects symlinked schema input", () => {
  withContractCopies((directory) => {
    const target = path.join(
      directory.schemas,
      "bootstrap-candidate-v1.schema.json",
    );
    const backup = `${target}.real`;
    cpSync(target, backup);
    rmSync(target);
    symlinkSync(backup, target);
    const result = runValidator({}, directory);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /\[VAL_INPUT_FILE_UNSAFE\]/);
    assert.match(result.stderr, /non-symlink|real directory|regular/i);
  });
});

test("contract schema gate rejects duplicate CLI flags with a stable code", () => {
  const result = spawnSync(
    process.execPath,
    [script, "--schema-dir", "schemas", "--schema-dir", "schemas"],
    { cwd: process.cwd(), encoding: "utf8" },
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /\[VAL_CLI_DUPLICATE_ARGUMENT\]/);
});

test("contract schema gate never follows an output symlink", () => {
  const root = mkdtempSync(path.join(os.tmpdir(), "deus-contract-output-"));
  const target = path.join(root, "target.json");
  const output = path.join(root, "report.json");
  try {
    writeFileSync(target, "do-not-overwrite\n");
    symlinkSync(target, output);
    const result = spawnSync(process.execPath, [script, "--output", output], {
      cwd: process.cwd(),
      encoding: "utf8",
    });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /\[VAL_OUTPUT_UNSAFE\]/);
    assert.equal(readFileSync(target, "utf8"), "do-not-overwrite\n");
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test("contract schema gate rejects an unowned published schema", () => {
  withContractCopies((directory) => {
    writeFileSync(
      path.join(directory.schemas, "unowned.schema.json"),
      `${JSON.stringify({
        $schema: "https://json-schema.org/draft/2020-12/schema",
        $id: "https://security.deus.dev/schemas/unowned.schema.json",
        type: "object",
        additionalProperties: false,
      })}\n`,
    );
    const result = runValidator({}, directory);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /published schema inventory|unowned/i);
  });
});

test("executed access receipts distinguish mutation from read-only recovery", () => {
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  addFormats(ajv);
  const validate = ajv.compile(
    JSON.parse(
      readFileSync(
        "schemas/management-seed-access-change-set-receipt-v1.schema.json",
        "utf8",
      ),
    ),
  );
  const receipt = {
    apiVersion:
      "security.deus.dev/management-seed-access-change-set-receipt/v1",
    kind: "ManagementSeedAccessChangeSetReceipt",
    stage: "executed",
    generatedAt: "2026-07-21T00:00:00.000Z",
    candidateDigest: "1".repeat(64),
    bundleDigest: "2".repeat(64),
    cloudFormationTemplateFileSha256: "3".repeat(64),
    managementAccountId: "999988887777",
    awsPartition: "aws",
    region: "us-east-1",
    stackName: "deus-management-seed-access",
    callerArn:
      "arn:aws:sts::999988887777:assumed-role/ManagementSeedProvisioner/human",
    cloudControlPlaneMutationPerformed: true,
    iamMutationPerformed: true,
    changeSet: {
      id: `arn:aws:cloudformation:us-east-1:999988887777:changeSet/deus-management-seed-access-${"4".repeat(12)}/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee`,
      name: `deus-management-seed-access-${"4".repeat(12)}`,
      stackId:
        "arn:aws:cloudformation:us-east-1:999988887777:stack/deus-management-seed-access/aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      status: "CREATE_COMPLETE",
      executionStatus: "AVAILABLE",
      changes: [
        {
          action: "Add",
          logicalResourceId: "ApplyRolePolicy",
          resourceType: "AWS::IAM::RolePolicy",
        },
        {
          action: "Add",
          logicalResourceId: "PreviewRolePolicy",
          resourceType: "AWS::IAM::RolePolicy",
        },
      ],
      changesDigest: "5".repeat(64),
    },
    provisionerRetirementRequired: true,
    preparedReceiptDigest: "6".repeat(64),
    execution: {
      stackStatus: "CREATE_COMPLETE",
      attestationDigest: "7".repeat(64),
      provisionerAssignmentRetired: false,
      recoveredAfterPriorExecution: false,
    },
    receiptDigest: "8".repeat(64),
  };
  assert.equal(validate(receipt), true, JSON.stringify(validate.errors));
  const recovered = structuredClone(receipt);
  recovered.cloudControlPlaneMutationPerformed = false;
  recovered.iamMutationPerformed = false;
  recovered.execution.recoveredAfterPriorExecution = true;
  assert.equal(validate(recovered), true, JSON.stringify(validate.errors));
  for (const invalid of [
    {
      ...structuredClone(receipt),
      iamMutationPerformed: false,
    },
    {
      ...structuredClone(recovered),
      cloudControlPlaneMutationPerformed: true,
    },
  ]) {
    assert.equal(validate(invalid), false);
  }
});

test("runtime provenance schemas reject authority and architecture mutations", () => {
  const ajv = new Ajv2020({ strict: true, allErrors: true });
  const closureSchema = JSON.parse(
    readFileSync("schemas/system-runtime-closure-v1.schema.json", "utf8"),
  );
  const provenanceSchema = JSON.parse(
    readFileSync("schemas/bootstrap-runtime-provenance-v1.schema.json", "utf8"),
  );
  ajv.addSchema(closureSchema, closureSchema.$id);
  const validate = ajv.compile(provenanceSchema);
  const closure = {
    apiVersion: "security.deus.dev/system-runtime-closure/v1",
    architecture: "amd64",
    loaders: [
      {
        path: "/lib/ld-linux-x86-64.so.2",
        sha256: "1".repeat(64),
      },
    ],
    libraries: [
      {
        path: "/usr/lib/libc.so.6",
        sha256: "2".repeat(64),
      },
    ],
  };
  const provenance = {
    apiVersion: "security.deus.dev/bootstrap-runtime-provenance/v1",
    platform: "linux",
    architecture: "amd64",
    artifacts: {
      go: {
        file: "go1.26.5.linux-amd64.tar.gz",
        sha256:
          "5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053",
        verification: "authenticated-host-kit-pinned-sha256",
      },
      node: {
        file: "node-v24.18.0-linux-x64.tar.xz",
        sha256:
          "55aa7153f9d88f28d765fcdad5ae6945b5c0f98a36881703817e4c450fa76742",
        verification: "authenticated-host-kit-pinned-sha256",
      },
      pulumi: {
        file: "pulumi-v3.253.0-linux-x64.tar.gz",
        sha256:
          "33161e521280e6c77395a46344dba5ff9c118a90df254801e662087143b4d1ac",
        verification: "authenticated-host-kit-pinned-sha256",
      },
      awsCli: {
        file: "awscli-exe-linux-x86_64-2.36.2.zip",
        sha256: "6".repeat(64),
        verification: "aws-cli-team-pgp",
        signingKeyFingerprint: "FB5DB77FD5C118B80511ADA8A6310ACC4672475C",
      },
    },
    installed: {
      goSha256: "7".repeat(64),
      nodeSha256: "8".repeat(64),
      pulumiTreeDigest: "9".repeat(64),
      awsCliTreeDigest: "a".repeat(64),
    },
    systemRuntime: closure,
  };
  assert.equal(validate(provenance), true, JSON.stringify(validate.errors));

  for (const mutate of [
    (value: any) => {
      value.authority = "ambient-root";
    },
    (value: any) => {
      value.artifacts.go.file = "go1.26.5.linux-arm64.tar.gz";
    },
    (value: any) => {
      value.artifacts.awsCli.signingKeyFingerprint = "A".repeat(40);
    },
    (value: any) => {
      value.systemRuntime.loaders.push(value.systemRuntime.loaders[0]);
    },
    (value: any) => {
      value.systemRuntime.libraries[0].path = "/tmp/attacker.so";
    },
    (value: any) => {
      value.systemRuntime.architecture = "arm64";
    },
  ]) {
    const hostile = structuredClone(provenance);
    mutate(hostile);
    assert.equal(
      validate(hostile),
      false,
      "hostile provenance mutation passed",
    );
  }
});

function runValidator(
  env: Record<string, string> = {},
  directories?: { schemas: string; contracts: string },
) {
  const args = [script];
  if (directories) {
    args.push(
      "--schema-dir",
      directories.schemas,
      "--contract-dir",
      directories.contracts,
    );
  }
  return spawnSync(process.execPath, args, {
    cwd: process.cwd(),
    encoding: "utf8",
    env: { ...process.env, ...env },
  });
}

function withContractCopies(
  fn: (directories: {
    root: string;
    schemas: string;
    contracts: string;
  }) => void,
) {
  const root = mkdtempSync(path.join(os.tmpdir(), "deus-contract-schema-"));
  const schemas = path.join(root, "schemas");
  const contracts = path.join(root, "contracts");
  try {
    mkdirSync(schemas);
    mkdirSync(contracts);
    const scope = JSON.parse(
      readFileSync("security/management-seed-qualification-scope.json", "utf8"),
    );
    for (const entry of scope.contracts.includedSchemaOnly) {
      cpSync(
        path.join("schemas", entry.schema),
        path.join(schemas, entry.schema),
      );
    }
    for (const entry of scope.contracts.includedChecked) {
      cpSync(
        path.join("schemas", entry.schema),
        path.join(schemas, entry.schema),
      );
      cpSync(
        path.join("contracts", entry.contract),
        path.join(contracts, entry.contract),
      );
    }
    for (const entry of scope.contracts.quarantinedChecked) {
      writeFileSync(path.join(schemas, entry.schema), "{}\n");
      writeFileSync(path.join(contracts, entry.contract), "{}\n");
    }
    for (const name of scope.contracts.quarantinedSchemaOnly) {
      writeFileSync(path.join(schemas, name), "{}\n");
    }
    fn({ root, schemas, contracts });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function mutateJson(file: string, mutate: (value: any) => void) {
  const value = JSON.parse(readFileSync(file, "utf8"));
  mutate(value);
  writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}
