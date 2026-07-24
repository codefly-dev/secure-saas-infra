#!/usr/bin/env node

import { readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { validateAdversarialReviewDisposition } from "./review-disposition.mjs";
import { assertManagementSeedSbom } from "./management-seed-sbom.mjs";
import {
  canonicalJson,
  loadManagementSeedScope,
  managementSeedSourceState,
  safeFile as safeScopeFile,
  sha256,
  writeAtomicArtifact,
} from "./management-seed-scope.mjs";

const root = realpathSync(
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."),
);
const args = parseArgs(process.argv.slice(2));
const scope = loadManagementSeedScope(root);
const validationReportPath = safeFile(
  args["validation-report"] ?? "artifacts/contract-schema-validation.json",
  "contract-schema validation report",
);
const sbomPath = safeFile(
  args.sbom ?? "artifacts/secure-saas-infra.spdx.json",
  "SPDX SBOM",
);
const gatePath = args["gate-report"]
  ? safeFile(args["gate-report"], "local gate evidence")
  : undefined;
const source = managementSeedSourceState(root, {
  requireClean: Boolean(args["require-clean"]),
});
const contractValidation = parseJson(validationReportPath);
verifyContractValidation(contractValidation);
const sbom = parseJson(sbomPath);
verifySbom(sbom);
const localGates = gatePath
  ? verifyLocalGates(parseJson(gatePath), gatePath)
  : undefined;

const subject = {
  apiVersion: "evidence.security.deus.dev/management-seed-release/v1",
  generatedAt: generatedAt(),
  scope: {
    repository: "secure-saas-infra",
    qualificationScope: "aws-organizations-management-seed",
    awsMutationPerformed: false,
    cleanInstallResultsBound: Boolean(localGates),
    staticValidationResultsBound: Boolean(localGates),
    unitTestResultsBound: Boolean(localGates),
    dependencyAuditResultsBound: Boolean(localGates),
    sbomResultsBound: Boolean(localGates),
    adversarialReviewResultsBound: Boolean(localGates),
  },
  source: { revision: source.revision, dirty: source.dirty },
  buildInputs: source.entries,
  validation: {
    contractSchemas: {
      path: relative(validationReportPath),
      sha256: hashFile(validationReportPath),
      apiVersion: contractValidation.apiVersion,
      publishedSchemaAggregateSha256: aggregate(
        contractValidation.publishedSchemas.map((entry) => ({
          path: entry.path,
          sha256: entry.sha256,
        })),
      ),
      validatedContractAggregateSha256: aggregate(
        contractValidation.validatedContracts.map((entry) => ({
          path: entry.contract,
          sha256: entry.contractSha256,
        })),
      ),
    },
    sbom: {
      path: relative(sbomPath),
      sha256: hashFile(sbomPath),
      spdxVersion: sbom.spdxVersion,
      packageCount: sbom.packages.length,
    },
    ...(localGates
      ? {
          localGates: {
            path: relative(gatePath),
            sha256: hashFile(gatePath),
            apiVersion: localGates.apiVersion,
            reportDigest: localGates.reportDigest,
            gateCount: localGates.gates.length,
            sourceTreeDigest: localGates.source.treeDigest,
            adversarialReviewSha256: localGates.adversarialReview.sha256,
          },
        }
      : {}),
  },
};
const evidence = { ...subject, evidenceDigest: sha256(canonicalJson(subject)) };
validate(
  evidence,
  safeFile(
    "schemas/management-seed-release-evidence-v1.schema.json",
    "release evidence schema",
  ),
  "release evidence",
);
const rendered = `${JSON.stringify(evidence, null, 2)}\n`;
if (args.output) writeAtomicArtifact(root, args.output, rendered);
else process.stdout.write(rendered);

function verifyContractValidation(report) {
  validate(
    report,
    safeFile(
      "schemas/contract-schema-validation-v1.schema.json",
      "contract evidence schema",
    ),
    "contract-schema evidence",
  );
  const expectedSchemas = scope.contracts.includedSchemaOnly
    .map((entry) => entry.schema)
    .sort();
  const expectedContracts = scope.contracts.includedChecked
    .map((entry) => entry.contract)
    .sort();
  exact(
    report.publishedSchemas.map((entry) => entry.path).sort(),
    expectedSchemas,
    "governed schema evidence",
  );
  exact(
    report.validatedContracts.map((entry) => entry.contract).sort(),
    expectedContracts,
    "governed contract evidence",
  );
  for (const entry of report.publishedSchemas) {
    if (
      hashFile(safeFile(`schemas/${entry.path}`, "governed schema")) !==
      entry.sha256
    ) {
      fail(`governed schema digest does not match '${entry.path}'`);
    }
  }
  for (const entry of report.validatedContracts) {
    if (
      hashFile(safeFile(`contracts/${entry.contract}`, "governed contract")) !==
      entry.contractSha256
    ) {
      fail(`governed contract digest does not match '${entry.contract}'`);
    }
  }
}

function verifySbom(sbom) {
  const lock = parseJson(safeFile("package-lock.json", "npm lockfile"));
  try {
    assertManagementSeedSbom(lock, sbom);
  } catch (error) {
    fail(error.message);
  }
}

function verifyLocalGates(report, file) {
  validate(
    report,
    safeFile("schemas/local-gate-evidence-v1.schema.json", "local gate schema"),
    "local gate evidence",
  );
  const { reportDigest, ...gateSubject } = report;
  if (reportDigest !== sha256(canonicalJson(gateSubject)))
    fail("local gate evidence digest does not match");
  if (
    report.source.revision !== source.revision ||
    report.source.dirty !== source.dirty ||
    report.source.treeDigest !== source.treeDigest
  ) {
    fail("local gate evidence source does not match management-seed scope");
  }
  if (
    report.execution.platform !== "linux" ||
    !["x64", "arm64"].includes(report.execution.architecture) ||
    report.execution.productionQualification !== true
  ) {
    fail(
      "local gate evidence was not produced by the sealed Linux production qualifier",
    );
  }
  const commands = new Map([
    ["g0-clean-install", "npm ci --ignore-scripts"],
    ["g0-static-contracts", "npm run validate:g0"],
    ["g1-unit", "npm run validate:g1"],
    ["g4-dependencies", "npm run security:audit"],
    [
      "g6-sbom",
      "npm run sbom -- --output artifacts/secure-saas-infra.spdx.json",
    ],
  ]);
  exact(
    report.gates.map((entry) => entry.id).sort(),
    [...commands.keys()].sort(),
    "local gate inventory",
  );
  for (const gate of report.gates)
    if (commands.get(gate.id) !== gate.command)
      fail(`local gate command changed for '${gate.id}'`);
  const review = safeFile(
    report.adversarialReview.path,
    "adversarial review disposition",
  );
  if (hashFile(review) !== report.adversarialReview.sha256)
    fail("adversarial review digest does not match");
  validateAdversarialReviewDisposition(root);
  return report;
}

function validate(value, schemaFile, label) {
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const schema = parseJson(schemaFile);
  const validator = ajv.compile(schema);
  if (!validator(value))
    fail(
      `${label} failed schema validation: ${JSON.stringify(validator.errors)}`,
    );
}

function parseArgs(values) {
  const result = {};
  const flags = new Set(["require-clean"]);
  const valued = new Set([
    "validation-report",
    "sbom",
    "gate-report",
    "output",
  ]);
  for (let index = 0; index < values.length; index += 1) {
    const token = values[index];
    if (!token.startsWith("--")) fail(`unexpected argument '${token}'`);
    const name = token.slice(2);
    if (flags.has(name)) {
      result[name] = true;
      continue;
    }
    if (
      !valued.has(name) ||
      !values[index + 1] ||
      values[index + 1].startsWith("--")
    )
      fail(`invalid argument '${token}'`);
    result[name] = values[++index];
  }
  return result;
}

function safeFile(value, label) {
  try {
    const relativeValue = path.isAbsolute(value)
      ? path.relative(root, value)
      : value;
    return safeScopeFile(root, relativeValue);
  } catch (error) {
    fail(`${label} is unsafe: ${error.message}`);
  }
}

function parseJson(file) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    fail(`${file} is invalid JSON: ${error.message}`);
  }
}

function hashFile(file) {
  return sha256(readFileSync(file));
}
function relative(file) {
  return path.relative(root, file).split(path.sep).join("/");
}
function aggregate(entries) {
  return sha256(
    canonicalJson([...entries].sort((a, b) => a.path.localeCompare(b.path))),
  );
}
function exact(actual, expected, label) {
  if (JSON.stringify(actual) !== JSON.stringify(expected))
    fail(`${label} does not match the positive inventory`);
}
function generatedAt() {
  if (process.env.SOURCE_DATE_EPOCH === undefined)
    return new Date().toISOString();
  const epoch = Number(process.env.SOURCE_DATE_EPOCH);
  if (!Number.isInteger(epoch) || epoch < 0)
    fail("SOURCE_DATE_EPOCH must be a non-negative integer");
  return new Date(epoch * 1000).toISOString();
}
function fail(message) {
  process.stderr.write(`generate-release-evidence: ${message}.\n`);
  process.exit(1);
}
