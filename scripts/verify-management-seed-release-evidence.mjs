import { readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  canonicalJson,
  loadManagementSeedScope,
  managementSeedQualifiedSourceState,
  managementSeedSourceState,
  safeFile,
  sha256,
} from "./management-seed-scope.mjs";
import { validateAdversarialReviewDisposition } from "./review-disposition.mjs";
import { assertManagementSeedSbom } from "./management-seed-sbom.mjs";

const expectedGateCommands = new Map([
  ["g0-clean-install", "npm ci --ignore-scripts"],
  ["g0-static-contracts", "npm run validate:g0"],
  ["g1-unit", "npm run validate:g1"],
  ["g4-dependencies", "npm run security:audit"],
  ["g6-sbom", "npm run sbom -- --output artifacts/secure-saas-infra.spdx.json"],
]);

export function verifyManagementSeedReleaseEvidence(
  root,
  {
    requireClean = true,
    releaseEvidencePath = "artifacts/security-contract-evidence.json",
    localGatePath = "artifacts/local-gate-evidence.json",
    contractValidationPath = "artifacts/contract-schema-validation.json",
    sbomPath = "artifacts/secure-saas-infra.spdx.json",
    qualifiedRevision,
    requireQualified = true,
  } = {},
) {
  const repositoryRoot = realpathSync(path.resolve(root));
  const scope = loadManagementSeedScope(repositoryRoot);
  const releaseFile = governedFile(repositoryRoot, releaseEvidencePath);
  const release = parseJson(releaseFile);
  validate(
    repositoryRoot,
    release,
    "schemas/management-seed-release-evidence-v1.schema.json",
    "management-seed release evidence",
  );

  const source = qualifiedRevision
    ? managementSeedQualifiedSourceState(repositoryRoot, qualifiedRevision)
    : managementSeedSourceState(repositoryRoot, { requireClean });
  const { evidenceDigest, ...releaseSubject } = release;
  if (evidenceDigest !== sha256(canonicalJson(releaseSubject))) {
    throw new Error("Management-seed release evidence digest is invalid.");
  }
  if (
    release.source.revision !== source.revision ||
    release.source.dirty !== source.dirty ||
    canonicalJson(release.buildInputs) !== canonicalJson(source.entries)
  ) {
    throw new Error(
      "Management-seed release evidence does not bind the exact source.",
    );
  }
  const expectedScope = {
    repository: "secure-saas-infra",
    qualificationScope: "aws-organizations-management-seed",
    awsMutationPerformed: false,
    cleanInstallResultsBound: requireQualified,
    staticValidationResultsBound: requireQualified,
    unitTestResultsBound: requireQualified,
    dependencyAuditResultsBound: requireQualified,
    sbomResultsBound: requireQualified,
    adversarialReviewResultsBound: requireQualified,
  };
  if (canonicalJson(release.scope) !== canonicalJson(expectedScope)) {
    throw new Error("Management-seed release scope is not fully qualified.");
  }

  let gates;
  if (requireQualified) {
    const gateFile = governedFile(repositoryRoot, localGatePath);
    gates = parseJson(gateFile);
    verifyLocalGates(
      repositoryRoot,
      gates,
      source,
      qualifiedRevision !== undefined,
    );
    verifyLocalGateBinding(
      repositoryRoot,
      release.validation.localGates,
      gateFile,
      gates,
    );
  } else if (release.validation.localGates !== undefined) {
    throw new Error(
      "Source-release evidence must not claim production local-gate qualification.",
    );
  }

  const contractFile = governedFile(repositoryRoot, contractValidationPath);
  const contracts = parseJson(contractFile);
  verifyContractValidation(repositoryRoot, scope, contracts);
  verifyContractBinding(
    repositoryRoot,
    release.validation.contractSchemas,
    contractFile,
    contracts,
  );

  const sbomFile = governedFile(repositoryRoot, sbomPath);
  const sbom = parseJson(sbomFile);
  verifySbom(repositoryRoot, sbom);
  verifySbomBinding(repositoryRoot, release.validation.sbom, sbomFile, sbom);

  return { release, source, gates, contracts, sbom };
}

function verifyLocalGates(root, report, source, trustImmutableQualifiedSource) {
  validate(
    root,
    report,
    "schemas/local-gate-evidence-v1.schema.json",
    "local gate evidence",
  );
  const { reportDigest, ...gateSubject } = report;
  if (reportDigest !== sha256(canonicalJson(gateSubject))) {
    throw new Error("Local gate evidence digest is invalid.");
  }
  if (
    report.source.revision !== source.revision ||
    report.source.dirty !== false ||
    report.source.treeDigest !== source.treeDigest
  ) {
    throw new Error("Local gate evidence does not bind the exact source.");
  }
  if (
    report.execution.platform !== "linux" ||
    !["x64", "arm64"].includes(report.execution.architecture) ||
    report.execution.productionQualification !== true
  ) {
    throw new Error(
      "Local gate evidence was not produced by the sealed Linux production qualifier.",
    );
  }
  exact(
    report.gates.map((entry) => entry.id).sort(),
    [...expectedGateCommands.keys()].sort(),
    "local gate inventory",
  );
  for (const gate of report.gates) {
    if (expectedGateCommands.get(gate.id) !== gate.command) {
      throw new Error(`Local gate command changed for '${gate.id}'.`);
    }
  }
  if (
    report.adversarialReview.path !==
    "security/adversarial-review-disposition.json"
  ) {
    throw new Error("Local gates reference an unexpected adversarial review.");
  }
  const reviewFile = governedFile(root, report.adversarialReview.path);
  if (hashFile(reviewFile) !== report.adversarialReview.sha256) {
    throw new Error("Adversarial review digest does not match.");
  }
  validateAdversarialReviewDisposition(root, {
    trustImmutableQualifiedSource,
  });
}

function verifyLocalGateBinding(root, binding, file, report) {
  if (
    binding.path !== relative(root, file) ||
    binding.sha256 !== hashFile(file) ||
    binding.apiVersion !== report.apiVersion ||
    binding.reportDigest !== report.reportDigest ||
    binding.gateCount !== expectedGateCommands.size ||
    binding.sourceTreeDigest !== report.source.treeDigest ||
    binding.adversarialReviewSha256 !== report.adversarialReview.sha256
  ) {
    throw new Error(
      "Release evidence does not bind the exact local gate artifact.",
    );
  }
}

function verifyContractValidation(root, scope, report) {
  validate(
    root,
    report,
    "schemas/contract-schema-validation-v1.schema.json",
    "contract-schema evidence",
  );
  exact(
    report.publishedSchemas.map((entry) => entry.path).sort(),
    scope.contracts.includedSchemaOnly.map((entry) => entry.schema).sort(),
    "governed schema evidence",
  );
  exact(
    report.validatedContracts.map((entry) => entry.contract).sort(),
    scope.contracts.includedChecked.map((entry) => entry.contract).sort(),
    "governed contract evidence",
  );
  for (const entry of report.publishedSchemas) {
    if (
      hashFile(governedFile(root, `schemas/${entry.path}`)) !== entry.sha256
    ) {
      throw new Error(`Governed schema digest changed for '${entry.path}'.`);
    }
  }
  for (const entry of report.validatedContracts) {
    if (
      hashFile(governedFile(root, `contracts/${entry.contract}`)) !==
      entry.contractSha256
    ) {
      throw new Error(
        `Governed contract digest changed for '${entry.contract}'.`,
      );
    }
  }
}

function verifyContractBinding(root, binding, file, report) {
  const published = report.publishedSchemas.map((entry) => ({
    path: entry.path,
    sha256: entry.sha256,
  }));
  const checked = report.validatedContracts.map((entry) => ({
    path: entry.contract,
    sha256: entry.contractSha256,
  }));
  if (
    binding.path !== relative(root, file) ||
    binding.sha256 !== hashFile(file) ||
    binding.apiVersion !== report.apiVersion ||
    binding.publishedSchemaAggregateSha256 !== aggregate(published) ||
    binding.validatedContractAggregateSha256 !== aggregate(checked)
  ) {
    throw new Error(
      "Release evidence does not bind the exact contract-validation artifact.",
    );
  }
}

function verifySbom(root, sbom) {
  const lock = parseJson(governedFile(root, "package-lock.json"));
  assertManagementSeedSbom(lock, sbom);
}

export function verifyEmbeddedLocalGateEvidence(root, report, source) {
  verifyLocalGates(realpathSync(path.resolve(root)), report, source, false);
}

export function verifyEmbeddedContractValidation(root, report) {
  const repositoryRoot = realpathSync(path.resolve(root));
  verifyContractValidation(
    repositoryRoot,
    loadManagementSeedScope(repositoryRoot),
    report,
  );
}

export function verifyEmbeddedSbom(root, sbom) {
  verifySbom(realpathSync(path.resolve(root)), sbom);
}

function verifySbomBinding(root, binding, file, sbom) {
  if (
    binding.path !== relative(root, file) ||
    binding.sha256 !== hashFile(file) ||
    binding.spdxVersion !== sbom.spdxVersion ||
    binding.packageCount !== sbom.packages.length
  ) {
    throw new Error("Release evidence does not bind the exact SBOM artifact.");
  }
}

function validate(root, value, schemaPath, label) {
  const ajv = new Ajv2020({
    allErrors: true,
    allowUnionTypes: false,
    strict: true,
    validateFormats: true,
  });
  addFormats(ajv);
  const schema = parseJson(governedFile(root, schemaPath));
  const validator = ajv.compile(schema);
  if (!validator(value)) {
    throw new Error(
      `${label} failed schema validation: ${ajv.errorsText(validator.errors, { separator: "; " })}`,
    );
  }
}

function governedFile(root, value) {
  const relativeValue = path.isAbsolute(value)
    ? path.relative(root, value)
    : value;
  return safeFile(root, relativeValue);
}

function parseJson(file) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    throw new Error(`${file} is invalid JSON: ${error.message}`);
  }
}

function hashFile(file) {
  return sha256(readFileSync(file));
}

function relative(root, file) {
  return path.relative(root, file).split(path.sep).join("/");
}

function aggregate(entries) {
  return sha256(
    canonicalJson(
      [...entries].sort((left, right) => left.path.localeCompare(right.path)),
    ),
  );
}

function exact(actual, expected, label) {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`${label} does not match the positive inventory.`);
  }
}
