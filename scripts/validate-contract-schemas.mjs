#!/usr/bin/env node

import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  realpathSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { loadManagementSeedScope } from "./management-seed-scope.mjs";

const repositoryRoot = fileURLToPath(new URL("..", import.meta.url));
const scope = loadManagementSeedScope(repositoryRoot);
const CONTRACT_SCHEMA_PAIRS = Object.freeze(scope.contracts.includedChecked);
const SCHEMA_ONLY_FILES = Object.freeze(scope.contracts.includedSchemaOnly);
const CLASSIFIED_CONTRACTS = Object.freeze([
  ...scope.contracts.includedChecked,
  ...scope.contracts.quarantinedChecked,
]);
const CLASSIFIED_SCHEMAS = Object.freeze([
  ...CLASSIFIED_CONTRACTS.map((entry) => entry.schema),
  ...scope.contracts.includedSchemaOnly.map((entry) => entry.schema),
  ...scope.contracts.quarantinedSchemaOnly,
]);

export function validateContractSchemas(options = {}) {
  const schemaDirectory = safeDirectory(
    options.schemaDirectory ?? path.resolve("schemas"),
    "schema directory",
  );
  const contractDirectory = safeDirectory(
    options.contractDirectory ?? path.resolve("contracts"),
    "contract directory",
  );
  const schemaFiles = readdirSync(schemaDirectory)
    .filter((name) => name.endsWith(".schema.json"))
    .sort();
  if (schemaFiles.length === 0) {
    fail(
      "VAL_SCHEMA_INVENTORY_EMPTY",
      `No published JSON schemas found in ${schemaDirectory}.`,
    );
  }
  assertExactNames(
    schemaFiles,
    CLASSIFIED_SCHEMAS,
    "classified schema inventory",
  );
  const contractFiles = readdirSync(contractDirectory)
    .filter((name) => name.endsWith(".json"))
    .sort();
  assertExactNames(
    contractFiles,
    CLASSIFIED_CONTRACTS.map((pair) => pair.contract),
    "classified contract inventory",
  );
  const schemaOwners = new Map([
    ...CONTRACT_SCHEMA_PAIRS.map((pair) => [
      pair.schema,
      { owner: pair.owner, validationMode: "checked-contract" },
    ]),
    ...SCHEMA_ONLY_FILES.map((entry) => [
      entry.schema,
      { owner: entry.owner, validationMode: "schema-only" },
    ]),
  ]);

  const ajv = new Ajv2020({
    allErrors: true,
    allowUnionTypes: false,
    strict: true,
    validateFormats: true,
  });
  addFormats(ajv);

  const schemas = new Map();
  const governedSchemaFiles = [
    ...new Set(CONTRACT_SCHEMA_PAIRS.map((pair) => pair.schema)),
    ...SCHEMA_ONLY_FILES.map((entry) => entry.schema),
  ].sort();
  for (const name of governedSchemaFiles) {
    const file = safeRegularFile(schemaDirectory, name, "schema");
    const source = readFileSync(file, "utf8");
    const schema = parseJson(source, file);
    if (typeof schema.$id !== "string" || !schema.$id.startsWith("https://")) {
      fail("VAL_SCHEMA_ID_INVALID", `${name} must declare an HTTPS $id.`);
    }
    if (schemas.has(schema.$id)) {
      fail(
        "VAL_SCHEMA_ID_DUPLICATE",
        `${name} duplicates schema $id '${schema.$id}' already declared by ${schemas.get(schema.$id).name}.`,
      );
    }
    schemas.set(schema.$id, {
      name,
      file,
      schema,
      sha256: sha256(source),
    });
    try {
      ajv.addSchema(schema, schema.$id);
    } catch (error) {
      fail(
        "VAL_SCHEMA_COMPILE_FAILED",
        `${name} could not be registered: ${error.message}`,
      );
    }
  }

  // Force compilation of every published schema, including schemas that do not
  // yet have a checked example contract. This catches unresolved references,
  // invalid formats, and strict-mode schema errors before a consumer sees them.
  for (const entry of schemas.values()) {
    let validator;
    try {
      validator = ajv.getSchema(entry.schema.$id);
    } catch (error) {
      fail(
        "VAL_SCHEMA_COMPILE_FAILED",
        `${entry.name} could not be compiled: ${error.message}`,
      );
    }
    if (!validator) {
      fail(
        "VAL_SCHEMA_COMPILE_FAILED",
        `${entry.name} was registered but could not be compiled.`,
      );
    }
  }

  const validatedContracts = [];
  for (const pair of CONTRACT_SCHEMA_PAIRS) {
    const schemaFile = safeRegularFile(
      schemaDirectory,
      pair.schema,
      "mapped schema",
    );
    const schema = parseJson(readFileSync(schemaFile, "utf8"), schemaFile);
    const validator = ajv.getSchema(schema.$id);
    if (!validator) {
      fail(
        "VAL_SCHEMA_MAPPING_INVALID",
        `Mapped schema ${pair.schema} was not registered under '${schema.$id}'.`,
      );
    }
    const contractFile = safeRegularFile(
      contractDirectory,
      pair.contract,
      "contract",
    );
    const source = readFileSync(contractFile, "utf8");
    const contract = parseJson(source, contractFile);
    if (!validator(contract)) {
      fail(
        "VAL_CONTRACT_SCHEMA_REJECTED",
        `${pair.contract} does not satisfy ${pair.schema}:\n${formatErrors(validator.errors)}`,
      );
    }
    const declaredVersion = contract?.apiVersion;
    const schemaVersion = schema?.properties?.apiVersion?.const;
    if (
      typeof declaredVersion === "string" &&
      typeof schemaVersion === "string" &&
      declaredVersion !== schemaVersion
    ) {
      fail(
        "VAL_VERSION_MISMATCH",
        `${pair.contract} apiVersion '${declaredVersion}' does not match ${pair.schema} const '${schemaVersion}'.`,
      );
    }
    validatedContracts.push({
      contract: pair.contract,
      contractSha256: sha256(source),
      schema: pair.schema,
      schemaId: schema.$id,
      schemaSha256: schemas.get(schema.$id).sha256,
      apiVersion: typeof declaredVersion === "string" ? declaredVersion : null,
      owner: pair.owner,
    });
  }

  const report = {
    apiVersion: "evidence.security.deus.dev/contract-schema-validation/v1",
    generatedAt: generatedAt(),
    validator: {
      engine: "ajv-2020",
      strict: true,
      allErrors: true,
      formats: true,
    },
    publishedSchemas: [...schemas.values()]
      .map((entry) => ({
        path: entry.name,
        schemaId: entry.schema.$id,
        sha256: entry.sha256,
        ...schemaOwners.get(entry.name),
      }))
      .sort((left, right) => left.path.localeCompare(right.path)),
    validatedContracts,
  };
  const evidenceSchema = [...schemas.values()].find(
    (entry) => entry.name === "contract-schema-validation-v1.schema.json",
  );
  const evidenceValidator = evidenceSchema
    ? ajv.getSchema(evidenceSchema.schema.$id)
    : undefined;
  if (!evidenceValidator || !evidenceValidator(report)) {
    fail(
      "VAL_EVIDENCE_SCHEMA_REJECTED",
      `generated validation evidence does not satisfy its published schema:\n${formatErrors(evidenceValidator?.errors)}`,
    );
  }
  return report;
}

function parseJson(source, file) {
  try {
    return JSON.parse(source);
  } catch (error) {
    fail("VAL_JSON_INVALID", `${file} is not valid JSON: ${error.message}`);
  }
}

function safeDirectory(directory, label) {
  const absolute = path.resolve(directory);
  let stat;
  try {
    stat = lstatSync(absolute);
  } catch (error) {
    fail(
      "VAL_INPUT_DIRECTORY_UNSAFE",
      `${label} is unavailable: ${error.message}`,
    );
  }
  if (!stat.isDirectory() || stat.isSymbolicLink()) {
    fail(
      "VAL_INPUT_DIRECTORY_UNSAFE",
      `${label} must be a real directory: ${absolute}.`,
    );
  }
  return realpathSync(absolute);
}

function safeRegularFile(directory, name, label) {
  if (path.basename(name) !== name) {
    fail(
      "VAL_INPUT_FILE_UNSAFE",
      `${label} name must not contain a path: ${name}.`,
    );
  }
  const file = path.join(directory, name);
  let stat;
  try {
    stat = lstatSync(file);
  } catch (error) {
    fail("VAL_INPUT_FILE_UNSAFE", `${label} is unavailable: ${error.message}`);
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail(
      "VAL_INPUT_FILE_UNSAFE",
      `${label} must be a regular non-symlink file: ${file}.`,
    );
  }
  const resolved = realpathSync(file);
  if (path.dirname(resolved) !== directory) {
    fail("VAL_INPUT_FILE_UNSAFE", `${label} escapes its directory: ${file}.`);
  }
  return resolved;
}

function formatErrors(errors = []) {
  return [...errors]
    .map((error) => {
      const location = error.instancePath || "/";
      return `- ${location} ${error.message ?? "is invalid"} (${error.schemaPath})`;
    })
    .sort()
    .join("\n");
}

function assertExactNames(actual, expected, label) {
  const sortedActual = [...actual].sort();
  const sortedExpected = [...expected].sort();
  if (
    new Set(sortedActual).size !== sortedActual.length ||
    new Set(sortedExpected).size !== sortedExpected.length ||
    JSON.stringify(sortedActual) !== JSON.stringify(sortedExpected)
  ) {
    const unexpected = sortedActual.filter(
      (name) => !sortedExpected.includes(name),
    );
    const missing = sortedExpected.filter(
      (name) => !sortedActual.includes(name),
    );
    fail(
      "VAL_INVENTORY_MISMATCH",
      `${label} is not explicit (unexpected: ${unexpected.join(", ") || "none"}; missing: ${missing.join(", ") || "none"}).`,
    );
  }
}

function generatedAt() {
  if (process.env.SOURCE_DATE_EPOCH !== undefined) {
    const epoch = Number(process.env.SOURCE_DATE_EPOCH);
    if (!Number.isInteger(epoch) || epoch < 0) {
      fail(
        "VAL_SOURCE_DATE_EPOCH_INVALID",
        "SOURCE_DATE_EPOCH must be a non-negative integer.",
      );
    }
    return new Date(epoch * 1000).toISOString();
  }
  return new Date().toISOString();
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function parseArgs(values) {
  const args = {};
  for (let index = 0; index < values.length; index += 1) {
    const token = values[index];
    if (!token.startsWith("--")) {
      fail("VAL_CLI_UNEXPECTED_ARGUMENT", `Unexpected argument '${token}'.`);
    }
    const value = values[index + 1];
    if (!value || value.startsWith("--")) {
      fail("VAL_CLI_MISSING_VALUE", `Missing value for '${token}'.`);
    }
    const name = token.slice(2);
    if (!["schema-dir", "contract-dir", "output"].includes(name)) {
      fail("VAL_CLI_UNKNOWN_ARGUMENT", `Unknown argument '${token}'.`);
    }
    if (Object.hasOwn(args, name)) {
      fail("VAL_CLI_DUPLICATE_ARGUMENT", `Duplicate argument '${token}'.`);
    }
    args[name] = value;
    index += 1;
  }
  return args;
}

function main() {
  try {
    const args = parseArgs(process.argv.slice(2));
    const report = validateContractSchemas({
      schemaDirectory: args["schema-dir"],
      contractDirectory: args["contract-dir"],
    });
    const rendered = `${JSON.stringify(report, null, 2)}\n`;
    if (args.output) {
      const output = safeOutputFile(args.output);
      writeFileSync(output, rendered, { mode: 0o600 });
    } else {
      process.stdout.write(rendered);
    }
  } catch (error) {
    const code =
      error instanceof ValidationError ? error.code : "VAL_INTERNAL_ERROR";
    process.stderr.write(
      `validate-contract-schemas[${code}]: ${error.message}\n`,
    );
    process.exitCode = 1;
  }
}

class ValidationError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

function fail(code, message) {
  throw new ValidationError(code, message);
}

function safeOutputFile(value) {
  const output = path.resolve(value);
  const parent = path.dirname(output);
  mkdirSync(parent, { recursive: true, mode: 0o700 });
  const realParent = realpathSync(parent);
  if (realParent !== parent) {
    fail(
      "VAL_OUTPUT_UNSAFE",
      `output directory must not traverse symbolic links: ${parent}.`,
    );
  }
  if (existsSync(output)) {
    const stat = lstatSync(output);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      fail(
        "VAL_OUTPUT_UNSAFE",
        `output must be a regular non-symlink file: ${output}.`,
      );
    }
  }
  return output;
}

if (
  process.argv[1] &&
  realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  main();
}
