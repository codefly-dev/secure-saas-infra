#!/usr/bin/env node

import { readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  createManagementSeedAccessBundle,
  renderManagementSeedAccessTemplate,
} from "./management-seed-access.mjs";
import { canonicalJson, safeFile, sha256 } from "./management-seed-scope.mjs";

const root = realpathSync(
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."),
);

try {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    printUsage();
    process.exit(0);
  }
  const configPath = safeFile(root, args.config ?? "onboarding.local.json");
  const bundlePath = safeFile(
    root,
    args.bundle ?? "artifacts/management-seed-access-bundle.json",
  );
  const config = parseObject(configPath, "onboarding configuration");
  const actual = parseObject(bundlePath, "management-seed access bundle");
  const expected = createManagementSeedAccessBundle(root, config);
  validateBundle(actual, "access bundle");
  validateBundle(expected, "recomputed access bundle");
  assertExact(actual, expected, "access bundle");

  const templatePath = safeFile(
    root,
    args.template ?? "artifacts/management-seed-access.template.json",
  );
  const actualTemplateSource = readFileSync(templatePath);
  const actualTemplate = parseObjectSource(
    actualTemplateSource,
    "CloudFormation template",
  );
  assertExact(
    actualTemplate,
    expected.cloudFormationTemplate,
    "CloudFormation template",
  );
  if (
    sha256(actualTemplateSource) !==
      expected.cloudFormationTemplateFileSha256 ||
    actualTemplateSource.toString("utf8") !==
      renderManagementSeedAccessTemplate(expected.cloudFormationTemplate)
  ) {
    throw new Error(
      "CloudFormation template bytes do not exactly match the deterministic deployment artifact",
    );
  }

  process.stdout.write(
    `${JSON.stringify(
      {
        apiVersion: "security.deus.dev/management-seed-access-verification/v1",
        valid: true,
        cloudMutationPerformed: false,
        bundle: {
          path: path.relative(root, bundlePath),
          digest: expected.bundleDigest,
        },
        template: {
          path: path.relative(root, templatePath),
          sha256: expected.cloudFormationTemplateFileSha256,
        },
      },
      null,
      2,
    )}\n`,
  );
} catch (error) {
  process.stderr.write(`verify-management-seed-access: ${error.message}\n`);
  process.exitCode = 1;
}

function parseObject(file, label) {
  try {
    return parseObjectSource(readFileSync(file), label);
  } catch (error) {
    throw new Error(`${label} is invalid: ${error.message}`);
  }
}

function parseObjectSource(source, label) {
  try {
    const value = JSON.parse(source.toString("utf8"));
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("must be a JSON object");
    }
    return value;
  } catch (error) {
    throw new Error(`${label} is invalid: ${error.message}`);
  }
}

function validateBundle(bundle, label) {
  const schema = parseObject(
    safeFile(root, "schemas/management-seed-access-bundle-v1.schema.json"),
    "management-seed access schema",
  );
  const ajv = new Ajv2020({
    allErrors: true,
    allowUnionTypes: false,
    strict: true,
    validateFormats: true,
  });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  if (!validate(bundle)) {
    const errors = [...(validate.errors ?? [])]
      .map(
        (entry) =>
          `${entry.instancePath || "/"} ${entry.message ?? "is invalid"}`,
      )
      .sort()
      .join("; ");
    throw new Error(`${label} failed strict schema validation: ${errors}`);
  }
}

function assertExact(actual, expected, label) {
  const actualCanonical = canonicalJson(actual);
  const expectedCanonical = canonicalJson(expected);
  if (actualCanonical !== expectedCanonical) {
    throw new Error(
      `${label} does not exactly match governed source and onboarding configuration (actual ${sha256(actualCanonical)}, expected ${sha256(expectedCanonical)})`,
    );
  }
}

function parseArgs(values) {
  const args = {};
  for (let index = 0; index < values.length; index += 1) {
    const token = values[index];
    if (token === "--help") {
      if (Object.hasOwn(args, "help")) throw new Error("duplicate --help");
      args.help = true;
      continue;
    }
    if (!token.startsWith("--")) {
      throw new Error(`unexpected argument '${token}'`);
    }
    const name = token.slice(2);
    if (!new Set(["config", "bundle", "template"]).has(name)) {
      throw new Error(`unknown argument '${token}'`);
    }
    if (Object.hasOwn(args, name)) {
      throw new Error(`duplicate argument '${token}'`);
    }
    const value = values[index + 1];
    if (!value || value.startsWith("--")) {
      throw new Error(`missing value for '${token}'`);
    }
    args[name] = value;
    index += 1;
  }
  if (args.help && Object.keys(args).length > 1) {
    throw new Error("--help cannot be combined with other arguments");
  }
  return args;
}

function printUsage() {
  process.stdout.write(`Usage:
  npm run bootstrap:verify-access-bundle -- \\
    --config onboarding.local.json \\
    --bundle artifacts/management-seed-access-bundle.json \\
    --template artifacts/management-seed-access.template.json

Recomputes the complete access bundle from governed policies and the selected
onboarding configuration, then requires byte-semantic equality. It makes no
network, AWS, or Pulumi call and performs no cloud mutation.
`);
}
