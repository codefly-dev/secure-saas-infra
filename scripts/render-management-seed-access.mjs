#!/usr/bin/env node

import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  createManagementSeedAccessBundle,
  renderManagementSeedAccessTemplate,
} from "./management-seed-access.mjs";
import { safeFile } from "./management-seed-scope.mjs";

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
  const onboarding = parseJson(configPath, "onboarding configuration");
  const bundle = createManagementSeedAccessBundle(root, onboarding);
  validateBundle(bundle);
  const output = args.output ? safeOutput(args.output) : null;
  const templateOutput = args["template-output"]
    ? safeOutput(args["template-output"])
    : null;
  if (output !== null && output === templateOutput) {
    throw new Error("--output and --template-output must be different files");
  }
  if (output === configPath || templateOutput === configPath) {
    throw new Error("outputs must not overwrite the onboarding configuration");
  }
  const rendered = `${JSON.stringify(bundle, null, 2)}\n`;
  if (output) {
    writeAtomic(output, rendered);
  } else {
    process.stdout.write(rendered);
  }
  if (templateOutput) {
    writeAtomic(
      templateOutput,
      renderManagementSeedAccessTemplate(bundle.cloudFormationTemplate),
    );
  }
} catch (error) {
  process.stderr.write(`render-management-seed-access: ${error.message}\n`);
  process.exitCode = 1;
}

function validateBundle(bundle) {
  const schemaPath = safeFile(
    root,
    "schemas/management-seed-access-bundle-v1.schema.json",
  );
  const schema = parseJson(schemaPath, "management-seed access schema");
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
    throw new Error(`generated access bundle failed strict schema: ${errors}`);
  }
}

function parseJson(file, label) {
  try {
    const value = JSON.parse(readFileSync(file, "utf8"));
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("must be a JSON object");
    }
    return value;
  } catch (error) {
    throw new Error(`${label} is invalid: ${error.message}`);
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
    if (!new Set(["config", "output", "template-output"]).has(name)) {
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

function safeOutput(value) {
  const output = path.resolve(root, value);
  const artifactRoot = path.join(root, "artifacts");
  if (!output.startsWith(`${artifactRoot}${path.sep}`)) {
    throw new Error(
      "output must remain under the repository artifacts directory",
    );
  }
  const parent = path.dirname(output);
  const relativeParent = path.relative(root, parent);
  let current = root;
  for (const segment of relativeParent.split(path.sep).filter(Boolean)) {
    current = path.join(current, segment);
    if (!existsSync(current)) {
      mkdirSync(current, { mode: 0o700 });
    }
    const stat = lstatSync(current);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      realpathSync(current) !== current
    ) {
      throw new Error("output directory must not traverse symbolic links");
    }
  }
  if (existsSync(output)) {
    const stat = lstatSync(output);
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error("output must be a regular non-symlink file");
    }
  }
  return output;
}

function writeAtomic(output, value) {
  const temporary = `${output}.tmp-${process.pid}`;
  try {
    writeFileSync(temporary, value, { mode: 0o600, flag: "wx" });
    renameSync(temporary, output);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function printUsage() {
  process.stdout.write(`Usage:
  npm run bootstrap:access-bundle -- --config onboarding.local.json \\
    --output artifacts/management-seed-access-bundle.json \\
    --template-output artifacts/management-seed-access.template.json

Renders and strictly validates an inert CloudFormation access bundle. This
command is deterministic, uses no credentials, makes no network calls, and
performs no AWS or Pulumi mutation.
`);
}
