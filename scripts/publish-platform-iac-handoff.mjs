#!/usr/bin/env node

import { lstatSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { createPlatformHandoff, regularFile } from "./platform-handoff.mjs";

const args = parseArguments(process.argv.slice(2));
const stackOutputsPath = regularFile(args.stackOutputs, "stack outputs");
const privateKeyPath = regularFile(args.privateKey, "private key");
const output = path.resolve(args.output);
assertNewOutput(output);
const stackOutputs = JSON.parse(readFileSync(stackOutputsPath, "utf8"));
const handoff = createPlatformHandoff(
  stackOutputs,
  readFileSync(privateKeyPath),
);
writeFileSync(output, `${JSON.stringify(handoff, null, 2)}\n`, {
  flag: "wx",
  mode: 0o600,
});
process.stdout.write(
  `Published signed ${handoff.spec.cluster.role} handoff for ${handoff.spec.cluster.name} at ${handoff.specDigest}.\n`,
);

function assertNewOutput(output) {
  try {
    lstatSync(output);
    throw new Error("handoff output already exists.");
  } catch (error) {
    if (error.code !== "ENOENT") throw error;
  }
}

function parseArguments(values) {
  const parsed = {};
  const names = new Map([
    ["--stack-outputs", "stackOutputs"],
    ["--private-key", "privateKey"],
    ["--output", "output"],
  ]);
  for (let index = 0; index < values.length; index += 2) {
    const key = names.get(values[index]);
    const value = values[index + 1];
    if (!key || !value || parsed[key]) usage();
    parsed[key] = value;
  }
  if (Object.keys(parsed).length !== names.size) usage();
  return parsed;
}

function usage() {
  process.stderr.write(
    "Usage: node scripts/publish-platform-iac-handoff.mjs --stack-outputs <pulumi-stack-output-json> --private-key <ecdsa-p256-private-key> --output <handoff-json>\n",
  );
  process.exit(2);
}
