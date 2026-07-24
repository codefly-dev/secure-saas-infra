#!/usr/bin/env node

import { writeFileSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import { format } from "prettier";
import core from "../dist/core/index.js";

const { createReferenceInfrastructureControllerRequest } = core;
const args = parseArgs(process.argv.slice(2));
const request = createReferenceInfrastructureControllerRequest(
  args.operation ?? "reconcile",
  args.environmentClass ?? "production",
);
const rendered = await format(JSON.stringify(request), { parser: "json" });

if (args.output) {
  writeFileSync(resolve(args.output), rendered, { mode: 0o600 });
} else {
  process.stdout.write(rendered);
}

function parseArgs(values) {
  const parsed = {};
  const allowed = new Set(["operation", "environment-class", "output"]);
  for (let index = 0; index < values.length; index += 1) {
    const key = values[index];
    const value = values[index + 1];
    if (!key?.startsWith("--") || !value) {
      throw new Error(`Invalid argument '${key ?? ""}'.`);
    }
    const name = key.slice(2);
    if (!allowed.has(name)) throw new Error(`Unknown argument '--${name}'.`);
    parsed[toCamelCase(name)] = value;
    index += 1;
  }
  if (
    parsed.operation &&
    !["plan", "reconcile", "observe", "cancel", "delete"].includes(
      parsed.operation,
    )
  ) {
    throw new Error(`Unsupported operation '${parsed.operation}'.`);
  }
  if (
    parsed.environmentClass &&
    !["nonproduction", "preproduction", "production"].includes(
      parsed.environmentClass,
    )
  ) {
    throw new Error(
      `Unsupported environment class '${parsed.environmentClass}'.`,
    );
  }
  return parsed;
}

function toCamelCase(value) {
  return value.replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
}
