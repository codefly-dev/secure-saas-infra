#!/usr/bin/env node

import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import process from "node:process";
import { format } from "prettier";
import aws from "../dist/adapters/aws/index.js";

const {
  compileAwsBootstrapAccessPlan,
  createReferenceAwsBootstrapAccessPlan,
  parseAwsBootstrapAccessPlan,
} = aws;
const args = parseArgs(process.argv.slice(2));
const plan = args.input
  ? parseAwsBootstrapAccessPlan(
      JSON.parse(readFileSync(resolve(args.input), "utf8")),
    )
  : createReferenceAwsBootstrapAccessPlan();
const document = args.compiled ? compileAwsBootstrapAccessPlan(plan) : plan;
const rendered = await format(JSON.stringify(document), { parser: "json" });

if (args.output) {
  writeFileSync(resolve(args.output), rendered, { mode: 0o600 });
} else {
  process.stdout.write(rendered);
}

function parseArgs(values) {
  const parsed = { compiled: false };
  for (let index = 0; index < values.length; index += 1) {
    const key = values[index];
    if (key === "--compiled") {
      parsed.compiled = true;
      continue;
    }
    if (key === "--output") {
      const value = values[index + 1];
      if (!value || value.startsWith("--")) {
        throw new Error("--output requires a path.");
      }
      parsed.output = value;
      index += 1;
      continue;
    }
    if (key === "--input") {
      const value = values[index + 1];
      if (!value || value.startsWith("--")) {
        throw new Error("--input requires a path.");
      }
      parsed.input = value;
      index += 1;
      continue;
    }
    throw new Error(`Unknown argument '${key ?? ""}'.`);
  }
  return parsed;
}
