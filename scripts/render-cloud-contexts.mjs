#!/usr/bin/env node

import {
  existsSync,
  lstatSync,
  readFileSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";
import { format } from "prettier";
import core from "../dist/core/index.js";
import aws from "../dist/adapters/aws/index.js";

const { createWardenMindBlueprint, parseManagedPostgresIntent } = core;
const { compileAwsCloudContextCatalog } = aws;
const args = parseArgs(process.argv.slice(2));
const blueprint = createWardenMindBlueprint({
  networkCidrs: {
    "egress-net": "10.0.0.0/16",
    "control-net": "10.10.0.0/16",
    "execution-shared-net": "10.20.0.0/16",
    "data-shared-net": "10.30.0.0/16",
  },
});
const managedPostgres = parseManagedPostgresIntent(
  JSON.parse(
    readFileSync(
      path.resolve("contracts/managed-postgres-v1alpha2.json"),
      "utf8",
    ),
  ),
  args.environment,
  blueprint,
);
const suffix = environmentSuffix(args.environment);
const platformStackRef = `${args.pulumiOrganization}/secure-saas-infra/platform-${suffix}`;
const executionStackRef = `${args.pulumiOrganization}/secure-saas-infra/execution-${suffix}`;
const catalog = compileAwsCloudContextCatalog(blueprint, managedPostgres, {
  partition: args.partition,
  platformAccountId: args.platformAccountId,
  executionAccountId: args.executionAccountId,
  region: args.region,
  applicationContextId: `aws-platform-${args.environment}`,
  executionContextId: `aws-execution-${args.environment}`,
  platformStackRef,
  executionStackRef,
  registryRef: `provider-reference://${args.partition}/ecr/${args.region}/${args.platformAccountId}/platform`,
  publicDnsRef: `stack-output://${platformStackRef}/publicDnsZoneId`,
  privateDnsRef: `stack-output://${platformStackRef}/privateDnsZoneId`,
  platformIdentityRef: `stack-output://${platformStackRef}/workloadIdentityBindings`,
  executionIdentityRef: `stack-output://${executionStackRef}/workloadIdentityBindings`,
  auditRef: `stack-output://${platformStackRef}/auditEvidence`,
  logsRef: `stack-output://${platformStackRef}/logsEndpoint`,
  metricsRef: `stack-output://${platformStackRef}/metricsEndpoint`,
  tracesRef: `stack-output://${platformStackRef}/tracesEndpoint`,
});
const rendered = await format(JSON.stringify(catalog), { parser: "json" });

if (args.output) {
  writeAtomic(args.output, rendered);
} else {
  process.stdout.write(rendered);
}

function parseArgs(values) {
  const parsed = { partition: "aws" };
  const seen = new Set();
  const supported = new Set([
    "--environment",
    "--platform-account-id",
    "--execution-account-id",
    "--region",
    "--partition",
    "--pulumi-organization",
    "--output",
  ]);
  for (let index = 0; index < values.length; index += 1) {
    const key = values[index];
    if (key === "--account-id") {
      fail(
        "CLOUD_CONTEXT_SINGLE_ACCOUNT_DENIED",
        "--account-id is forbidden; platform and execution account IDs must be explicit and separate.",
      );
    }
    if (!supported.has(key)) {
      fail(
        "CLOUD_CONTEXT_ARGUMENT_UNKNOWN",
        `Unknown argument '${key ?? ""}'.`,
      );
    }
    const field = {
      "--environment": "environment",
      "--platform-account-id": "platformAccountId",
      "--execution-account-id": "executionAccountId",
      "--region": "region",
      "--partition": "partition",
      "--pulumi-organization": "pulumiOrganization",
      "--output": "output",
    }[key];
    if (seen.has(key)) {
      fail("CLOUD_CONTEXT_ARGUMENT_DUPLICATE", `${key} may be supplied once.`);
    }
    seen.add(key);
    const value = values[index + 1];
    if (!value || value.startsWith("--")) {
      fail("CLOUD_CONTEXT_ARGUMENT_MISSING", `${key} requires a value.`);
    }
    parsed[field] = value;
    index += 1;
  }
  for (const field of [
    "environment",
    "platformAccountId",
    "executionAccountId",
    "region",
    "pulumiOrganization",
  ]) {
    if (!parsed[field]) {
      fail(
        "CLOUD_CONTEXT_ARGUMENT_REQUIRED",
        `--${field.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`)} is required.`,
      );
    }
  }
  if (!["development", "staging", "production"].includes(parsed.environment)) {
    fail("CLOUD_CONTEXT_ENVIRONMENT_INVALID", "Unsupported environment.");
  }
  if (!/^[A-Za-z0-9._-]+$/.test(parsed.pulumiOrganization)) {
    fail(
      "CLOUD_CONTEXT_PULUMI_ORGANIZATION_INVALID",
      "Pulumi organization contains unsafe characters.",
    );
  }
  if (!["aws", "aws-us-gov", "aws-cn"].includes(parsed.partition)) {
    fail("CLOUD_CONTEXT_PARTITION_INVALID", "Unsupported AWS partition.");
  }
  return parsed;
}

function environmentSuffix(environment) {
  return { development: "dev", staging: "staging", production: "prod" }[
    environment
  ];
}

function writeAtomic(output, contents) {
  const target = path.resolve(output);
  const parent = path.dirname(target);
  if (!lstatSync(parent).isDirectory() || lstatSync(parent).isSymbolicLink()) {
    fail(
      "CLOUD_CONTEXT_OUTPUT_UNSAFE",
      "Output parent must be a real directory.",
    );
  }
  const canonicalParent = realpathSync(parent);
  if (path.dirname(target) !== canonicalParent) {
    fail(
      "CLOUD_CONTEXT_OUTPUT_UNSAFE",
      "Output parent must not traverse a symlink.",
    );
  }
  if (existsSync(target)) {
    const targetStat = lstatSync(target);
    if (!targetStat.isFile() || targetStat.isSymbolicLink()) {
      fail(
        "CLOUD_CONTEXT_OUTPUT_UNSAFE",
        "Output must be a regular non-symlink file.",
      );
    }
  }
  const temporary = path.join(
    canonicalParent,
    `.${path.basename(target)}.${process.pid}.tmp`,
  );
  try {
    writeFileSync(temporary, contents, { mode: 0o600, flag: "wx" });
    renameSync(temporary, target);
  } finally {
    if (existsSync(temporary)) unlinkSync(temporary);
  }
}

function fail(code, message) {
  throw new Error(`[${code}] ${message}`);
}
