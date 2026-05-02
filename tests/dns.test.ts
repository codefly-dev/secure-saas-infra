import test from "node:test";
import assert from "node:assert/strict";
import {
  flushPulumiMocks,
  installPulumiMocks,
  resourcesOfType,
} from "./helpers/pulumiMocks";
import { DnsConfig, validateDnsConfig } from "../src/config";

const baseline: DnsConfig = {
  rootDomain: "mind.example",
  createRootZone: true,
  enableQueryLogging: true,
  environmentSubdomains: ["dev", "staging", "prod"],
};

test("validateDnsConfig accepts a multi-env baseline", () => {
  assert.doesNotThrow(() => validateDnsConfig(baseline));
});

test("validateDnsConfig rejects malformed apex, bad slugs, duplicates", () => {
  assert.throws(
    () => validateDnsConfig({ ...baseline, rootDomain: "not-an-apex" }),
    /valid DNS apex/,
  );
  assert.throws(
    () =>
      validateDnsConfig({
        ...baseline,
        environmentSubdomains: ["dev", "Bad Slug"],
      }),
    /DNS-safe slug/,
  );
  assert.throws(
    () =>
      validateDnsConfig({
        ...baseline,
        environmentSubdomains: ["dev", "dev"],
      }),
    /duplicate entry/,
  );
});

test("dns stack creates root zone, per-env zones, NS delegation, query logging", async () => {
  const { resources } = await installPulumiMocks();
  const { createDns } = await import("../src/dns");

  createDns(baseline);

  await flushPulumiMocks();

  const zones = resourcesOfType(resources, "aws:route53/zone:Zone");
  assert.equal(zones.length, 4); // root + dev + staging + prod
  const zoneNames = zones.map((zone) => zone.inputs.name);
  for (const expected of [
    "mind.example",
    "dev.mind.example",
    "staging.mind.example",
    "prod.mind.example",
  ]) {
    assert.ok(zoneNames.includes(expected), `expected zone ${expected}`);
  }

  const records = resourcesOfType(resources, "aws:route53/record:Record");
  const nsRecords = records.filter((record) => record.inputs.type === "NS");
  assert.equal(nsRecords.length, 3, "one NS delegation per environment");
  assert.ok(
    nsRecords.every((record) => record.inputs.ttl === 172800),
    "delegations should use 48h TTL",
  );

  const queryLogs = resourcesOfType(
    resources,
    "aws:route53/queryLog:QueryLog",
  );
  assert.equal(queryLogs.length, 1);

  const logGroups = resourcesOfType(
    resources,
    "aws:cloudwatch/logGroup:LogGroup",
  );
  assert.ok(
    logGroups.some(
      (group) => group.inputs.name === "/aws/route53/mind.example",
    ),
  );
});

test("dns stack skips root zone and query logging when disabled", async () => {
  const { resources } = await installPulumiMocks();
  const { createDns } = await import("../src/dns");

  createDns({
    ...baseline,
    createRootZone: false,
    enableQueryLogging: false,
    environmentSubdomains: ["dev"],
  });

  await flushPulumiMocks();

  const zones = resourcesOfType(resources, "aws:route53/zone:Zone");
  // No root zone, just one env zone.
  assert.equal(zones.length, 1);

  const queryLogs = resourcesOfType(
    resources,
    "aws:route53/queryLog:QueryLog",
  );
  assert.equal(queryLogs.length, 0);

  // Without root zone, no NS delegation records.
  const nsRecords = resourcesOfType(
    resources,
    "aws:route53/record:Record",
  ).filter((record) => record.inputs.type === "NS");
  assert.equal(nsRecords.length, 0);
});
