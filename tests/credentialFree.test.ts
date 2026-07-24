import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  parseAwsDatabaseInfrastructureHandoff,
  parsePostgresAccessObservationEvidence,
  parsePostgresAccessProfile,
} from "../src/core";

const parsers = [
  {
    name: "PostgresAccessProfile",
    fixture: "contracts/postgres-access-profile-v1alpha1.json",
    parse: parsePostgresAccessProfile,
    setValue(value: any, canary: string) {
      value.application.serviceRef = canary;
    },
  },
  {
    name: "AwsDatabaseInfrastructureHandoff",
    fixture: "contracts/aws-database-infrastructure-handoff-v1alpha1.json",
    parse: parseAwsDatabaseInfrastructureHandoff,
    setValue(value: any, canary: string) {
      value.readiness.reason = canary;
    },
  },
  {
    name: "PostgresAccessObservationEvidence",
    fixture: "contracts/postgres-access-observation-v1alpha1.json",
    parse: parsePostgresAccessObservationEvidence,
    setValue(value: any, canary: string) {
      value.deploymentAuthority.sourceRepository = canary;
    },
  },
] as const;

test("PostgreSQL public contracts share one recursive credential-free guard", () => {
  const valueCanaries = [
    "-----BEGIN PRIVATE KEY-----\nforbidden\n-----END PRIVATE KEY-----",
    `AKIA${"A".repeat(16)}`,
    `ASIA${"B".repeat(16)}`,
    "eyJheader.payload.signature",
    "postgresql://runtime:password@database.internal/warden",
    "Bearer eyJforbidden.token.value",
    "Basic dXNlcjpwYXNzd29yZA==",
    `ghp_${"a".repeat(24)}`,
    Buffer.from(
      "postgresql://runtime:password@database.internal/warden",
    ).toString("base64"),
    "forbidden\u0000value",
  ];
  const keyCanaries = [
    "db_password",
    "client-secret",
    "connection.string",
    "apiKey",
    "authorization",
    "private_key_pem",
    "sessionToken",
  ];

  for (const entry of parsers) {
    const baseline = read(entry.fixture);
    assert.doesNotThrow(() => entry.parse(baseline), entry.name);
    for (const key of keyCanaries) {
      const hostile = read(entry.fixture);
      hostile[key] = "forbidden";
      assert.throws(
        () => entry.parse(hostile),
        /CREDENTIAL_MATERIAL/,
        `${entry.name}/${key}`,
      );
    }
    for (const canary of valueCanaries) {
      const hostile = read(entry.fixture);
      entry.setValue(hostile, canary);
      assert.throws(
        () => entry.parse(hostile),
        /CREDENTIAL_MATERIAL/,
        `${entry.name}/${canary.slice(0, 24)}`,
      );
    }
    const secret = read(entry.fixture);
    secret.injected = {
      apiVersion: "v1",
      kind: "Secret",
      stringData: { harmlessLookingField: "forbidden" },
    };
    assert.throws(
      () => entry.parse(secret),
      /CREDENTIAL_MATERIAL/,
      `${entry.name}/Secret`,
    );
  }
});

function read(file: string): any {
  return JSON.parse(readFileSync(file, "utf8"));
}
