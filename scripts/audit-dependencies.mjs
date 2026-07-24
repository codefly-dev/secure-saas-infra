#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { evaluateDependencyAudit } from "../dist-management-seed-support/dependencySecurity.js";

const root = resolve(process.cwd());
const exceptionFile = JSON.parse(
  readFileSync(resolve(root, "security/dependency-exceptions.json"), "utf8"),
);
const audit = spawnSync("npm", ["audit", "--json"], {
  cwd: root,
  encoding: "utf8",
  maxBuffer: 20 * 1024 * 1024,
});

if (!audit.stdout) {
  console.error(
    audit.stderr || audit.error?.message || "npm audit produced no output",
  );
  process.exit(1);
}

let report;
try {
  report = JSON.parse(audit.stdout);
} catch (error) {
  console.error(`Unable to parse npm audit JSON: ${error.message}`);
  process.exit(1);
}

if (audit.status !== 0 && audit.status !== 1) {
  console.error(
    audit.stderr ||
      `npm audit failed with unexpected exit code ${audit.status}`,
  );
  process.exit(1);
}

let evaluation;
try {
  evaluation = evaluateDependencyAudit(report, exceptionFile);
} catch (error) {
  console.error(
    `Dependency security gate could not evaluate the audit: ${error.message}`,
  );
  process.exit(1);
}
for (const warning of evaluation.warnings) console.warn(`warning: ${warning}`);
for (const accepted of evaluation.accepted) {
  console.log(
    `accepted: ${accepted.advisoryId} (${accepted.severity}) in ${accepted.packageName}`,
  );
}
if (evaluation.failures.length > 0) {
  for (const failure of evaluation.failures) console.error(`error: ${failure}`);
  process.exit(1);
}

console.log(
  `Dependency security gate passed: ${evaluation.advisories.length} underlying advisories, ${evaluation.accepted.length} reviewed exceptions, no high or critical findings.`,
);
