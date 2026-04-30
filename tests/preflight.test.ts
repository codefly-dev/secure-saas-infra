import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";

test("preflight accepts the repository automation baseline", () => {
  const output = execFileSync(process.execPath, ["scripts/preflight.mjs"], {
    encoding: "utf8",
  });
  assert.match(output, /Preflight passed/);
});
