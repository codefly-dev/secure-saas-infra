#!/usr/bin/env node

// This entrypoint is credentialed-only and deliberately builtins-only until
// the installed verifier's in-process capability has passed.
const capability =
  globalThis[Symbol.for("security.deus.dev/credentialed-stage1/v1")];
if (
  capability?.apiVersion !== "security.deus.dev/credentialed-stage1/v1" ||
  capability.entrypoint !== "access-provisioner" ||
  capability.executionRoot !== "/usr/local/lib/deus-bootstrap/execution"
) {
  throw new Error(
    "Credentialed access provisioning requires /usr/local/bin/deus-aws-bootstrap and its immutable qualified snapshot.",
  );
}

await import("./provision-management-seed-access-main.mjs");
