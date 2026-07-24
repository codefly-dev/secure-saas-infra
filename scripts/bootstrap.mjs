#!/usr/bin/env node

// Builtins-only boundary. No package or repository module is loaded until a
// credential-bearing invocation proves the installed stage-1 capability.
const credentialRequest = process.argv
  .slice(2)
  .some(
    (argument) =>
      argument === "--preview" ||
      argument.startsWith("--preview=") ||
      argument === "--apply" ||
      argument.startsWith("--apply=") ||
      argument === "--recover-organization-state" ||
      argument.startsWith("--recover-organization-state="),
  );
const credentialPresent = Object.entries(process.env).some(
  ([name, value]) =>
    Boolean(value) &&
    (/^(?:AWS_|PULUMI_)/.test(name) ||
      /^(?:GH_TOKEN|GITHUB_TOKEN|NPM_TOKEN|NODE_AUTH_TOKEN|SSH_AUTH_SOCK|GIT_ASKPASS|SSH_ASKPASS)$/.test(
        name,
      )),
);

if (credentialRequest || credentialPresent) {
  const capability =
    globalThis[Symbol.for("security.deus.dev/credentialed-stage1/v1")];
  if (
    capability?.apiVersion !== "security.deus.dev/credentialed-stage1/v1" ||
    capability.entrypoint !== "bootstrap" ||
    capability.executionRoot !== "/usr/local/lib/deus-bootstrap/execution"
  ) {
    throw new Error(
      "Credentialed bootstrap requires /usr/local/bin/deus-aws-bootstrap and its immutable qualified snapshot.",
    );
  }
}

await import("./bootstrap-main.mjs");
