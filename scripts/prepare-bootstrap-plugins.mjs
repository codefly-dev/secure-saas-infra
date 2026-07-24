#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import {
  lstatSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  rmSync,
} from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { assertHostToolchainPins } from "./bootstrap-host-toolchain.mjs";

const root = realpathSync(
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."),
);
const pulumiHome = path.join(root, "artifacts", "bootstrap-pulumi-home");
const pluginHome = path.join(root, "artifacts", "bootstrap-plugin-home");
assertCredentialFreeEnvironment(process.env, pulumiHome);
if (process.platform !== "linux" || !["x64", "arm64"].includes(process.arch)) {
  throw new Error(
    "production bootstrap plugin installation requires Linux amd64 or arm64",
  );
}
const pulumi = selectPulumi(process.argv.slice(2));
const architecture = process.arch === "x64" ? "amd64" : "arm64";
const toolchain = JSON.parse(
  readFileSync(
    path.join(root, "security", "bootstrap-host-toolchain.json"),
    "utf8",
  ),
);
const provider = assertHostToolchainPins(toolchain).pulumiAwsProvider;
const archive = provider?.linuxArchives?.[architecture];
const plugins = [
  {
    kind: "resource",
    name: "aws",
    version: provider.version,
    checksum: archive.sha256,
  },
];
rmSync(pulumiHome, { recursive: true, force: true });
rmSync(pluginHome, { recursive: true, force: true });
mkdirSync(pulumiHome, { recursive: true, mode: 0o700 });
mkdirSync(pluginHome, { recursive: true, mode: 0o700 });

for (const plugin of plugins) {
  const result = spawnSync(
    pulumi,
    [
      "plugin",
      "install",
      plugin.kind,
      plugin.name,
      plugin.version,
      "--exact",
      "--reinstall",
      "--checksum",
      plugin.checksum,
    ],
    {
      stdio: "inherit",
      env: {
        HOME: pluginHome,
        LANG: "C",
        PATH: "/usr/bin:/bin",
        PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION: "true",
        PULUMI_HOME: pulumiHome,
        PULUMI_IGNORE_AMBIENT_PLUGINS: "true",
      },
    },
  );
  if (result.status !== 0) process.exit(result.status ?? 1);
}

process.stdout.write(
  `Exact management-seed Pulumi plugins are installed in ${pulumiHome}.\n`,
);

function selectPulumi(args) {
  const production = process.env.DEUS_PRODUCTION_QUALIFICATION === "1";
  let candidate = "/usr/local/lib/deus-bootstrap/toolchains/pulumi/pulumi";
  if (args.length !== 0) {
    if (
      production ||
      args.length !== 2 ||
      args[0] !== "--pulumi" ||
      !path.isAbsolute(args[1])
    ) {
      throw new Error("bootstrap plugin installer received invalid arguments");
    }
    candidate = args[1];
  }
  const resolved = realpathSync(candidate);
  const stat = lstatSync(resolved);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.mode & 0o022) {
    throw new Error(
      "bootstrap plugin installer requires a protected direct Pulumi executable",
    );
  }
  return resolved;
}

function assertCredentialFreeEnvironment(environment, expectedPulumiHome) {
  const permitted = new Map([
    ["PULUMI_HOME", expectedPulumiHome],
    ["PULUMI_DISABLE_AUTOMATIC_PLUGIN_ACQUISITION", "true"],
    ["PULUMI_IGNORE_AMBIENT_PLUGINS", "true"],
  ]);
  for (const [name, value] of Object.entries(environment)) {
    const upper = name.toUpperCase();
    const fixed = permitted.get(upper);
    if (fixed !== undefined && value === fixed) continue;
    if (
      upper.startsWith("AWS_") ||
      upper.startsWith("PULUMI_") ||
      upper.startsWith("NODE_") ||
      upper.startsWith("NPM_") ||
      upper.startsWith("GIT_") ||
      upper.startsWith("LD_") ||
      upper.startsWith("DYLD_") ||
      upper.includes("TOKEN") ||
      upper.includes("SECRET") ||
      upper.includes("CREDENTIAL") ||
      upper.endsWith("_PROXY") ||
      upper === "SSH_AUTH_SOCK" ||
      upper === "BASH_ENV" ||
      upper === "ENV"
    ) {
      throw new Error(
        `bootstrap plugin installer rejects inherited environment variable ${name}`,
      );
    }
  }
}
