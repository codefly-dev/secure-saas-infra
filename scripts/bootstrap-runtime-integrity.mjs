import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  realpathSync,
  statSync,
} from "node:fs";
import { homedir } from "node:os";
import path from "node:path";

const expectedPulumiPlugins = [
  { kind: "resource", name: "aws", version: "7.27.0" },
];
const runtimeProvenancePath =
  "/usr/local/lib/deus-bootstrap/runtime-provenance.json";

export function bootstrapRuntimeProvenanceBinding(runtime) {
  assertRootOwnedProtectedPath(runtimeProvenancePath);
  const provenance = JSON.parse(readFileSync(runtimeProvenancePath, "utf8"));
  const architecture = process.arch === "x64" ? "amd64" : process.arch;
  const expectedArchives = {
    amd64: {
      go: [
        "go1.26.5.linux-amd64.tar.gz",
        "5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053",
      ],
      node: [
        "node-v24.18.0-linux-x64.tar.xz",
        "55aa7153f9d88f28d765fcdad5ae6945b5c0f98a36881703817e4c450fa76742",
      ],
      pulumi: [
        "pulumi-v3.253.0-linux-x64.tar.gz",
        "33161e521280e6c77395a46344dba5ff9c118a90df254801e662087143b4d1ac",
      ],
    },
    arm64: {
      go: [
        "go1.26.5.linux-arm64.tar.gz",
        "fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49",
      ],
      node: [
        "node-v24.18.0-linux-arm64.tar.xz",
        "58c9520501f6ae2b52d5b210444e24b9d0c029a58c5011b797bc1fe7105886f6",
      ],
      pulumi: [
        "pulumi-v3.253.0-linux-arm64.tar.gz",
        "7d7074d67a76139226c163b2365f14fbd45d8e2251362a2e10dc4602b3b577ea",
      ],
    },
  }[architecture];
  if (
    !expectedArchives ||
    provenance.apiVersion !==
      "security.deus.dev/bootstrap-runtime-provenance/v1" ||
    provenance.platform !== "linux" ||
    provenance.architecture !== architecture ||
    !["go", "node", "pulumi"].every(
      (name) =>
        provenance.artifacts?.[name]?.verification ===
        "authenticated-host-kit-pinned-sha256",
    ) ||
    provenance.artifacts?.awsCli?.verification !== "aws-cli-team-pgp" ||
    provenance.artifacts?.awsCli?.signingKeyFingerprint !==
      "FB5DB77FD5C118B80511ADA8A6310ACC4672475C" ||
    !/^[a-f0-9]{64}$/.test(provenance.artifacts?.awsCli?.sha256 ?? "") ||
    !Object.entries(expectedArchives).every(
      ([name, [file, sha256]]) =>
        provenance.artifacts?.[name]?.file === file &&
        provenance.artifacts?.[name]?.sha256 === sha256,
    )
  ) {
    throw new Error(
      "Bootstrap runtime provenance does not match the authenticated pinned installation.",
    );
  }
  assertSystemRuntimeClosure(provenance.systemRuntime, architecture);
  const executable = new Map(
    runtime.executables.map((entry) => [entry.name, entry]),
  );
  const directory = new Map(
    runtime.directories.map((entry) => [entry.name, entry]),
  );
  const goPath = "/usr/local/lib/deus-bootstrap/toolchains/go/bin/go";
  if (
    provenance.installed?.nodeSha256 !== executable.get("node")?.sha256 ||
    provenance.installed?.pulumiTreeDigest !==
      directory.get("pulumi-install")?.treeDigest ||
    provenance.installed?.awsCliTreeDigest !==
      directory.get("aws-cli-install")?.treeDigest ||
    provenance.installed?.goSha256 !== hashFile(goPath)
  ) {
    throw new Error(
      "Bootstrap runtime does not match its authenticated installation provenance.",
    );
  }
  return {
    path: runtimeProvenancePath,
    sha256: hashFile(runtimeProvenancePath),
  };
}

function assertSystemRuntimeClosure(value, architecture) {
  if (
    value?.apiVersion !== "security.deus.dev/system-runtime-closure/v1" ||
    value.architecture !== architecture ||
    !Array.isArray(value.loaders) ||
    value.loaders.length === 0 ||
    value.loaders.length > 8 ||
    !Array.isArray(value.libraries) ||
    value.libraries.length > 512
  ) {
    throw new Error("Bootstrap system runtime closure is malformed.");
  }
  const seen = new Set();
  for (const entries of [value.loaders, value.libraries]) {
    const paths = entries.map((entry) => entry.path);
    if (canonicalJson(paths) !== canonicalJson([...paths].sort())) {
      throw new Error("Bootstrap system runtime closure is not sorted.");
    }
    for (const entry of entries) {
      if (
        typeof entry.path !== "string" ||
        (!entry.path.startsWith("/usr/lib/") &&
          !entry.path.startsWith("/lib/")) ||
        seen.has(entry.path) ||
        !/^[a-f0-9]{64}$/.test(entry.sha256 ?? "") ||
        realpathSync(entry.path) !== entry.path ||
        hashFile(entry.path) !== entry.sha256
      ) {
        throw new Error("Bootstrap system runtime binding changed.");
      }
      assertRootOwnedProtectedPath(entry.path);
      seen.add(entry.path);
    }
  }
}

function assertRootOwnedProtectedPath(value) {
  let current = path.parse(value).root;
  for (const part of value.slice(current.length).split(path.sep)) {
    if (!part) continue;
    current = path.join(current, part);
    const info = lstatSync(current);
    if (info.isSymbolicLink() || info.uid !== 0 || (info.mode & 0o022) !== 0) {
      throw new Error(
        `Bootstrap trust path '${current}' is not root-owned and protected.`,
      );
    }
  }
  if (!statSync(value).isFile()) {
    throw new Error("Bootstrap runtime provenance is not a regular file.");
  }
}

export const forbiddenBootstrapEnvironmentPatterns = [
  /^NODE_OPTIONS$/i,
  /^NODE_PATH$/i,
  /^BUN_OPTIONS$/i,
  /^DENO_DIR$/i,
  /^PULUMI_NODEJS_/i,
  /^PULUMI_DEBUG_COMMANDS$/i,
  /^PULUMI_AUTOMATION_API_SKIP_VERSION_CHECK$/i,
  /^AWS_ENDPOINT_URL(?:_|$)/i,
  /^AWS_EC2_METADATA_SERVICE_ENDPOINT$/i,
  /^AWS_PROFILE$/i,
  /^AWS_DEFAULT_PROFILE$/i,
  /^AWS_SDK_LOAD_CONFIG$/i,
  /^AWS_WEB_IDENTITY_TOKEN_FILE$/i,
  /^AWS_ROLE_ARN$/i,
  /^AWS_CONTAINER_CREDENTIALS_RELATIVE_URI$/i,
  /^LOCALSTACK_/i,
];

export const forbiddenCredentialTransportEnvironmentPatterns = [
  /^(?:HTTP|HTTPS|ALL|NO)_PROXY$/i,
  /^(?:AWS|REQUESTS|CURL)_CA_BUNDLE$/i,
  /^SSL_CERT_(?:FILE|DIR)$/i,
  /^NODE_EXTRA_CA_CERTS$/i,
];

export function assertSafeBootstrapEnvironment(
  environment,
  label = "bootstrap",
) {
  for (const [name, expected] of Object.entries({
    AWS_CONFIG_FILE: "/dev/null",
    AWS_EC2_METADATA_DISABLED: "true",
    AWS_SHARED_CREDENTIALS_FILE: "/dev/null",
  })) {
    if (environment[name] !== undefined && environment[name] !== expected) {
      throw new Error(`${label} rejects unsafe ${name}.`);
    }
  }
  const forbidden = Object.keys(environment)
    .filter((name) => environment[name])
    .filter((name) =>
      forbiddenBootstrapEnvironmentPatterns.some((pattern) =>
        pattern.test(name),
      ),
    )
    .sort();
  if (forbidden.length > 0) {
    throw new Error(
      `${label} rejects executable/provider override variables: ${forbidden.join(", ")}.`,
    );
  }
}

export function assertSafeCredentialTransportEnvironment(
  environment,
  label = "credentialed bootstrap",
) {
  const forbidden = Object.keys(environment)
    .filter((name) => environment[name])
    .filter((name) =>
      forbiddenCredentialTransportEnvironmentPatterns.some((pattern) =>
        pattern.test(name),
      ),
    )
    .sort();
  if (forbidden.length > 0) {
    throw new Error(
      `${label} rejects proxy or custom-CA variables: ${forbidden.join(", ")}.`,
    );
  }
}

export function assertExportedAwsSession(environment) {
  for (const name of [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "PULUMI_ACCESS_TOKEN",
    "PULUMI_CONFIG_PASSPHRASE",
    "PULUMI_CONFIG_PASSPHRASE_FILE",
  ]) {
    if (environment[name]) {
      throw new Error(
        `credentialed bootstrap rejects raw credential material in ${name}.`,
      );
    }
  }
  if (
    !/^http:\/\/127\.0\.0\.1:[1-9][0-9]{0,4}\/v1\/credentials$/.test(
      environment.AWS_CONTAINER_CREDENTIALS_FULL_URI ?? "",
    ) ||
    !/^Bearer [A-Za-z0-9_-]{43}$/.test(
      environment.AWS_CONTAINER_AUTHORIZATION_TOKEN ?? "",
    )
  ) {
    throw new Error(
      "credentialed bootstrap requires the native loopback credential broker.",
    );
  }
}

export function collectBootstrapRuntime(root, environment = process.env) {
  assertSafeBootstrapEnvironment(environment, "runtime qualification");
  const repositoryRoot = realpathSync(path.resolve(root));
  const node = executableArtifact(
    "node",
    process.execPath,
    ["--version"],
    repositoryRoot,
    environment,
  );
  const pulumi = executableArtifact(
    "pulumi",
    resolveCommand("pulumi", environment),
    ["version"],
    repositoryRoot,
    environment,
  );
  const aws = executableArtifact(
    "aws",
    resolveCommand("aws", environment),
    ["--version"],
    repositoryRoot,
    environment,
  );
  const pulumiDirectory = path.dirname(pulumi.realPath);
  const companions = [
    "pulumi-analyzer-policy",
    "pulumi-language-nodejs",
    "pulumi-resource-pulumi-nodejs",
  ].map((name) =>
    executableArtifact(
      name,
      path.join(pulumiDirectory, name),
      [],
      repositoryRoot,
      environment,
      false,
    ),
  );
  const pluginRoot = path.resolve(
    environment.PULUMI_HOME ?? path.join(homedir(), ".pulumi"),
    "plugins",
  );
  const plugins = expectedPulumiPlugins.map(({ kind, name, version }) => {
    const locator = path.join(pluginRoot, `${kind}-${name}-v${version}`);
    if (!existsSync(locator)) {
      throw new Error(
        `Required Pulumi plugin ${kind}/${name}@${version} is not installed; run env -i HOME="$HOME" LANG=C PATH="$PATH" mise exec -- ./scripts/prepare-bootstrap-plugins before qualification.`,
      );
    }
    return {
      kind,
      name,
      version,
      ...directoryArtifact(locator, repositoryRoot),
    };
  });
  const fixedAwsInstallRoot =
    "/usr/local/lib/deus-bootstrap/toolchains/aws-cli";
  const awsInstallRoot = aws.realPath.startsWith(
    `${fixedAwsInstallRoot}${path.sep}`,
  )
    ? fixedAwsInstallRoot
    : aws.realPath.includes(`${path.sep}libexec${path.sep}bin${path.sep}`)
      ? path.dirname(path.dirname(path.dirname(aws.realPath)))
      : path.dirname(aws.realPath);
  return {
    executables: [node, pulumi, aws, ...companions].sort((left, right) =>
      left.name.localeCompare(right.name),
    ),
    directories: [
      {
        name: "aws-cli-install",
        ...directoryArtifact(awsInstallRoot, repositoryRoot, true),
      },
      {
        name: "dependencies",
        ...directoryArtifact(
          path.join(repositoryRoot, "node_modules"),
          repositoryRoot,
        ),
      },
      {
        name: "pulumi-install",
        ...directoryArtifact(pulumiDirectory, repositoryRoot),
      },
      {
        name: "policy-build",
        ...directoryArtifact(
          path.join(repositoryRoot, "dist-management-seed-policy"),
          repositoryRoot,
        ),
      },
    ],
    pulumiPlugins: plugins,
  };
}

export function assertBootstrapRuntime(
  root,
  expected,
  environment = process.env,
  { requireRunningNode = true, runVersionProbes = true } = {},
) {
  assertSafeBootstrapEnvironment(environment, "runtime verification");
  const repositoryRoot = realpathSync(path.resolve(root));
  const executables = assertExpectedExecutableIntegrity(
    repositoryRoot,
    expected?.executables,
    requireRunningNode,
  );
  const directories = assertExpectedDirectoryIntegrity(
    repositoryRoot,
    expected?.directories,
  );
  const pulumiPlugins = assertExpectedPluginIntegrity(
    repositoryRoot,
    expected?.pulumiPlugins,
  );
  const actual = { executables, directories, pulumiPlugins };
  if (canonicalJson(actual) !== canonicalJson(expected)) {
    throw new Error(
      "Qualified executable, dependency, policy, or Pulumi plugin integrity changed after qualification.",
    );
  }

  // No executable is started until every candidate-bound byte/directory hash
  // above has passed. Version probes then run by exact real path without cloud
  // or Pulumi credentials, so a rejected executable cannot observe secrets.
  if (runVersionProbes) {
    const probeEnvironment = nonCredentialEnvironment(environment, executables);
    for (const entry of executables) {
      const args = versionArguments(entry.name);
      if (args === null) continue;
      const result = spawnSync(entry.realPath, args, {
        cwd: repositoryRoot,
        encoding: "utf8",
        env: probeEnvironment,
      });
      const version = `${result.stdout ?? ""} ${result.stderr ?? ""}`
        .trim()
        .split(/\r?\n/)[0];
      if (result.status !== 0 || version !== entry.version) {
        throw new Error(
          `Qualified executable '${entry.name}' failed its credential-free version check.`,
        );
      }
    }
  }
  return actual;
}

function assertExpectedExecutableIntegrity(root, expected, requireRunningNode) {
  const names = [
    "aws",
    "node",
    "pulumi",
    "pulumi-analyzer-policy",
    "pulumi-language-nodejs",
    "pulumi-resource-pulumi-nodejs",
  ];
  if (
    !Array.isArray(expected) ||
    canonicalJson(expected.map((entry) => entry?.name).sort()) !==
      canonicalJson(names)
  ) {
    throw new Error("Qualified executable inventory is not exact.");
  }
  return expected
    .map((entry) => {
      const locator = path.resolve(root, entry.path);
      if (!existsSync(locator)) {
        throw new Error(`Qualified executable '${entry.name}' is missing.`);
      }
      const real = realpathSync(locator);
      const stat = lstatSync(real);
      if (
        !stat.isFile() ||
        stat.isSymbolicLink() ||
        real !== entry.realPath ||
        hashFile(real) !== entry.sha256
      ) {
        throw new Error(
          `Qualified executable '${entry.name}' integrity changed.`,
        );
      }
      if (
        requireRunningNode &&
        entry.name === "node" &&
        real !== realpathSync(process.execPath)
      ) {
        throw new Error(
          "Credentialed verifier is not the qualified Node runtime.",
        );
      }
      return { ...entry };
    })
    .sort((left, right) => left.name.localeCompare(right.name));
}

function assertExpectedDirectoryIntegrity(root, expected) {
  const names = [
    "aws-cli-install",
    "dependencies",
    "policy-build",
    "pulumi-install",
  ];
  if (
    !Array.isArray(expected) ||
    canonicalJson(expected.map((entry) => entry?.name).sort()) !==
      canonicalJson(names)
  ) {
    throw new Error("Qualified runtime directory inventory is not exact.");
  }
  return expected.map((entry) => {
    const locator = path.resolve(root, entry.path);
    if (
      !existsSync(locator) ||
      lstatSync(locator).isSymbolicLink() ||
      !lstatSync(locator).isDirectory()
    ) {
      throw new Error(`Qualified directory '${entry.name}' is unsafe.`);
    }
    const real = realpathSync(locator);
    const digest = directoryDigest(real, {
      allowExternalSymlinks: entry.name === "aws-cli-install",
    });
    if (real !== entry.realPath || digest !== entry.treeDigest) {
      throw new Error(`Qualified directory '${entry.name}' integrity changed.`);
    }
    return { ...entry };
  });
}

function assertExpectedPluginIntegrity(root, expected) {
  if (
    !Array.isArray(expected) ||
    expected.length !== 1 ||
    expected[0]?.kind !== "resource" ||
    expected[0]?.name !== "aws" ||
    expected[0]?.version !== "7.27.0"
  ) {
    throw new Error("Qualified Pulumi plugin inventory is not exact.");
  }
  return expected.map((entry) => {
    const locator = path.resolve(root, entry.path);
    if (
      !existsSync(locator) ||
      lstatSync(locator).isSymbolicLink() ||
      !lstatSync(locator).isDirectory()
    ) {
      throw new Error("Qualified AWS Pulumi plugin is unsafe.");
    }
    const real = realpathSync(locator);
    if (real !== entry.realPath || directoryDigest(real) !== entry.treeDigest) {
      throw new Error("Qualified AWS Pulumi plugin integrity changed.");
    }
    return { ...entry };
  });
}

function versionArguments(name) {
  if (name === "node" || name === "aws") {
    return ["--version"];
  }
  if (name === "pulumi") return ["version"];
  return null;
}

function nonCredentialEnvironment(environment, executables) {
  const allowed = [
    "HOME",
    "USER",
    "LOGNAME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "TERM",
  ];
  const result = Object.fromEntries(
    allowed
      .filter((name) => environment[name] !== undefined)
      .map((name) => [name, environment[name]]),
  );
  result.PATH = [
    ...new Set(executables.map((entry) => path.dirname(entry.realPath))),
    "/usr/bin",
    "/bin",
  ].join(":");
  result.GIT_CONFIG_NOSYSTEM = "1";
  result.GIT_CONFIG_GLOBAL = "/dev/null";
  return result;
}

export function runtimeExecutable(runtime, name) {
  const entry = runtime?.executables?.find(
    (candidate) => candidate.name === name,
  );
  if (!entry) throw new Error(`Qualified runtime does not bind '${name}'.`);
  return entry.realPath;
}

export function directoryDigest(value, { allowExternalSymlinks = false } = {}) {
  const base = realpathSync(path.resolve(value));
  const entries = [];
  const walk = (current) => {
    for (const name of readdirSync(current).sort()) {
      const candidate = path.join(current, name);
      const stat = lstatSync(candidate);
      const relative = path.relative(base, candidate).split(path.sep).join("/");
      if (stat.isSymbolicLink()) {
        const target = readlinkSync(candidate);
        const resolved = realpathSync(candidate);
        if (!isWithin(base, resolved) && !allowExternalSymlinks) {
          throw new Error(
            `Symlink '${candidate}' escapes its sealed directory.`,
          );
        }
        const resolvedStat = lstatSync(resolved);
        if (resolvedStat.isDirectory() && isWithin(base, resolved)) {
          entries.push({ path: relative, type: "symlink", target });
          continue;
        }
        if (resolvedStat.isDirectory() && allowExternalSymlinks) {
          entries.push({
            path: relative,
            type: "symlink",
            target,
            resolvedTreeDigest: directoryDigest(resolved, {
              allowExternalSymlinks: true,
            }),
          });
          continue;
        }
        if (!resolvedStat.isFile()) {
          throw new Error(
            `Runtime symlink '${candidate}' must resolve to a regular file.`,
          );
        }
        entries.push({
          path: relative,
          type: "symlink",
          target,
          resolvedSha256: hashFile(resolved),
        });
      } else if (stat.isDirectory()) {
        walk(candidate);
      } else if (stat.isFile()) {
        entries.push({
          path: relative,
          type: "file",
          sha256: hashFile(candidate),
        });
      } else {
        throw new Error(
          `Runtime artifact '${candidate}' is not a regular file or directory.`,
        );
      }
    }
  };
  walk(base);
  if (entries.length === 0)
    throw new Error(`Runtime directory '${value}' is empty.`);
  return sha256(canonicalJson(entries));
}

function directoryArtifact(value, root, allowExternalSymlinks = false) {
  const locator = path.resolve(value);
  if (!existsSync(locator) || lstatSync(locator).isSymbolicLink()) {
    throw new Error(
      `Runtime directory '${locator}' is missing or is a symlink.`,
    );
  }
  const real = realpathSync(locator);
  return {
    path: portableLocator(locator, root),
    realPath: real,
    treeDigest: directoryDigest(real, { allowExternalSymlinks }),
  };
}

function executableArtifact(
  name,
  commandPath,
  versionArgs,
  root,
  environment,
  runVersion = true,
) {
  const locator = path.resolve(commandPath);
  if (!existsSync(locator))
    throw new Error(`Required executable '${name}' is missing.`);
  const real = realpathSync(locator);
  const stat = lstatSync(real);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new Error(`Required executable '${name}' is not a regular file.`);
  }
  let version = "bundled";
  if (runVersion) {
    const result = spawnSync(real, versionArgs, {
      cwd: root,
      encoding: "utf8",
      env: environment,
    });
    if (result.status !== 0)
      throw new Error(
        `Required executable '${name}' failed its version check.`,
      );
    version = `${result.stdout ?? ""} ${result.stderr ?? ""}`
      .trim()
      .split(/\r?\n/)[0];
  }
  return {
    name,
    path: portableLocator(locator, root),
    realPath: real,
    sha256: hashFile(real),
    version,
  };
}

function resolveCommand(command, environment) {
  const pathValue = environment.PATH ?? "";
  for (const directory of pathValue.split(path.delimiter)) {
    if (!directory) continue;
    const candidate = path.resolve(directory, command);
    if (
      existsSync(candidate) &&
      (lstatSync(candidate).isFile() ||
        lstatSync(candidate).isSymbolicLink()) &&
      lstatSync(realpathSync(candidate)).isFile()
    ) {
      return candidate;
    }
  }
  throw new Error(`Required command '${command}' is not available on PATH.`);
}

function portableLocator(value, root) {
  const relative = path.relative(root, value);
  return relative &&
    !relative.startsWith(`..${path.sep}`) &&
    !path.isAbsolute(relative)
    ? relative.split(path.sep).join("/")
    : value;
}

function isWithin(root, value) {
  const relative = path.relative(root, value);
  return !(
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  );
}

function hashFile(file) {
  return sha256(readFileSync(file));
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}
