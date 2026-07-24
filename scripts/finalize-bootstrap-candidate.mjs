#!/usr/bin/env node

import { createHash, createPublicKey, verify } from "node:crypto";
import {
  existsSync,
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  assertBootstrapRuntime,
  assertSafeBootstrapEnvironment,
  bootstrapRuntimeProvenanceBinding,
  directoryDigest,
} from "./bootstrap-runtime-integrity.mjs";
import { assertBootstrapSealInventory } from "./bootstrap-seal-inventory.mjs";
import { managementSeedSourceState } from "./management-seed-scope.mjs";

const root = realpathSync(
  path.resolve(path.dirname(fileURLToPath(import.meta.url)), ".."),
);
const args = parseArgs(process.argv.slice(2));
assertSafeBootstrapEnvironment(process.env, "bootstrap finalization");
const requestPath = safeRepositoryInput(
  args.request ?? "artifacts/bootstrap-candidate.unsigned.json",
  "qualification request",
);
if (!args.signature)
  fail(
    "--signature is required and must name the raw 64-byte Ed25519 signature.",
  );
if (root !== "/usr/local/lib/deus-bootstrap/execution") {
  fail("Bootstrap finalization must run in the fixed execution root.");
}
const signaturePath = safeExternalInput(args.signature, "detached signature");
const outputPath = safeRepositoryOutput(
  args.output ?? "artifacts/bootstrap-candidate.json",
);
const signingReviewBundlePath = safeRepositoryInput(
  "artifacts/bootstrap-signing-review-bundle.json",
  "confidential signing review bundle",
);
const request = parseJson(requestPath);
validate(
  request,
  "schemas/bootstrap-qualification-request-v1.schema.json",
  "bootstrap qualification request",
);
const { candidateDigest, ...subject } = request;
if (candidateDigest !== sha256(canonicalJson(subject))) {
  fail("Qualification request digest does not match its canonical subject.");
}

const trustPath = safeRepositoryInput(
  "security/bootstrap-qualification-trust.json",
  "qualification trust root",
);
const trust = parseJson(trustPath);
validate(
  trust,
  "schemas/bootstrap-qualification-trust-v1.schema.json",
  "qualification trust root",
);
if (trust.configured !== true || request.signingKeyId !== trust.keyId) {
  fail(
    "Qualification request does not bind the configured signing trust root.",
  );
}
const signatureBytes = readFileSync(signaturePath);
if (signatureBytes.length !== 64)
  fail("Detached Ed25519 signature must be exactly 64 bytes.");
let publicKey;
try {
  const publicDer = Buffer.from(trust.publicKeySpki, "base64url");
  if (sha256(publicDer) !== trust.keyId)
    fail("Qualification trust key ID is invalid.");
  publicKey = createPublicKey({ key: publicDer, format: "der", type: "spki" });
} catch (error) {
  fail(`Qualification trust root is invalid: ${error.message}`);
}
if (
  publicKey.asymmetricKeyType !== "ed25519" ||
  !verify(
    null,
    Buffer.from(signaturePayload(candidateDigest), "utf8"),
    publicKey,
    signatureBytes,
  )
) {
  fail("Detached bootstrap qualification signature verification failed.");
}

const runtime = assertBootstrapRuntime(root, request.runtime, process.env, {
  requireRunningNode: false,
});
if (
  canonicalJson(bootstrapRuntimeProvenanceBinding(runtime)) !==
  canonicalJson(request.runtimeProvenance)
) {
  fail("Runtime provenance changed after credential-free qualification.");
}
const source = sourceState();
if (
  source.dirty ||
  source.revision !== request.source.revision ||
  source.treeDigest !== request.source.treeDigest
) {
  fail("Source changed after credential-free qualification.");
}
if (
  directoryDigest(path.join(root, request.build.path)) !==
  request.build.treeDigest
) {
  fail("Compiled infrastructure build changed after qualification.");
}
const configuration = currentConfiguration(request.configuration);
if (canonicalJson(configuration) !== canonicalJson(request.configuration)) {
  fail("Onboarding or Pulumi stack configuration changed after qualification.");
}
for (const evidence of [request.localGateEvidence, request.releaseEvidence]) {
  if (
    hashFile(safeRepositoryInput(evidence.path, "qualification evidence")) !==
    evidence.sha256
  ) {
    fail(
      `Qualification evidence '${evidence.path}' changed before finalization.`,
    );
  }
}
if (
  request.nativeLauncher.path !== "artifacts/deus-aws-bootstrap" ||
  hashFile(
    safeRepositoryInput(request.nativeLauncher.path, "native launcher"),
  ) !== request.nativeLauncher.sha256
) {
  fail("Native credential launcher changed after qualification.");
}
assertBootstrapSealInventory(root, request.sealInventory);
const candidate = {
  ...request,
  signature: {
    algorithm: "Ed25519",
    keyId: trust.keyId,
    value: signatureBytes.toString("base64url"),
  },
};
validate(
  candidate,
  "schemas/bootstrap-candidate-v1.schema.json",
  "bootstrap candidate",
);
rmSync(signingReviewBundlePath);
writeAtomic(outputPath, `${JSON.stringify(candidate, null, 2)}\n`);
process.stdout.write(
  `Finalized signed bootstrap candidate ${path.relative(root, outputPath)} (${candidateDigest}).\n`,
);

function currentConfiguration(requested) {
  const paths = requested.map((entry) => entry.path).sort();
  if (
    paths.length !== 2 ||
    !paths.includes("Pulumi.management.yaml") ||
    paths.filter((entry) => entry !== "Pulumi.management.yaml").length !== 1
  ) {
    fail(
      "Qualification request must bind only onboarding and Pulumi.management.yaml.",
    );
  }
  return paths
    .map((file) => ({
      path: file,
      sha256: hashFile(safeRepositoryInput(file, "qualified configuration")),
    }))
    .sort((left, right) => left.path.localeCompare(right.path));
}

function sourceState() {
  const { entries: _entries, ...source } = managementSeedSourceState(root);
  return source;
}

function validate(value, schemaName, label) {
  const schema = parseJson(safeRepositoryInput(schemaName, "schema"));
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  if (schemaName === "schemas/bootstrap-qualification-request-v1.schema.json") {
    ajv.addSchema(
      parseJson(
        safeRepositoryInput(
          "schemas/bootstrap-candidate-v1.schema.json",
          "candidate schema",
        ),
      ),
    );
  }
  const validator = ajv.compile(schema);
  if (!validator(value))
    fail(
      `${label} failed strict schema validation: ${JSON.stringify(validator.errors)}.`,
    );
}

function safeRepositoryInput(value, label) {
  const candidate = path.resolve(root, value);
  assertInsideRepository(candidate);
  if (!existsSync(candidate)) fail(`${label} is missing: ${value}.`);
  const stat = lstatSync(candidate);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    realpathSync(candidate) !== candidate
  ) {
    fail(`${label} must be a direct regular file.`);
  }
  return candidate;
}

function safeExternalInput(value, label) {
  const candidate = path.resolve(value);
  if (!existsSync(candidate)) fail(`${label} is missing.`);
  const stat = lstatSync(candidate);
  if (
    !stat.isFile() ||
    stat.isSymbolicLink() ||
    realpathSync(candidate) !== candidate
  ) {
    fail(`${label} must be a direct regular file without symlinks.`);
  }
  return candidate;
}

function safeRepositoryOutput(value) {
  const candidate = path.resolve(root, value);
  assertInsideRepository(candidate);
  const parent = path.dirname(candidate);
  if (
    !existsSync(parent) ||
    lstatSync(parent).isSymbolicLink() ||
    realpathSync(parent) !== parent
  ) {
    fail("Candidate output parent must be an existing direct directory.");
  }
  if (
    existsSync(candidate) &&
    (!lstatSync(candidate).isFile() || lstatSync(candidate).isSymbolicLink())
  ) {
    fail("Candidate output must be a regular file.");
  }
  return candidate;
}

function assertInsideRepository(candidate) {
  const relative = path.relative(root, candidate);
  if (
    !relative ||
    relative === ".." ||
    relative.startsWith(`..${path.sep}`) ||
    path.isAbsolute(relative)
  ) {
    fail(`Path '${candidate}' escapes the repository.`);
  }
}

function writeAtomic(file, body) {
  const temporary = `${file}.${process.pid}.tmp`;
  try {
    writeFileSync(temporary, body, { flag: "wx", mode: 0o600 });
    renameSync(temporary, file);
  } finally {
    rmSync(temporary, { force: true });
  }
}

function parseArgs(values) {
  const allowed = new Set(["request", "signature", "output"]);
  const parsed = {};
  for (let index = 0; index < values.length; index += 1) {
    const token = values[index];
    if (!token?.startsWith("--") || !allowed.has(token.slice(2)))
      fail(`Unknown argument '${token}'.`);
    const key = token.slice(2);
    if (Object.hasOwn(parsed, key)) fail(`Duplicate argument '${token}'.`);
    const value = values[++index];
    if (!value || value.startsWith("--")) fail(`${token} requires a value.`);
    parsed[key] = value;
  }
  return parsed;
}

function parseJson(file) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch (error) {
    fail(`${file} is not valid JSON: ${error.message}`);
  }
}

function signaturePayload(digest) {
  return `security.deus.dev/bootstrap-candidate/v1:${digest}`;
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

function fail(message) {
  process.stderr.write(`BOOTSTRAP_CANDIDATE_FINALIZATION_DENIED: ${message}\n`);
  process.exit(1);
}
