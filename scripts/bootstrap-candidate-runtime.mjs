import { createPublicKey, verify as verifySignature } from "node:crypto";
import { lstatSync, readFileSync, readdirSync, realpathSync } from "node:fs";
import path from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { validateAdversarialReviewDisposition } from "./review-disposition.mjs";
import {
  assertBootstrapRuntime,
  runtimeExecutable,
} from "./bootstrap-runtime-integrity.mjs";
import { assertBootstrapSealInventory } from "./bootstrap-seal-inventory.mjs";
import {
  canonicalJson,
  managementSeedTreeDigest,
  safeFile,
  sha256,
} from "./management-seed-scope.mjs";
import { verifyManagementSeedReleaseEvidence } from "./verify-management-seed-release-evidence.mjs";

const CANDIDATE_MAX_AGE_MS = 24 * 60 * 60 * 1_000;

export function verifyBootstrapCandidateRuntime(
  root,
  candidateValue,
  configurationPath,
) {
  const repositoryRoot = realpathSync(path.resolve(root));
  const candidatePath = safeFile(repositoryRoot, candidateValue);
  const candidate = parseObject(candidatePath, "bootstrap candidate");
  validate(
    repositoryRoot,
    candidate,
    "schemas/bootstrap-candidate-v1.schema.json",
    "bootstrap candidate",
  );
  const { candidateDigest, signature, ...subject } = candidate;
  if (candidateDigest !== sha256(canonicalJson(subject))) {
    throw new Error("bootstrap candidate digest does not match");
  }
  const capability = credentialedCapability(repositoryRoot, candidateDigest);
  verifyCandidateSignature(repositoryRoot, candidateDigest, signature);
  assertBootstrapSealInventory(repositoryRoot, candidate.sealInventory);
  const generated = Date.parse(candidate.generatedAt);
  if (
    !Number.isFinite(generated) ||
    generated > Date.now() + 60_000 ||
    Date.now() - generated > CANDIDATE_MAX_AGE_MS ||
    candidate.signingKeyId !== signature.keyId
  ) {
    throw new Error(
      "bootstrap candidate timestamp or signer binding is invalid",
    );
  }
  // Verify every candidate-bound executable and directory before starting
  // even a version probe or Git process. The exact signed Git path then runs
  // with cloud/backend credentials removed.
  assertBootstrapRuntime(repositoryRoot, candidate.runtime, process.env, {
    runVersionProbes: false,
  });
  if (
    candidate.source.dirty !== false ||
    candidate.source.revision !== capability.sourceRevision ||
    candidate.source.treeDigest !== capability.sourceTreeDigest ||
    candidate.source.treeDigest !== managementSeedTreeDigest(repositoryRoot)
  ) {
    throw new Error(
      "bootstrap candidate does not bind the clean current source",
    );
  }
  const configured = new Map(
    candidate.configuration.map((entry) => [entry.path, entry.sha256]),
  );
  const configPath = safeFile(repositoryRoot, configurationPath);
  const configRelative = path
    .relative(repositoryRoot, configPath)
    .split(path.sep)
    .join("/");
  const expectedConfiguration = [
    configRelative,
    "Pulumi.management.yaml",
  ].sort();
  if (
    configured.size !== expectedConfiguration.length ||
    canonicalJson([...configured.keys()].sort()) !==
      canonicalJson(expectedConfiguration)
  ) {
    throw new Error("bootstrap candidate configuration inventory is not exact");
  }
  for (const [relative, digest] of configured) {
    if (sha256(readFileSync(safeFile(repositoryRoot, relative))) !== digest) {
      throw new Error(`qualified configuration '${relative}' changed`);
    }
  }
  if (
    candidate.build.path !== "dist-management-seed" ||
    directoryDigest(repositoryRoot, candidate.build.path) !==
      candidate.build.treeDigest
  ) {
    throw new Error("bootstrap candidate build changed");
  }
  for (const evidence of [
    candidate.localGateEvidence,
    candidate.releaseEvidence,
  ]) {
    const file = safeFile(repositoryRoot, evidence.path);
    const document = parseObject(file, "qualified evidence");
    if (
      sha256(readFileSync(file)) !== evidence.sha256 ||
      (document.reportDigest ?? document.evidenceDigest) !==
        evidence.evidenceDigest
    ) {
      throw new Error(`qualified evidence '${evidence.path}' changed`);
    }
  }
  validateAdversarialReviewDisposition(repositoryRoot, {
    trustImmutableQualifiedSource: true,
  });
  verifyManagementSeedReleaseEvidence(repositoryRoot, {
    requireClean: false,
    qualifiedRevision: candidate.source.revision,
    releaseEvidencePath: candidate.releaseEvidence.path,
    localGatePath: candidate.localGateEvidence.path,
  });
  assertCredentialedRuntimeToolBindings(candidate);
  return {
    candidate,
    candidatePath,
    awsExecutable: runtimeExecutable(candidate.runtime, "aws"),
  };
}

export function assertCredentialedRuntimeToolBindings(candidate) {
  const versions = new Map(
    candidate.runtime.executables.map(({ name, version }) => [name, version]),
  );
  for (const name of ["aws", "node", "pulumi"]) {
    if (candidate.tools?.[name] !== versions.get(name)) {
      throw new Error(`bootstrap candidate tool '${name}' is inconsistent`);
    }
  }
}

function verifyCandidateSignature(root, candidateDigest, signature) {
  const trust = parseObject(
    safeFile(root, "security/bootstrap-qualification-trust.json"),
    "bootstrap qualification trust root",
  );
  validate(
    root,
    trust,
    "schemas/bootstrap-qualification-trust-v1.schema.json",
    "bootstrap qualification trust root",
  );
  const publicDer = Buffer.from(trust.publicKeySpki, "base64url");
  if (
    trust.configured !== true ||
    trust.algorithm !== "Ed25519" ||
    trust.keyId !== sha256(publicDer) ||
    signature.algorithm !== "Ed25519" ||
    signature.keyId !== trust.keyId
  ) {
    throw new Error("bootstrap candidate signer does not match the trust root");
  }
  const publicKey = createPublicKey({
    key: publicDer,
    format: "der",
    type: "spki",
  });
  if (
    publicKey.asymmetricKeyType !== "ed25519" ||
    !verifySignature(
      null,
      Buffer.from(
        `security.deus.dev/bootstrap-candidate/v1:${candidateDigest}`,
        "utf8",
      ),
      publicKey,
      Buffer.from(signature.value, "base64url"),
    )
  ) {
    throw new Error("bootstrap candidate signature is invalid");
  }
}

function validate(root, value, schemaValue, label) {
  const schema = parseObject(safeFile(root, schemaValue), `${label} schema`);
  const ajv = new Ajv2020({ allErrors: true, strict: true });
  addFormats(ajv);
  const validator = ajv.compile(schema);
  if (!validator(value)) {
    throw new Error(`${label} failed strict schema validation`);
  }
}

function parseObject(file, label) {
  try {
    const value = JSON.parse(readFileSync(file, "utf8"));
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new Error("must be an object");
    }
    return value;
  } catch (error) {
    throw new Error(`${label} is invalid: ${error.message}`);
  }
}

function credentialedCapability(root, candidateDigest) {
  const capability =
    globalThis[Symbol.for("security.deus.dev/credentialed-stage1/v1")];
  if (
    capability?.apiVersion !== "security.deus.dev/credentialed-stage1/v1" ||
    capability.entrypoint !== "access-provisioner" ||
    capability.executionRoot !== root ||
    capability.candidateDigest !== candidateDigest ||
    !/^[a-f0-9]{40}$/.test(capability.sourceRevision ?? "") ||
    !/^[a-f0-9]{64}$/.test(capability.sourceTreeDigest ?? "")
  ) {
    throw new Error(
      "access provisioning requires the installed native launcher and immutable qualified snapshot",
    );
  }
  return capability;
}

function directoryDigest(root, value) {
  const base = realpathSync(path.resolve(root, value));
  const entries = [];
  const walk = (current) => {
    for (const name of readdirSync(current).sort()) {
      const candidate = path.join(current, name);
      const stat = lstatSync(candidate);
      if (stat.isSymbolicLink()) {
        throw new Error("qualified build contains a symbolic link");
      }
      if (stat.isDirectory()) walk(candidate);
      else if (stat.isFile()) {
        entries.push({
          path: path.relative(base, candidate),
          sha256: sha256(readFileSync(candidate)),
        });
      } else {
        throw new Error("qualified build contains a non-file entry");
      }
    }
  };
  walk(base);
  if (entries.length === 0) throw new Error("qualified build is empty");
  return sha256(canonicalJson(entries));
}
