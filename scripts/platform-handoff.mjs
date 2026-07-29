import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import { lstatSync, readFileSync, realpathSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";

const schemaPath = fileURLToPath(
  new URL("../schemas/platform-iac-handoff-v1.schema.json", import.meta.url),
);
const schema = parseJson(readFileSync(schemaPath, "utf8"), schemaPath);
const ajv = new Ajv2020({
  allErrors: true,
  allowUnionTypes: false,
  strict: true,
  validateFormats: true,
});
addFormats(ajv);
const validate = ajv.compile(schema);

export function createPlatformHandoff(stackOutputs, privateKeySource) {
  const candidate = stackOutputs?.platformIacHandoff;
  if (!isObject(candidate) || !isObject(candidate.cluster)) {
    fail(
      "stack outputs must contain one platformIacHandoff object with cluster outputs.",
    );
  }
  const { certificateAuthority, ...cluster } = candidate.cluster;
  if (
    !isObject(certificateAuthority) ||
    Object.keys(certificateAuthority).length !== 1 ||
    typeof certificateAuthority.data !== "string"
  ) {
    fail(
      "platformIacHandoff.cluster.certificateAuthority must contain only base64 data.",
    );
  }
  const certificateAuthorityBytes = decodeBase64(
    certificateAuthority.data,
    "platformIacHandoff.cluster.certificateAuthority.data",
  );
  const spec = {
    ...candidate,
    cluster: {
      ...cluster,
      certificateAuthorityReference: `sha256:${sha256(
        certificateAuthorityBytes,
      )}`,
    },
  };
  const privateKey = createPrivateKey(privateKeySource);
  assertP256Key(privateKey, "handoff signing key");
  const publicKey = createPublicKey(privateKey);
  const keyId = sha256(publicKey.export({ type: "spki", format: "der" }));
  const canonicalSpec = canonicalJson(spec);
  const handoff = {
    apiVersion: "infrastructure.deus.dev/platform-iac-handoff/v1",
    kind: "PlatformIacHandoff",
    specDigest: sha256(canonicalSpec),
    spec,
    signature: {
      algorithm: "ecdsa-p256-sha256",
      keyId,
      publicKeyReference: `key-id://sha256/${keyId}`,
      value: sign("sha256", Buffer.from(canonicalSpec), privateKey).toString(
        "base64",
      ),
    },
  };
  validateHandoffDocument(handoff);
  assertSignatureIdentity(handoff, publicKey);
  return handoff;
}

export function verifyPlatformHandoff(handoffFile, publicKeyFile) {
  const handoffPath = regularFile(handoffFile, "handoff");
  const publicKeyPath = regularFile(publicKeyFile, "public key");
  const handoff = parseJson(readFileSync(handoffPath, "utf8"), handoffPath);
  const publicKey = createPublicKey(readFileSync(publicKeyPath));
  verifyPlatformHandoffDocument(handoff, publicKey);
  return handoff;
}

function verifyPlatformHandoffDocument(handoff, publicKey) {
  validateHandoffDocument(handoff);
  assertP256Key(publicKey, "handoff trust key");
  assertSignatureIdentity(handoff, publicKey);
  const canonicalSpec = canonicalJson(handoff.spec);
  if (
    !verify(
      "sha256",
      Buffer.from(canonicalSpec),
      publicKey,
      Buffer.from(handoff.signature.value, "base64"),
    )
  ) {
    fail("handoff signature verification failed.");
  }
}

function validateHandoffDocument(handoff) {
  if (!validate(handoff)) {
    fail(
      `schema validation failed:\n${(validate.errors ?? [])
        .map((error) => `- ${error.instancePath || "/"} ${error.message}`)
        .join("\n")}`,
    );
  }
  assertCredentialFree(handoff);
  assertBindings(handoff.spec);
  const canonicalSpec = canonicalJson(handoff.spec);
  if (handoff.specDigest !== sha256(canonicalSpec)) {
    fail("specDigest does not bind the canonical handoff spec.");
  }
}

export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${canonicalJson(entry)}`)
      .join(",")}}`;
  }
  return JSON.stringify(value);
}

export function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

export function regularFile(value, label) {
  const candidate = path.resolve(value);
  const stat = lstatSync(candidate);
  if (!stat.isFile() || stat.isSymbolicLink()) {
    fail(`${label} must be a regular non-symlink file.`);
  }
  return realpathSync(candidate);
}

function assertSignatureIdentity(handoff, publicKey) {
  const keyId = sha256(publicKey.export({ type: "spki", format: "der" }));
  if (handoff.signature.keyId !== keyId) {
    fail("signature keyId does not match the reviewed public key.");
  }
  if (handoff.signature.publicKeyReference !== `key-id://sha256/${keyId}`) {
    fail("signature publicKeyReference does not match signature keyId.");
  }
}

function assertP256Key(key, label) {
  if (
    key.asymmetricKeyType !== "ec" ||
    key.asymmetricKeyDetails?.namedCurve !== "prime256v1"
  ) {
    fail(`${label} must be ECDSA P-256.`);
  }
}

function assertBindings(spec) {
  const { role, name } = spec.cluster;
  if (!name.startsWith(`${role}-`)) {
    fail("cluster name does not match cluster role.");
  }
  const entrypoint =
    /^gitops\/bootstrap\/argocd\/overlays\/(dev|staging|production)\/(platform|execution)$/.exec(
      spec.gitops.bootstrapEntrypoint,
    );
  const expectedEnvironment = name.endsWith("-prod")
    ? "production"
    : name.split("-").at(-1);
  if (
    !entrypoint ||
    entrypoint[1] !== expectedEnvironment ||
    entrypoint[2] !== role
  ) {
    fail("GitOps entrypoint does not match cluster environment and role.");
  }
  const endpoint = new URL(spec.cluster.endpoint);
  if (
    endpoint.protocol !== "https:" ||
    endpoint.username ||
    endpoint.password ||
    endpoint.search ||
    endpoint.hash ||
    endpoint.pathname !== "/"
  ) {
    fail("cluster endpoint must be one credential-free HTTPS origin.");
  }
  const { accountId, region, clusterArn, secretsEncryptionKeyArn } =
    spec.cloudResources;
  const cluster = parseArn(
    clusterArn,
    /^arn:(aws|aws-us-gov|aws-cn):eks:([^:]+):(\d{12}):cluster\/([^/]+)$/,
    "EKS cluster",
  );
  const encryptionKey = parseArn(
    secretsEncryptionKeyArn,
    /^arn:(aws|aws-us-gov|aws-cn):kms:([^:]+):(\d{12}):key\/([A-Za-z0-9-]+)$/,
    "KMS key",
  );
  const principal = parseArn(
    spec.bootstrapIdentity.principalArn,
    /^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role\/([A-Za-z0-9+=,.@_/-]+)$/,
    "bootstrap role",
  );
  const partition = partitionForRegion(region);
  if (
    cluster[1] !== partition ||
    encryptionKey[1] !== partition ||
    principal[1] !== partition ||
    cluster[2] !== region ||
    encryptionKey[2] !== region ||
    cluster[3] !== accountId ||
    encryptionKey[3] !== accountId ||
    principal[2] !== accountId ||
    cluster[4] !== name
  ) {
    fail("cloud resource and bootstrap identity references cross boundaries.");
  }
}

function parseArn(value, pattern, label) {
  const match = pattern.exec(value);
  if (!match) fail(`${label} ARN is invalid.`);
  return match;
}

function partitionForRegion(region) {
  if (region.startsWith("us-gov-")) return "aws-us-gov";
  if (region.startsWith("cn-")) return "aws-cn";
  return "aws";
}

function assertCredentialFree(value, currentPath = "handoff") {
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      assertCredentialFree(entry, `${currentPath}[${index}]`),
    );
    return;
  }
  if (value === null || typeof value !== "object") {
    if (
      typeof value === "string" &&
      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/.test(value)
    ) {
      fail(`${currentPath} contains private key material.`);
    }
    if (typeof value === "string" && /^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
      const reference = new URL(value);
      if (
        reference.username ||
        reference.password ||
        reference.search ||
        reference.hash
      ) {
        fail(`${currentPath} contains credentials or mutable URL parameters.`);
      }
    }
    return;
  }
  for (const [key, entry] of Object.entries(value)) {
    if (
      /(?:password|private.?key|client.?secret|access.?token|refresh.?token|credential)$/i.test(
        key,
      )
    ) {
      fail(`${currentPath}.${key} is credential-bearing.`);
    }
    assertCredentialFree(entry, `${currentPath}.${key}`);
  }
}

function decodeBase64(value, label) {
  if (
    value.length === 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(
      value,
    )
  ) {
    fail(`${label} must be canonical base64.`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.length === 0 || decoded.toString("base64") !== value) {
    fail(`${label} must be canonical base64.`);
  }
  return decoded;
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function parseJson(source, file) {
  try {
    return JSON.parse(source);
  } catch (error) {
    fail(`${file} is not valid JSON: ${error.message}`);
  }
}

function fail(message) {
  throw new Error(`PLATFORM_HANDOFF_INVALID ${message}`);
}
