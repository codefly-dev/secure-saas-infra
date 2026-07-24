export interface CredentialFreeJsonOptions {
  code: string;
  path: string;
  allowedNullKeys?: readonly string[];
}

const forbiddenCredentialKeys = new Set([
  "apikey",
  "authorization",
  "authtoken",
  "accesstoken",
  "clientsecret",
  "connectionstring",
  "credential",
  "credentials",
  "databaseurl",
  "dbpassword",
  "dsn",
  "masterpassword",
  "passphrase",
  "passwd",
  "password",
  "privatekey",
  "privatekeypem",
  "refreshtoken",
  "secret",
  "secretkey",
  "secretstring",
  "secretvalue",
  "sessiontoken",
  "token",
]);

const credentialValuePatterns = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/,
  /\bAKIA[A-Z0-9]{16}\b/,
  /\bASIA[A-Z0-9]{16}\b/,
  /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/,
  /\bBearer\s+[A-Za-z0-9._~+/-]+=*/i,
  /\bBasic\s+[A-Za-z0-9+/]+=*/i,
  /\bgh[opusr]_[A-Za-z0-9_]{20,}\b/,
  /[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s@]+@/i,
] as const;

const decodedCredentialPatterns = [
  ...credentialValuePatterns,
  /\b(?:password|passwd|secret|token|authorization|api[_-]?key)\s*[:=]/i,
] as const;

export function assertCredentialFreeJson(
  value: unknown,
  options: CredentialFreeJsonOptions,
): void {
  const allowedNullKeys = new Set(
    (options.allowedNullKeys ?? []).map(normalizedCredentialKey),
  );
  visit(value, options.path, options.code, allowedNullKeys);
}

function visit(
  value: unknown,
  path: string,
  code: string,
  allowedNullKeys: ReadonlySet<string>,
): void {
  if (Array.isArray(value)) {
    value.forEach((entry, index) =>
      visit(entry, `${path}[${index}]`, code, allowedNullKeys),
    );
    return;
  }
  if (value !== null && typeof value === "object") {
    const object = value as Record<string, unknown>;
    if (object.kind === "Secret" && object.apiVersion === "v1") {
      deny(code, `${path} must not contain a Kubernetes Secret object`);
    }
    for (const [key, entry] of Object.entries(object)) {
      const normalized = normalizedCredentialKey(key);
      if (
        forbiddenCredentialKeys.has(normalized) &&
        !(entry === null && allowedNullKeys.has(normalized))
      ) {
        deny(code, `${path}.${key} is forbidden credential material`);
      }
      visit(entry, `${path}.${key}`, code, allowedNullKeys);
    }
    return;
  }
  if (typeof value !== "string") return;
  if (/[^\t\n\r\x20-\x7e]/.test(value)) {
    deny(code, `${path} contains control or non-ASCII credential material`);
  }
  if (
    credentialValuePatterns.some((pattern) => pattern.test(value)) ||
    decodedCredential(value)
  ) {
    deny(code, `${path} contains a credential-shaped value`);
  }
}

function decodedCredential(value: string): boolean {
  if (value.length < 16 || value.length > 8192) return false;
  const compact = value.replace(/=+$/, "");
  if (!/^[A-Za-z0-9+/_-]+$/.test(compact)) return false;
  for (const encoding of ["base64", "base64url"] as const) {
    let decoded: string;
    try {
      const bytes = Buffer.from(value, encoding);
      if (bytes.length === 0) continue;
      const canonical = bytes.toString(encoding).replace(/=+$/, "");
      if (canonical !== compact) continue;
      decoded = bytes.toString("utf8");
    } catch {
      continue;
    }
    if (
      !decoded.includes("\ufffd") &&
      decodedCredentialPatterns.some((pattern) => pattern.test(decoded))
    ) {
      return true;
    }
  }
  return false;
}

function normalizedCredentialKey(value: string): string {
  return value.replace(/[^A-Za-z0-9]/g, "").toLowerCase();
}

function deny(code: string, message: string): never {
  throw new Error(`${code}: ${message}`);
}
