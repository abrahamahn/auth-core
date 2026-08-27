import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomInt,
  scryptSync,
} from "node:crypto";

const ENCRYPTION_ALGORITHM = "aes-256-gcm";
const ENCRYPTION_KEY_BYTES = 32;
const IV_BYTES = 12;
const SALT_BYTES = 16;
const AUTH_TAG_BYTES = 16;
const MAX_NUMERIC_CODE_DIGITS = 14;

export interface GeneratedOpaqueToken {
  readonly plain: string;
  readonly digest: string;
}

export function sha256TokenDigest(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

export function generateHexToken(bytes = 32): string {
  requirePositiveByteCount(bytes);
  return randomBytes(bytes).toString("hex");
}

export function generateBase64UrlToken(bytes = 32): string {
  requirePositiveByteCount(bytes);
  return randomBytes(bytes).toString("base64url");
}

export function generateOpaqueToken(bytes = 32): GeneratedOpaqueToken {
  const plain = generateHexToken(bytes);
  return { plain, digest: sha256TokenDigest(plain) };
}

export function generateNumericCode(digits = 6): string {
  if (
    !Number.isSafeInteger(digits) ||
    digits <= 0 ||
    digits > MAX_NUMERIC_CODE_DIGITS
  ) {
    throw new RangeError(
      `numeric-code digits must be an integer from 1 through ${String(MAX_NUMERIC_CODE_DIGITS)}`,
    );
  }
  const max = 10 ** digits;
  return randomInt(0, max).toString().padStart(digits, "0");
}

export function encryptSecret(
  plaintext: string,
  encryptionKey: string,
): string {
  requireEncryptionKey(encryptionKey);
  const salt = randomBytes(SALT_BYTES);
  const key = scryptSync(encryptionKey, salt, ENCRYPTION_KEY_BYTES);
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv(ENCRYPTION_ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_BYTES,
  });
  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return [salt, iv, tag, encrypted]
    .map((value) => value.toString("base64"))
    .join(":");
}

export function decryptSecret(envelope: string, encryptionKey: string): string {
  requireEncryptionKey(encryptionKey);
  const parts = envelope.split(":");
  if (parts.length !== 4) throw new Error("Invalid encrypted secret format");
  const [saltEncoded, ivEncoded, tagEncoded, encryptedEncoded] = parts;
  if (
    saltEncoded === undefined ||
    ivEncoded === undefined ||
    tagEncoded === undefined ||
    encryptedEncoded === undefined
  ) {
    throw new Error("Invalid encrypted secret format");
  }
  const salt = decodeBase64Field(saltEncoded, SALT_BYTES, "salt");
  const iv = decodeBase64Field(ivEncoded, IV_BYTES, "iv");
  const tag = decodeBase64Field(
    tagEncoded,
    AUTH_TAG_BYTES,
    "authentication tag",
  );
  const encrypted = decodeBase64Field(
    encryptedEncoded,
    undefined,
    "ciphertext",
  );
  const key = scryptSync(encryptionKey, salt, ENCRYPTION_KEY_BYTES);
  const decipher = createDecipheriv(ENCRYPTION_ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_BYTES,
  });
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]).toString(
    "utf8",
  );
}

/** Identify the four-part authenticated secret-envelope format. */
export function isSecretEnvelope(value: string): boolean {
  return value.split(":").length === 4;
}

export function contextualDeviceFingerprint(
  identity: string,
  userAgent: string,
): string {
  return sha256TokenDigest(`${identity}:${userAgent}`);
}

export function stableDeviceFingerprint(deviceId: string): string {
  return sha256TokenDigest(`device:${deviceId}`);
}

function requirePositiveByteCount(bytes: number): void {
  if (!Number.isSafeInteger(bytes) || bytes <= 0) {
    throw new RangeError("token byte count must be a positive integer");
  }
}

function requireEncryptionKey(encryptionKey: string): void {
  if (encryptionKey === "") throw new Error("encryption key must not be empty");
}

function decodeBase64Field(
  encoded: string,
  expectedBytes: number | undefined,
  label: string,
): Buffer {
  if (encoded === "") throw new Error(`Invalid encrypted secret ${label}`);
  const decoded = Buffer.from(encoded, "base64");
  if (decoded.toString("base64") !== encoded) {
    throw new Error(`Invalid encrypted secret ${label}`);
  }
  if (expectedBytes !== undefined && decoded.length !== expectedBytes) {
    throw new Error(`Invalid encrypted secret ${label} length`);
  }
  return decoded;
}
