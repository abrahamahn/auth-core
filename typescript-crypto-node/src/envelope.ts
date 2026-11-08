import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  scryptSync,
} from "node:crypto";

const ENCRYPTION_ALGORITHM = "aes-256-gcm";
const ENCRYPTION_KEY_BYTES = 32;
const IV_BYTES = 12;
const SALT_BYTES = 16;
const AUTH_TAG_BYTES = 16;

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
