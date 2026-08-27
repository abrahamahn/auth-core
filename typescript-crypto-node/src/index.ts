import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  randomInt,
  scryptSync,
  timingSafeEqual,
} from "node:crypto";

const ENCRYPTION_ALGORITHM = "aes-256-gcm";
const ENCRYPTION_KEY_BYTES = 32;
const IV_BYTES = 12;
const SALT_BYTES = 16;
const AUTH_TAG_BYTES = 16;
const MAX_NUMERIC_CODE_DIGITS = 14;
const CSRF_ENCRYPTION_CONTEXT = "csrf-encryption-key";
const CSRF_IV_BYTES = 16;

export const CSRF_TOKEN_BYTES = 32;

export interface CsrfValidationOptions {
  readonly secret: string;
  readonly encrypted?: boolean;
  readonly signed?: boolean;
}

export interface CsrfSignatureVerification {
  readonly valid: boolean;
  readonly token: string | null;
}

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

/** Generate an unpadded base64url token suitable for double-submit CSRF protection. */
export function generateCsrfToken(bytes = CSRF_TOKEN_BYTES): string {
  return generateBase64UrlToken(bytes);
}

/** Sign a CSRF token with HMAC-SHA-256 using the existing `token.signature` wire format. */
export function signCsrfToken(token: string, secret: string): string {
  requireSecret(secret);
  const signature = createHmac("sha256", secret)
    .update(token)
    .digest("base64url");
  return `${token}.${signature}`;
}

/** Authenticate and unwrap a signed CSRF token without throwing for untrusted token input. */
export function verifySignedCsrfToken(
  signedToken: string,
  secret: string,
): CsrfSignatureVerification {
  requireSecret(secret);
  const lastDotIndex = signedToken.lastIndexOf(".");
  if (lastDotIndex < 0) return { valid: false, token: null };

  const token = signedToken.slice(0, lastDotIndex);
  const signature = signedToken.slice(lastDotIndex + 1);
  const expected = createHmac("sha256", secret).update(token).digest();

  try {
    const observed = Buffer.from(signature, "base64url");
    if (
      observed.length !== expected.length ||
      !timingSafeEqual(observed, expected)
    ) {
      return { valid: false, token: null };
    }
    return { valid: true, token };
  } catch {
    return { valid: false, token: null };
  }
}

/** Protect a CSRF cookie value with the existing AES-256-GCM envelope wire format. */
export function encryptCsrfToken(token: string, secret: string): string {
  requireSecret(secret);
  const key = deriveCsrfEncryptionKey(secret);
  const iv = randomBytes(CSRF_IV_BYTES);
  const cipher = createCipheriv(ENCRYPTION_ALGORITHM, key, iv, {
    authTagLength: AUTH_TAG_BYTES,
  });
  const encrypted = Buffer.concat([
    cipher.update(token, "utf8"),
    cipher.final(),
  ]);
  return [iv, encrypted, cipher.getAuthTag()]
    .map((value) => value.toString("base64url"))
    .join(".");
}

/** Authenticate and decrypt a CSRF cookie value, returning null for untrusted malformed input. */
export function decryptCsrfToken(
  envelope: string,
  secret: string,
): string | null {
  requireSecret(secret);
  const parts = envelope.split(".");
  if (parts.length !== 3) return null;
  const [ivEncoded, encryptedEncoded, tagEncoded] = parts;
  if (
    ivEncoded === undefined ||
    ivEncoded === "" ||
    encryptedEncoded === undefined ||
    encryptedEncoded === "" ||
    tagEncoded === undefined ||
    tagEncoded === ""
  ) {
    return null;
  }

  try {
    const iv = Buffer.from(ivEncoded, "base64url");
    const encrypted = Buffer.from(encryptedEncoded, "base64url");
    const tag = Buffer.from(tagEncoded, "base64url");
    if (iv.length !== CSRF_IV_BYTES || tag.length !== AUTH_TAG_BYTES)
      return null;
    const decipher = createDecipheriv(
      ENCRYPTION_ALGORITHM,
      deriveCsrfEncryptionKey(secret),
      iv,
      { authTagLength: AUTH_TAG_BYTES },
    );
    decipher.setAuthTag(tag);
    return Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    return null;
  }
}

/** Validate the cookie/request pair used by double-submit CSRF protection. */
export function validateCsrfToken(
  cookieToken: string | undefined,
  requestToken: string | undefined,
  options: CsrfValidationOptions,
): boolean {
  const { secret, encrypted = false, signed = true } = options;
  requireSecret(secret);
  if (
    cookieToken === undefined ||
    cookieToken === "" ||
    requestToken === undefined ||
    requestToken === ""
  ) {
    return false;
  }

  const protectedToken = encrypted
    ? decryptCsrfToken(cookieToken, secret)
    : cookieToken;
  if (protectedToken === null) return false;
  const unwrapped = signed
    ? verifySignedCsrfToken(protectedToken, secret).token
    : protectedToken;
  if (unwrapped === null) return false;

  const observed = Buffer.from(requestToken);
  const expected = Buffer.from(unwrapped);
  return (
    observed.length === expected.length && timingSafeEqual(observed, expected)
  );
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

function requireSecret(secret: string): void {
  if (secret === "") throw new Error("secret must not be empty");
}

function deriveCsrfEncryptionKey(secret: string): Buffer {
  return createHmac("sha256", secret).update(CSRF_ENCRYPTION_CONTEXT).digest();
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
