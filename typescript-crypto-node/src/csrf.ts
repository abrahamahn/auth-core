import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";

import { generateBase64UrlToken } from "./token.js";

const ENCRYPTION_ALGORITHM = "aes-256-gcm";
const AUTH_TAG_BYTES = 16;
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

function requireSecret(secret: string): void {
  if (secret === "") throw new Error("secret must not be empty");
}

function deriveCsrfEncryptionKey(secret: string): Buffer {
  return createHmac("sha256", secret).update(CSRF_ENCRYPTION_CONTEXT).digest();
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
