import { createHash, randomBytes, randomInt } from "node:crypto";

const MAX_NUMERIC_CODE_DIGITS = 14;

export interface GeneratedOpaqueToken {
  readonly plain: string;
  readonly digest: string;
}

function requirePositiveByteCount(bytes: number): void {
  if (!Number.isSafeInteger(bytes) || bytes <= 0) {
    throw new RangeError("token byte count must be a positive integer");
  }
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

export function contextualDeviceFingerprint(
  identity: string,
  userAgent: string,
): string {
  return sha256TokenDigest(`${identity}:${userAgent}`);
}

export function stableDeviceFingerprint(deviceId: string): string {
  return sha256TokenDigest(`device:${deviceId}`);
}
