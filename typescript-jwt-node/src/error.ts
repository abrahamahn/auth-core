export interface JwtHeader {
  readonly alg: "HS256";
  readonly typ: "JWT";
}

export interface JwtPayload {
  readonly iat?: number;
  readonly exp?: number;
  readonly [key: string]: unknown;
}

export type JwtSecret = string | Uint8Array;

export interface SignOptions {
  /** Relative lifetime in seconds or as an `s`, `m`, `h`, or `d` duration. */
  readonly expiresIn?: string | number;
  /** Deterministic issued-at override. Omit in production to use the system clock. */
  readonly issuedAtSeconds?: number;
}

export interface VerifyOptions {
  /** Clock skew tolerance in seconds. */
  readonly clockToleranceSeconds?: number;
  /** Deterministic verification-clock override. Omit in production to use the system clock. */
  readonly currentTimeSeconds?: number;
}

export type JwtErrorCode =
  | "INVALID_TOKEN"
  | "INVALID_SIGNATURE"
  | "TOKEN_EXPIRED"
  | "MALFORMED_TOKEN";

export class JwtError extends Error {
  override readonly name = "JwtError";

  constructor(
    message: string,
    readonly code: JwtErrorCode,
  ) {
    super(message);
  }
}

export function requireNonNegativeInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new JwtError(
      `${name} must be a non-negative integer`,
      "INVALID_TOKEN",
    );
  }
  return value;
}

export function nowInSeconds(): number {
  return Math.floor(Date.now() / 1_000);
}

export function secretBytes(secret: JwtSecret): Uint8Array {
  const bytes =
    typeof secret === "string" ? Buffer.from(secret, "utf8") : secret;
  if (bytes.byteLength === 0) {
    throw new JwtError("JWT secret is required", "INVALID_TOKEN");
  }
  return bytes;
}
