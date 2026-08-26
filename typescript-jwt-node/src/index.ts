import { createHmac, timingSafeEqual } from 'node:crypto';

export interface JwtHeader {
  readonly alg: 'HS256';
  readonly typ: 'JWT';
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
  | 'INVALID_TOKEN'
  | 'INVALID_SIGNATURE'
  | 'TOKEN_EXPIRED'
  | 'MALFORMED_TOKEN';

export class JwtError extends Error {
  override readonly name = 'JwtError';

  constructor(
    message: string,
    readonly code: JwtErrorCode,
  ) {
    super(message);
  }
}

const HEADER: JwtHeader = Object.freeze({ alg: 'HS256', typ: 'JWT' });
const DURATION_MULTIPLIERS: Readonly<Record<string, number>> = Object.freeze({
  s: 1,
  m: 60,
  h: 3_600,
  d: 86_400,
});

function requireNonNegativeInteger(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new JwtError(`${name} must be a non-negative integer`, 'INVALID_TOKEN');
  }
  return value;
}

function nowInSeconds(): number {
  return Math.floor(Date.now() / 1_000);
}

function secretBytes(secret: JwtSecret): Uint8Array {
  const bytes = typeof secret === 'string' ? Buffer.from(secret, 'utf8') : secret;
  if (bytes.byteLength === 0) {
    throw new JwtError('JWT secret is required', 'INVALID_TOKEN');
  }
  return bytes;
}

function parseExpiration(expiration: string | number): number {
  if (typeof expiration === 'number') {
    return requireNonNegativeInteger(expiration, 'JWT expiration');
  }

  const match = /^(\d+)([smhd])$/.exec(expiration);
  if (match?.[1] === undefined || match[2] === undefined) {
    throw new JwtError(`Invalid expiration format: ${expiration}`, 'INVALID_TOKEN');
  }

  const value = Number(match[1]);
  const multiplier = DURATION_MULTIPLIERS[match[2]];
  if (multiplier === undefined || !Number.isSafeInteger(value * multiplier)) {
    throw new JwtError(`Invalid expiration format: ${expiration}`, 'INVALID_TOKEN');
  }
  return value * multiplier;
}

function base64UrlEncode(input: string): string {
  return Buffer.from(input, 'utf8').toString('base64url');
}

function base64UrlDecode(input: string): string {
  if (!/^[A-Za-z0-9_-]+$/.test(input)) {
    throw new Error('invalid base64url');
  }
  return Buffer.from(input, 'base64url').toString('utf8');
}

function encodeJson(value: unknown): string {
  try {
    const encoded = JSON.stringify(value);
    return base64UrlEncode(encoded);
  } catch {
    throw new JwtError('Malformed token payload', 'MALFORMED_TOKEN');
  }
}

function signInput(input: string, secret: JwtSecret): string {
  return createHmac('sha256', secretBytes(secret)).update(input).digest('base64url');
}

function safeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, 'utf8');
  const rightBytes = Buffer.from(right, 'utf8');
  const length = Math.max(leftBytes.length, rightBytes.length);
  const paddedLeft = Buffer.alloc(length);
  const paddedRight = Buffer.alloc(length);
  leftBytes.copy(paddedLeft);
  rightBytes.copy(paddedRight);
  return leftBytes.length === rightBytes.length && timingSafeEqual(paddedLeft, paddedRight);
}

function parseHeader(encodedHeader: string): JwtHeader {
  let header: unknown;
  try {
    header = JSON.parse(base64UrlDecode(encodedHeader)) as unknown;
  } catch {
    throw new JwtError('Invalid header', 'MALFORMED_TOKEN');
  }

  if (header === null || typeof header !== 'object' || Array.isArray(header)) {
    throw new JwtError('Invalid header', 'MALFORMED_TOKEN');
  }

  const record = header as Record<string, unknown>;
  if (record['alg'] !== 'HS256' || record['typ'] !== 'JWT') {
    throw new JwtError('Algorithm not supported', 'INVALID_TOKEN');
  }
  return HEADER;
}

function parsePayload(encodedPayload: string): JwtPayload {
  try {
    const parsed = JSON.parse(base64UrlDecode(encodedPayload)) as unknown;
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new JwtError('Malformed token payload', 'MALFORMED_TOKEN');
    }
    return parsed as JwtPayload;
  } catch (error) {
    if (error instanceof JwtError) throw error;
    throw new JwtError('Malformed token payload', 'MALFORMED_TOKEN');
  }
}

function validateExpiration(payload: JwtPayload, options: VerifyOptions): void {
  if (payload.exp === undefined) return;
  if (!Number.isSafeInteger(payload.exp)) {
    throw new JwtError('Malformed token payload', 'MALFORMED_TOKEN');
  }

  const currentTime = requireNonNegativeInteger(
    options.currentTimeSeconds ?? nowInSeconds(),
    'currentTimeSeconds',
  );
  const tolerance = requireNonNegativeInteger(
    options.clockToleranceSeconds ?? 0,
    'clockToleranceSeconds',
  );
  if (currentTime >= payload.exp + tolerance) {
    throw new JwtError('Token has expired', 'TOKEN_EXPIRED');
  }
}

/** Sign an object payload using HS256. */
export function sign(payload: object, secret: JwtSecret, options: SignOptions = {}): string {
  const unknownPayload: unknown = payload;
  if (unknownPayload === null || typeof unknownPayload !== 'object' || Array.isArray(unknownPayload)) {
    throw new JwtError('Malformed token payload', 'MALFORMED_TOKEN');
  }
  secretBytes(secret);

  const issuedAt = requireNonNegativeInteger(
    options.issuedAtSeconds ?? nowInSeconds(),
    'issuedAtSeconds',
  );
  const tokenPayload: Record<string, unknown> = { ...payload, iat: issuedAt };
  if (options.expiresIn !== undefined) {
    tokenPayload['exp'] = issuedAt + parseExpiration(options.expiresIn);
  }
  if (tokenPayload['exp'] !== undefined && !Number.isSafeInteger(tokenPayload['exp'])) {
    throw new JwtError('Malformed token payload', 'MALFORMED_TOKEN');
  }

  const encodedHeader = encodeJson(HEADER);
  const encodedPayload = encodeJson(tokenPayload);
  const input = `${encodedHeader}.${encodedPayload}`;
  return `${input}.${signInput(input, secret)}`;
}

/** Verify an HS256 JWT and return its object payload. */
export function verify(
  token: string,
  secret: JwtSecret,
  options: VerifyOptions = {},
): JwtPayload {
  if (typeof token !== 'string') {
    throw new JwtError('Token must be a string', 'INVALID_TOKEN');
  }
  secretBytes(secret);

  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part) => part === '')) {
    throw new JwtError('Invalid token format', 'MALFORMED_TOKEN');
  }
  const [encodedHeader, encodedPayload, signature] = parts as [string, string, string];

  parseHeader(encodedHeader);
  const expected = signInput(`${encodedHeader}.${encodedPayload}`, secret);
  if (!safeEqual(signature, expected)) {
    throw new JwtError('Invalid signature', 'INVALID_SIGNATURE');
  }

  const payload = parsePayload(encodedPayload);
  validateExpiration(payload, options);
  return payload;
}

/** Decode a JWT payload without verifying it. Never authorize from this result. */
export function decode(token: string): JwtPayload | null {
  try {
    const parts = token.split('.');
    const encodedPayload = parts[1];
    if (parts.length !== 3 || encodedPayload === undefined || encodedPayload === '') return null;
    return parsePayload(encodedPayload);
  } catch {
    return null;
  }
}

export interface JwtRotationConfig {
  readonly secret: JwtSecret;
  readonly previousSecret?: JwtSecret;
}

export interface RotatingJwtOptions extends SignOptions {
  readonly config?: JwtRotationConfig;
}

export type UsedJwtSecret = 'current' | 'previous' | 'none';

export interface TokenSecretCheck {
  readonly isValid: boolean;
  readonly usedSecret: UsedJwtSecret;
  readonly error?: JwtError;
}

function hasSecret(secret: JwtSecret | undefined): secret is JwtSecret {
  return secret !== undefined && (typeof secret === 'string' ? secret !== '' : secret.byteLength > 0);
}

/** Sign only with the current secret. */
export function signWithRotation(
  payload: object,
  config: JwtRotationConfig,
  options?: SignOptions,
): string {
  return sign(payload, config.secret, options);
}

/** Verify with the current secret, falling back only after a signature mismatch. */
export function verifyWithRotation(
  token: string,
  config: JwtRotationConfig,
  options?: VerifyOptions,
): JwtPayload {
  try {
    return verify(token, config.secret, options);
  } catch (currentError) {
    if (
      currentError instanceof JwtError &&
      currentError.code === 'INVALID_SIGNATURE' &&
      hasSecret(config.previousSecret)
    ) {
      try {
        return verify(token, config.previousSecret, options);
      } catch {
        throw currentError;
      }
    }
    throw currentError;
  }
}

/** Report which configured secret verifies a token. */
export function checkTokenSecret(
  token: string,
  config: JwtRotationConfig,
  options?: VerifyOptions,
): TokenSecretCheck {
  try {
    verify(token, config.secret, options);
    return { isValid: true, usedSecret: 'current' };
  } catch (currentError) {
    if (
      currentError instanceof JwtError &&
      currentError.code === 'INVALID_SIGNATURE' &&
      hasSecret(config.previousSecret)
    ) {
      try {
        verify(token, config.previousSecret, options);
        return { isValid: true, usedSecret: 'previous' };
      } catch {
        // Preserve the current-secret error below.
      }
    }
    return currentError instanceof JwtError
      ? { isValid: false, usedSecret: 'none', error: currentError }
      : { isValid: false, usedSecret: 'none' };
  }
}

export interface JwtRotationHandler {
  sign(payload: object, options?: SignOptions): string;
  verify(token: string, options?: VerifyOptions): JwtPayload;
  checkSecret(token: string, options?: VerifyOptions): TokenSecretCheck;
  isRotating(): boolean;
  getConfig(): { readonly hasSecret: boolean; readonly hasPreviousSecret: boolean };
}

/** Bind immutable key-rotation configuration to a small signing and verification facade. */
export function createJwtRotationHandler(config: JwtRotationConfig): JwtRotationHandler {
  return {
    sign: (payload, options) => signWithRotation(payload, config, options),
    verify: (token, options) => verifyWithRotation(token, config, options),
    checkSecret: (token, options) => checkTokenSecret(token, config, options),
    isRotating: () => hasSecret(config.previousSecret),
    getConfig: () => ({
      hasSecret: hasSecret(config.secret),
      hasPreviousSecret: hasSecret(config.previousSecret),
    }),
  };
}
