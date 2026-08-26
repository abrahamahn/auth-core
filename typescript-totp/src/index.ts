import { Secret, TOTP } from 'otpauth';

export type TotpAlgorithm = 'SHA1' | 'SHA256' | 'SHA512';

export interface TotpConfig {
  readonly algorithm: TotpAlgorithm;
  readonly digits: number;
  readonly periodSeconds: number;
}

export const DEFAULT_TOTP_CONFIG = {
  algorithm: 'SHA1',
  digits: 6,
  periodSeconds: 30,
} as const satisfies TotpConfig;

export interface TotpSetupOptions {
  readonly issuer: string;
  readonly label: string;
  readonly secretBytes?: number;
  readonly config?: Partial<TotpConfig>;
}

export interface TotpSetup {
  readonly secretBase32: string;
  readonly otpauthUrl: string;
}

export interface TotpVerificationOptions {
  readonly timestampMs?: number;
  readonly window?: number;
  readonly config?: Partial<TotpConfig>;
}

export interface BackupCodeOptions {
  readonly count?: number;
  readonly bytesPerCode?: number;
  readonly groupSize?: number;
}

export type RandomBytes = (length: number) => Uint8Array;

function resolveConfig(config: Partial<TotpConfig> = {}): TotpConfig {
  const resolved: TotpConfig = { ...DEFAULT_TOTP_CONFIG, ...config };
  if (!Number.isSafeInteger(resolved.digits) || resolved.digits < 6 || resolved.digits > 8) {
    throw new RangeError('TOTP digits must be an integer from 6 through 8');
  }
  if (!Number.isSafeInteger(resolved.periodSeconds) || resolved.periodSeconds <= 0) {
    throw new RangeError('TOTP periodSeconds must be a positive integer');
  }
  return resolved;
}

function createTotp(secretBase32: string, config: TotpConfig, issuer?: string, label?: string): TOTP {
  return new TOTP({
    ...(issuer === undefined ? {} : { issuer }),
    ...(label === undefined ? {} : { label }),
    algorithm: config.algorithm,
    digits: config.digits,
    period: config.periodSeconds,
    secret: Secret.fromBase32(secretBase32),
  });
}

export function createTotpSetup(options: TotpSetupOptions): TotpSetup {
  if (options.issuer.trim() === '') throw new Error('TOTP issuer must not be empty');
  if (options.label.trim() === '') throw new Error('TOTP label must not be empty');
  const secretBytes = options.secretBytes ?? 20;
  if (!Number.isSafeInteger(secretBytes) || secretBytes < 16) {
    throw new RangeError('TOTP secretBytes must be an integer of at least 16');
  }
  const config = resolveConfig(options.config);
  const secret = new Secret({ size: secretBytes });
  const totp = createTotp(secret.base32, config, options.issuer, options.label);
  return { secretBase32: secret.base32, otpauthUrl: totp.toString() };
}

export function createTotpUri(
  secretBase32: string,
  issuer: string,
  label: string,
  config: Partial<TotpConfig> = {},
): string {
  if (issuer.trim() === '') throw new Error('TOTP issuer must not be empty');
  if (label.trim() === '') throw new Error('TOTP label must not be empty');
  return createTotp(secretBase32, resolveConfig(config), issuer, label).toString();
}

export function generateTotpCode(
  secretBase32: string,
  timestampMs: number = Date.now(),
  config: Partial<TotpConfig> = {},
): string {
  if (!Number.isFinite(timestampMs) || timestampMs < 0) {
    throw new RangeError('TOTP timestampMs must be a non-negative finite number');
  }
  return createTotp(secretBase32, resolveConfig(config)).generate({ timestamp: timestampMs });
}

export function verifyTotpCode(
  secretBase32: string,
  code: string,
  options: TotpVerificationOptions = {},
): boolean {
  const window = options.window ?? 0;
  if (!Number.isSafeInteger(window) || window < 0) {
    throw new RangeError('TOTP window must be a non-negative integer');
  }
  const timestampMs = options.timestampMs ?? Date.now();
  if (!Number.isFinite(timestampMs) || timestampMs < 0) {
    throw new RangeError('TOTP timestampMs must be a non-negative finite number');
  }
  const config = resolveConfig(options.config);
  if (!new RegExp(`^\\d{${String(config.digits)}}$`).test(code)) return false;
  return (
    createTotp(secretBase32, config).validate({ token: code, window, timestamp: timestampMs }) !==
    null
  );
}

export function formatBackupCode(randomBytes: Uint8Array, groupSize = 4): string {
  if (randomBytes.length === 0) throw new RangeError('backup-code entropy must not be empty');
  if (!Number.isSafeInteger(groupSize) || groupSize <= 0) {
    throw new RangeError('backup-code groupSize must be a positive integer');
  }
  const encoded = Array.from(randomBytes, (byte) => byte.toString(16).padStart(2, '0'))
    .join('')
    .toUpperCase();
  const groups: string[] = [];
  for (let offset = 0; offset < encoded.length; offset += groupSize) {
    groups.push(encoded.slice(offset, offset + groupSize));
  }
  return groups.join('-');
}

export function createBackupCodes(
  randomBytes: RandomBytes,
  options: BackupCodeOptions = {},
): string[] {
  const count = options.count ?? 10;
  const bytesPerCode = options.bytesPerCode ?? 4;
  const groupSize = options.groupSize ?? 4;
  if (!Number.isSafeInteger(count) || count <= 0) {
    throw new RangeError('backup-code count must be a positive integer');
  }
  if (!Number.isSafeInteger(bytesPerCode) || bytesPerCode <= 0) {
    throw new RangeError('backup-code bytesPerCode must be a positive integer');
  }
  return Array.from({ length: count }, () => {
    const entropy = randomBytes(bytesPerCode);
    if (entropy.length !== bytesPerCode) {
      throw new Error('randomBytes returned an unexpected number of bytes');
    }
    return formatBackupCode(entropy, groupSize);
  });
}
