import argon2 from "argon2";

import type { HashOptions } from "argon2";

export type Argon2Variant = 0 | 1 | 2;

export interface Argon2Config {
  /** 0 = Argon2d, 1 = Argon2i, 2 = Argon2id. */
  readonly type: Argon2Variant;
  /** Memory cost in KiB. */
  readonly memoryCost: number;
  /** Number of iterations. */
  readonly timeCost: number;
  /** Degree of parallelism. */
  readonly parallelism: number;
}

export const DEFAULT_ARGON2_CONFIG: Readonly<Argon2Config> = Object.freeze({
  type: 2,
  memoryCost: 19_456,
  timeCost: 2,
  parallelism: 1,
});

export function requirePositiveInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RangeError(`${name} must be a positive integer`);
  }
}

export function toArgon2Options(config: Argon2Config): HashOptions {
  requirePositiveInteger(config.memoryCost, "memoryCost");
  requirePositiveInteger(config.timeCost, "timeCost");
  requirePositiveInteger(config.parallelism, "parallelism");

  return {
    type: config.type,
    memoryCost: config.memoryCost,
    timeCost: config.timeCost,
    parallelism: config.parallelism,
  };
}

/** Hash a password into a self-describing Argon2 PHC string. */
export async function hashPassword(
  password: string,
  config: Argon2Config = DEFAULT_ARGON2_CONFIG,
): Promise<string> {
  return argon2.hash(password, toArgon2Options(config));
}

/** Verify a password without leaking malformed-hash errors to callers. */
export async function verifyPassword(
  password: string,
  hash: string,
): Promise<boolean> {
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}

/** Determine whether an existing PHC string should be replaced with the configured parameters. */
export function needsRehash(
  hash: string,
  config: Argon2Config = DEFAULT_ARGON2_CONFIG,
): boolean {
  if (!hash.startsWith("$argon2")) return true;

  try {
    return argon2.needsRehash(hash, toArgon2Options(config));
  } catch {
    return true;
  }
}
