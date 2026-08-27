import { randomInt, randomUUID } from "node:crypto";

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

function requirePositiveInteger(value: number, name: string): void {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RangeError(`${name} must be a positive integer`);
  }
}

function toArgon2Options(config: Argon2Config): HashOptions {
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

export interface DummyHashPoolOptions {
  readonly config?: Argon2Config;
  readonly size?: number;
}

/**
 * Pre-computed Argon2 hashes used to equalize unknown-account password verification.
 *
 * Each instance owns its pool so applications and tests do not need to share mutable global state.
 */
export class DummyHashPool {
  readonly #config: Argon2Config;
  readonly #size: number;
  #hashes: string[] = [];
  #initialization: Promise<void> | undefined;

  constructor(options: DummyHashPoolOptions = {}) {
    this.#config = options.config ?? DEFAULT_ARGON2_CONFIG;
    this.#size = options.size ?? 10;
    requirePositiveInteger(this.#size, "size");
    toArgon2Options(this.#config);
  }

  /** Initialize at most once, including when several startup paths call concurrently. */
  async initialize(): Promise<void> {
    if (this.isInitialized()) return;
    if (this.#initialization !== undefined) return this.#initialization;

    this.#initialization = Promise.all(
      Array.from({ length: this.#size }, (_, index) =>
        hashPassword(
          `auth-core-dummy-${String(index)}-${randomUUID()}-${randomUUID()}`,
          this.#config,
        ),
      ),
    )
      .then((hashes) => {
        this.#hashes = hashes;
      })
      .finally(() => {
        this.#initialization = undefined;
      });

    return this.#initialization;
  }

  isInitialized(): boolean {
    return this.#hashes.length === this.#size;
  }

  reset(): void {
    this.#hashes = [];
    this.#initialization = undefined;
  }

  async #getHash(): Promise<string> {
    if (this.#hashes.length > 0) {
      const selected = this.#hashes[randomInt(this.#hashes.length)];
      if (selected !== undefined) return selected;
    }

    return hashPassword(
      `auth-core-fallback-${randomUUID()}-${randomUUID()}`,
      this.#config,
    );
  }

  /** Always perform Argon2 verification, even when no account hash exists. */
  async verify(
    password: string,
    hash: string | null | undefined,
  ): Promise<boolean> {
    const hasHash = hash !== undefined && hash !== null && hash !== "";
    const hashToVerify = hasHash ? hash : await this.#getHash();
    const valid = await verifyPassword(password, hashToVerify);
    return hasHash && valid;
  }
}

let defaultDummyHashPool = new DummyHashPool();

/** Compatibility singleton for applications that prefer process-wide startup initialization. */
export async function initDummyHashPool(
  config: Argon2Config = DEFAULT_ARGON2_CONFIG,
): Promise<void> {
  if (
    config !== DEFAULT_ARGON2_CONFIG &&
    !defaultDummyHashPool.isInitialized()
  ) {
    defaultDummyHashPool = new DummyHashPool({ config });
  }
  await defaultDummyHashPool.initialize();
}

export function isDummyHashPoolInitialized(): boolean {
  return defaultDummyHashPool.isInitialized();
}

export function resetDummyHashPool(): void {
  defaultDummyHashPool.reset();
}

export async function verifyPasswordSafe(
  password: string,
  hash: string | null | undefined,
): Promise<boolean> {
  return defaultDummyHashPool.verify(password, hash);
}
