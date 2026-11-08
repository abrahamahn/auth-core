import { randomInt, randomUUID } from "node:crypto";

import {
  DEFAULT_ARGON2_CONFIG,
  hashPassword,
  requirePositiveInteger,
  toArgon2Options,
  verifyPassword,
} from "./argon2.js";

import type { Argon2Config } from "./argon2.js";

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
