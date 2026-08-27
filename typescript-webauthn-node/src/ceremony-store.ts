import { randomUUID } from "node:crypto";

import { AuthWebAuthnError } from "./error.js";

export type WebAuthnCeremonyKind = "registration" | "authentication";

export interface WebAuthnCeremony {
  readonly kind: WebAuthnCeremonyKind;
  readonly challenge: string;
  readonly expiresAtMs: number;
  readonly subjectId?: string | undefined;
}

export interface PutWebAuthnCeremonyInput {
  readonly kind: WebAuthnCeremonyKind;
  readonly challenge: string;
  readonly subjectId?: string | undefined;
}

export interface WebAuthnCeremonyStore {
  put(key: string, ceremony: PutWebAuthnCeremonyInput): void;
  consume(key: string, expectedKind: WebAuthnCeremonyKind): WebAuthnCeremony;
}

export interface InMemoryWebAuthnCeremonyStoreOptions {
  readonly ttlMs: number;
  readonly now?: (() => number) | undefined;
}

/**
 * Single-process ceremony store for tests and simple deployments.
 *
 * Distributed applications should implement `WebAuthnCeremonyStore` with an atomic, expiring
 * shared store. A ceremony is deleted before it is returned so every verification attempt is
 * single-use, including failed attempts.
 */
export class InMemoryWebAuthnCeremonyStore implements WebAuthnCeremonyStore {
  readonly #entries = new Map<string, WebAuthnCeremony>();
  readonly #ttlMs: number;
  readonly #now: () => number;

  constructor(options: InMemoryWebAuthnCeremonyStoreOptions) {
    if (!Number.isSafeInteger(options.ttlMs) || options.ttlMs <= 0) {
      throw new RangeError("ttlMs must be a positive safe integer");
    }
    this.#ttlMs = options.ttlMs;
    this.#now = options.now ?? Date.now;
  }

  put(key: string, ceremony: PutWebAuthnCeremonyInput): void {
    if (key === "") throw new RangeError("ceremony key must not be empty");
    if (ceremony.challenge === "")
      throw new RangeError("ceremony challenge must not be empty");
    const nowMs = this.#now();
    this.prune(nowMs);
    this.#entries.set(
      key,
      Object.freeze({
        ...ceremony,
        expiresAtMs: nowMs + this.#ttlMs,
      }),
    );
  }

  consume(key: string, expectedKind: WebAuthnCeremonyKind): WebAuthnCeremony {
    const ceremony = this.#entries.get(key);
    this.#entries.delete(key);
    if (ceremony === undefined) {
      throw new AuthWebAuthnError(
        "ceremony-missing",
        "WebAuthn ceremony was not found",
      );
    }
    if (ceremony.expiresAtMs <= this.#now()) {
      throw new AuthWebAuthnError(
        "ceremony-expired",
        "WebAuthn ceremony has expired",
      );
    }
    if (ceremony.kind !== expectedKind) {
      throw new AuthWebAuthnError(
        "ceremony-mismatch",
        "WebAuthn ceremony kind does not match",
      );
    }
    return ceremony;
  }

  prune(nowMs: number = this.#now()): number {
    let removed = 0;
    for (const [key, ceremony] of this.#entries) {
      if (ceremony.expiresAtMs <= nowMs) {
        this.#entries.delete(key);
        removed += 1;
      }
    }
    return removed;
  }

  clear(): void {
    this.#entries.clear();
  }

  get size(): number {
    return this.#entries.size;
  }
}

export function createWebAuthnCeremonyKey(kind: WebAuthnCeremonyKind): string {
  return `${kind}:${randomUUID()}`;
}
