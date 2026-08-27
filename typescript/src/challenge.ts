export interface ExpiringReplayGuardOptions {
  readonly now?: () => number;
}

/** In-memory replay protection for short-lived, uniquely identified challenges. */
export class ExpiringReplayGuard<Key> {
  readonly #expiresAtByKey = new Map<Key, number>();
  readonly #now: () => number;

  public constructor(options: ExpiringReplayGuardOptions = {}) {
    this.#now = options.now ?? Date.now;
  }

  public burn(key: Key, ttlMs: number): void {
    if (!Number.isFinite(ttlMs)) throw new RangeError("ttlMs must be finite");
    const nowMs = this.#readNow();
    this.#sweep(nowMs);
    if (ttlMs <= 0) {
      this.#expiresAtByKey.delete(key);
      return;
    }
    const expiresAtMs = nowMs + ttlMs;
    if (!Number.isFinite(expiresAtMs))
      throw new RangeError("challenge expiry overflow");
    this.#expiresAtByKey.set(key, expiresAtMs);
  }

  public isBurned(key: Key): boolean {
    const nowMs = this.#readNow();
    const expiresAtMs = this.#expiresAtByKey.get(key);
    if (expiresAtMs === undefined) return false;
    if (expiresAtMs <= nowMs) {
      this.#expiresAtByKey.delete(key);
      return false;
    }
    return true;
  }

  public clear(): void {
    this.#expiresAtByKey.clear();
  }

  public get size(): number {
    this.#sweep(this.#readNow());
    return this.#expiresAtByKey.size;
  }

  #readNow(): number {
    const nowMs = this.#now();
    if (!Number.isFinite(nowMs) || nowMs < 0) {
      throw new RangeError("clock must return a non-negative finite timestamp");
    }
    return nowMs;
  }

  #sweep(nowMs: number): void {
    for (const [key, expiresAtMs] of this.#expiresAtByKey) {
      if (expiresAtMs <= nowMs) this.#expiresAtByKey.delete(key);
    }
  }
}
