import { describe, expect, it } from "vitest";

import { ExpiringReplayGuard } from "../src/challenge.js";

describe("ExpiringReplayGuard", () => {
  it("burns one challenge until its deadline", () => {
    let nowMs = 1_000;
    const guard = new ExpiringReplayGuard<string>({ now: () => nowMs });
    guard.burn("challenge-a", 500);

    expect(guard.isBurned("challenge-a")).toBe(true);
    expect(guard.isBurned("challenge-b")).toBe(false);
    nowMs = 1_500;
    expect(guard.isBurned("challenge-a")).toBe(false);
    expect(guard.size).toBe(0);
  });

  it("does not retain non-positive burns and supports explicit reset", () => {
    const guard = new ExpiringReplayGuard<string>({ now: () => 1_000 });
    guard.burn("expired", 0);
    expect(guard.isBurned("expired")).toBe(false);
    guard.burn("active", 100);
    guard.clear();
    expect(guard.isBurned("active")).toBe(false);
  });

  it("rejects invalid time inputs", () => {
    const guard = new ExpiringReplayGuard<string>();
    expect(() => {
      guard.burn("challenge", Number.NaN);
    }).toThrow("ttlMs must be finite");
    expect(() =>
      new ExpiringReplayGuard({ now: () => Number.NaN }).isBurned("challenge"),
    ).toThrow("clock must return a non-negative finite timestamp");
    expect(() => {
      new ExpiringReplayGuard({ now: () => Number.MAX_VALUE }).burn(
        "challenge",
        Number.MAX_VALUE,
      );
    }).toThrow("challenge expiry overflow");
  });
});
