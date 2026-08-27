import { describe, expect, it } from "vitest";

import {
  classifyRefreshCredential,
  evaluateSessionBinding,
  isRefreshRetryEligible,
  isSessionIdle,
  selectSessionsForEviction,
  sessionIdleRemainingMs,
  sessionIdleWindowMs,
  sessionSpanMs,
} from "../src/index.js";

const ACTIVE = {
  nowMs: 10_000,
  expiresAtMs: 20_000,
  gracePeriodMs: 1_000,
} as const;

describe("refresh credential decisions", () => {
  it("separates rotation, retry, expiration, and compromise", () => {
    expect(classifyRefreshCredential(ACTIVE)).toEqual({ kind: "rotate" });
    expect(
      classifyRefreshCredential({ ...ACTIVE, rotatedAtMs: 9_500 }),
    ).toEqual({
      kind: "retry-current",
    });
    expect(
      classifyRefreshCredential({ ...ACTIVE, rotatedAtMs: 8_000 }),
    ).toEqual({
      kind: "revoke-family",
      reason: "credential-reuse",
    });
    expect(
      classifyRefreshCredential({ ...ACTIVE, expiresAtMs: 10_000 }),
    ).toEqual({
      kind: "reject",
      reason: "expired",
    });
    expect(
      classifyRefreshCredential({
        ...ACTIVE,
        nowMs: 10_500,
        rotatedAtMs: 9_500,
      }),
    ).toEqual({
      kind: "revoke-family",
      reason: "credential-reuse",
    });
  });

  it("requires the observed credential epoch to survive a retry race", () => {
    expect(
      isRefreshRetryEligible({
        ...ACTIVE,
        rotatedAtMs: 9_500,
        observedCredentialEpoch: 4,
        currentCredentialEpoch: 4,
      }),
    ).toBe(true);
    expect(
      isRefreshRetryEligible({
        ...ACTIVE,
        rotatedAtMs: 9_500,
        observedCredentialEpoch: 4,
        currentCredentialEpoch: 5,
      }),
    ).toBe(false);
  });

  it("preserves optional binding and bounded idle policy", () => {
    expect(evaluateSessionBinding("browser-a", undefined)).toBe("not-checked");
    expect(evaluateSessionBinding("browser-a", "browser-b")).toBe("mismatch");
    expect(
      sessionSpanMs(true, { defaultSpanMs: 1_000, rememberedSpanMs: 5_000 }),
    ).toBe(5_000);
    expect(sessionIdleWindowMs(5_000, 2_000)).toBe(2_000);
    expect(isSessionIdle(7_000, 3_000, 10_000)).toBe(false);
    expect(isSessionIdle(6_999, 3_000, 10_000)).toBe(true);
    expect(sessionIdleRemainingMs(8_000, 3_000, 10_000)).toBe(1_000);
  });

  it("selects only the oldest excess sessions for eviction", () => {
    const sessions = [
      { id: "newest", createdAtMs: 30 },
      { id: "oldest", createdAtMs: 10 },
      { id: "middle", createdAtMs: 20 },
    ];
    expect(
      selectSessionsForEviction(sessions, 2, (session) => session.createdAtMs),
    ).toEqual([sessions[1]]);
  });

  it("rejects invalid numeric policies at the public boundary", () => {
    expect(() =>
      classifyRefreshCredential({ ...ACTIVE, gracePeriodMs: -1 }),
    ).toThrow(RangeError);
    expect(() => sessionIdleWindowMs(Number.NaN, 1_000)).toThrow(RangeError);
    expect(() => selectSessionsForEviction([], 1.5, () => 0)).toThrow(
      RangeError,
    );
  });
});
