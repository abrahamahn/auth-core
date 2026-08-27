import { describe, expect, it } from "vitest";

import {
  createAuthAuditEvent,
  isSensitiveAuthAuditMetadataKey,
} from "../src/index.js";

describe("authentication audit events", () => {
  it("creates immutable typed events with nested JSON metadata", () => {
    const event = createAuthAuditEvent({
      type: "oauth_login_success",
      severity: "low",
      outcome: "success",
      occurredAtMs: 10_000,
      subjectId: "user-1",
      factor: "oauth",
      metadata: { provider: "github", context: { isNewUser: false } },
    });

    expect(event.metadata).toEqual({
      provider: "github",
      context: { isNewUser: false },
    });
    expect(Object.isFrozen(event)).toBe(true);
    expect(Object.isFrozen(event.metadata)).toBe(true);
    expect(Object.isFrozen(event.metadata?.["context"])).toBe(true);
  });

  it("rejects secret-bearing keys at every nesting level", () => {
    expect(isSensitiveAuthAuditMetadataKey("refresh_token")).toBe(true);
    expect(isSensitiveAuthAuditMetadataKey("tokenCount")).toBe(false);
    expect(() =>
      createAuthAuditEvent({
        type: "oauth_login_failure",
        severity: "high",
        outcome: "failure",
        occurredAtMs: 10_000,
        metadata: { provider: "github", request: { authorization: "secret" } },
      }),
    ).toThrow(/not permitted/u);
  });

  it("rejects non-JSON metadata without including its value in the error", () => {
    expect(() =>
      createAuthAuditEvent({
        type: "suspicious_login",
        severity: "high",
        outcome: "denied",
        occurredAtMs: 10_000,
        metadata: { invalid: Number.NaN },
      }),
    ).toThrow(/finite/u);
  });
});
