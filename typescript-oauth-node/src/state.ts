import { randomBytes } from "node:crypto";

export interface OAuthStateEnvelope<TPayload> {
  readonly nonce: string;
  readonly provider: string;
  readonly redirectUri: string;
  readonly createdAtMs: number;
  readonly payload: TPayload;
}

export type OAuthStateErrorCode =
  | "MALFORMED_STATE"
  | "EXPIRED_STATE"
  | "PROTECTION_FAILED";

export class OAuthStateError extends Error {
  override readonly name = "OAuthStateError";

  constructor(
    message: string,
    readonly code: OAuthStateErrorCode,
  ) {
    super(message);
  }
}

export interface OAuthStateProtector {
  readonly protect: (plaintext: string) => string;
  readonly unprotect: (protectedState: string) => string;
}

export interface OAuthStateManagerOptions<TPayload>
  extends OAuthStateProtector {
  readonly maxAgeMs: number;
  readonly nowMs?: () => number;
  readonly nonce?: () => string;
  readonly parsePayload?: (value: unknown) => TPayload;
}

export interface OAuthStateManager<TPayload> {
  create(
    provider: string,
    redirectUri: string,
    payload: TPayload,
  ): OAuthStateEnvelope<TPayload>;
  encode(state: OAuthStateEnvelope<TPayload>): string;
  decode(encoded: string): OAuthStateEnvelope<TPayload>;
}

function validateEnvelope<TPayload>(
  value: unknown,
  parsePayload: (value: unknown) => TPayload,
): OAuthStateEnvelope<TPayload> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new OAuthStateError(
      "OAuth state must be an object",
      "MALFORMED_STATE",
    );
  }
  const record = value as Record<string, unknown>;
  if (
    typeof record["nonce"] !== "string" ||
    record["nonce"] === "" ||
    typeof record["provider"] !== "string" ||
    record["provider"] === "" ||
    typeof record["redirectUri"] !== "string" ||
    record["redirectUri"] === "" ||
    typeof record["createdAtMs"] !== "number" ||
    !Number.isSafeInteger(record["createdAtMs"]) ||
    record["createdAtMs"] < 0
  ) {
    throw new OAuthStateError(
      "OAuth state has invalid fields",
      "MALFORMED_STATE",
    );
  }
  return {
    nonce: record["nonce"],
    provider: record["provider"],
    redirectUri: record["redirectUri"],
    createdAtMs: record["createdAtMs"],
    payload: parsePayload(record["payload"]),
  };
}

export function createOAuthStateManager<TPayload>(
  options: OAuthStateManagerOptions<TPayload>,
): OAuthStateManager<TPayload> {
  if (!Number.isSafeInteger(options.maxAgeMs) || options.maxAgeMs <= 0) {
    throw new OAuthStateError(
      "maxAgeMs must be a positive integer",
      "MALFORMED_STATE",
    );
  }
  const nowMs = options.nowMs ?? Date.now;
  const createNonce = options.nonce ?? (() => randomBytes(32).toString("hex"));
  const parsePayload =
    options.parsePayload ?? ((value: unknown) => value as TPayload);

  return {
    create(provider, redirectUri, payload) {
      if (provider.trim() === "" || redirectUri.trim() === "") {
        throw new OAuthStateError(
          "provider and redirectUri are required",
          "MALFORMED_STATE",
        );
      }
      const nonce = createNonce();
      if (nonce === "") {
        throw new OAuthStateError("nonce must not be empty", "MALFORMED_STATE");
      }
      return { nonce, provider, redirectUri, createdAtMs: nowMs(), payload };
    },

    encode(state) {
      try {
        return options.protect(JSON.stringify(state));
      } catch {
        throw new OAuthStateError(
          "OAuth state protection failed",
          "PROTECTION_FAILED",
        );
      }
    },

    decode(encoded) {
      let state: OAuthStateEnvelope<TPayload>;
      try {
        const plaintext = options.unprotect(encoded);
        state = validateEnvelope(
          JSON.parse(plaintext) as unknown,
          parsePayload,
        );
      } catch (error) {
        if (error instanceof OAuthStateError) throw error;
        throw new OAuthStateError(
          "OAuth state could not be opened",
          "PROTECTION_FAILED",
        );
      }

      const age = nowMs() - state.createdAtMs;
      if (age < 0 || age > options.maxAgeMs) {
        throw new OAuthStateError("OAuth state has expired", "EXPIRED_STATE");
      }
      return state;
    },
  };
}
