import { OAuthError } from "./types.js";

import type {
  OAuthErrorCode,
  OAuthProvider,
  OAuthRuntime,
  OAuthTokenSet,
} from "./types.js";

export interface ProviderRuntime {
  readonly fetch: typeof globalThis.fetch;
  readonly nowMs: () => number;
}

const MAX_DATE_MS = 8_640_000_000_000_000;

export function providerRuntime(runtime: OAuthRuntime = {}): ProviderRuntime {
  return {
    fetch: runtime.fetch ?? globalThis.fetch,
    nowMs: runtime.nowMs ?? Date.now,
  };
}

export function requireConfig(
  value: string,
  field: string,
  provider: OAuthProvider,
): string {
  if (value.trim() === "") {
    throw new OAuthError(`${field} is required`, provider, "INVALID_CONFIG");
  }
  return value;
}

export async function requireOk(
  response: Response,
  provider: OAuthProvider,
  code: OAuthErrorCode,
  action: string,
): Promise<void> {
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    throw new OAuthError(
      `${action} failed with HTTP ${String(response.status)}`,
      provider,
      code,
      response.status,
    );
  }
}

export async function jsonRecord(
  response: Response,
  provider: OAuthProvider,
  code: OAuthErrorCode = "MALFORMED_RESPONSE",
): Promise<Record<string, unknown>> {
  let data: unknown;
  try {
    data = await response.json();
  } catch {
    throw new OAuthError(
      "Provider returned invalid JSON",
      provider,
      code,
      response.status,
    );
  }
  if (data === null || typeof data !== "object" || Array.isArray(data)) {
    throw new OAuthError(
      "Provider returned an invalid object",
      provider,
      code,
      response.status,
    );
  }
  return data as Record<string, unknown>;
}

export function requiredString(
  record: Record<string, unknown>,
  field: string,
  provider: OAuthProvider,
  code: OAuthErrorCode = "MALFORMED_RESPONSE",
): string {
  const value = record[field];
  if (typeof value !== "string" || value === "") {
    throw new OAuthError(
      `Provider response is missing ${field}`,
      provider,
      code,
    );
  }
  return value;
}

export function optionalString(
  record: Record<string, unknown>,
  field: string,
): string | undefined {
  const value = record[field];
  return typeof value === "string" && value !== "" ? value : undefined;
}

export function optionalNumber(
  record: Record<string, unknown>,
  field: string,
): number | undefined {
  const value = record[field];
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0
    ? value
    : undefined;
}

function optionalDurationSeconds(
  record: Record<string, unknown>,
  field: string,
  provider: OAuthProvider,
  code: OAuthErrorCode,
): number | undefined {
  const value = record[field];
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new OAuthError(
      `Provider response has invalid ${field}`,
      provider,
      code,
    );
  }
  return value;
}

function expirationDate(
  nowMs: number,
  seconds: number | undefined,
  field: string,
  provider: OAuthProvider,
  code: OAuthErrorCode,
): Date | undefined {
  if (seconds === undefined) return undefined;
  const expiresAtMs = nowMs + seconds * 1_000;
  if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs > MAX_DATE_MS) {
    throw new OAuthError(
      `Provider response ${field} exceeds the supported date range`,
      provider,
      code,
    );
  }
  return new Date(expiresAtMs);
}

export function accessToken(tokens: OAuthTokenSet | string): string {
  return typeof tokens === "string" ? tokens : tokens.accessToken;
}

export function tokenSetFromResponse(
  record: Record<string, unknown>,
  provider: OAuthProvider,
  nowMs: number,
  code: OAuthErrorCode,
): OAuthTokenSet {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || nowMs > MAX_DATE_MS) {
    throw new OAuthError(
      "OAuth clock returned an invalid timestamp",
      provider,
      "INVALID_CONFIG",
    );
  }
  const accessTokenValue = requiredString(record, "access_token", provider);
  const tokenType = optionalString(record, "token_type") ?? "Bearer";
  const refreshToken = optionalString(record, "refresh_token");
  const idToken = optionalString(record, "id_token");
  const scope = optionalString(record, "scope");
  const expiresAt = expirationDate(
    nowMs,
    optionalDurationSeconds(record, "expires_in", provider, code),
    "expires_in",
    provider,
    code,
  );
  const refreshTokenExpiresAt = expirationDate(
    nowMs,
    optionalDurationSeconds(
      record,
      "refresh_token_expires_in",
      provider,
      code,
    ),
    "refresh_token_expires_in",
    provider,
    code,
  );

  return {
    accessToken: accessTokenValue,
    tokenType,
    ...(refreshToken === undefined ? {} : { refreshToken }),
    ...(idToken === undefined ? {} : { idToken }),
    ...(scope === undefined ? {} : { scope }),
    ...(expiresAt === undefined ? {} : { expiresAt }),
    ...(refreshTokenExpiresAt === undefined ? {} : { refreshTokenExpiresAt }),
  };
}

export function tokenError(
  record: Record<string, unknown>,
  provider: OAuthProvider,
  code: "TOKEN_EXCHANGE_FAILED" | "TOKEN_REFRESH_FAILED",
): void {
  const error = optionalString(record, "error");
  if (error !== undefined) {
    const description = optionalString(record, "error_description");
    throw new OAuthError(description ?? error, provider, code);
  }
}
