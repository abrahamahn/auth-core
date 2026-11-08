import {
  jsonRecord,
  providerRuntime,
  requestFormTokens,
  requireConfig,
  requireOk,
} from "../http.js";
import { OAuthError } from "../types.js";
import {
  generateAppleClientSecret,
  parseJwk,
  verifyAppleIdentityToken,
} from "./apple-jwt.js";

import type {
  AuthorizationRequestOptions,
  OAuthProviderClient,
  OAuthRuntime,
  OAuthTokenSet,
  OAuthUserInfo,
  TokenExchangeOptions,
} from "../types.js";
import type { AppleJwk } from "./apple-jwt.js";

const AUTH_URL = "https://appleid.apple.com/auth/authorize";
const TOKEN_URL = "https://appleid.apple.com/auth/token";
const KEYS_URL = "https://appleid.apple.com/auth/keys";
const DEFAULT_SCOPES = ["email", "name"] as const;
const DEFAULT_KEYS_CACHE_TTL_MS = 60 * 60 * 1_000;
const DEFAULT_CLOCK_TOLERANCE_SECONDS = 300;

export interface AppleProviderConfig extends OAuthRuntime {
  readonly clientId: string;
  readonly teamId: string;
  readonly keyId: string;
  readonly privateKey: string;
  readonly scopes?: readonly string[];
  readonly keysCacheTtlMs?: number;
  readonly clockToleranceSeconds?: number;
}

export function createAppleProvider(
  config: AppleProviderConfig,
): OAuthProviderClient {
  const provider = "apple";
  const clientId = requireConfig(config.clientId, "clientId", provider);
  const teamId = requireConfig(config.teamId, "teamId", provider);
  const keyId = requireConfig(config.keyId, "keyId", provider);
  const privateKey = requireConfig(config.privateKey, "privateKey", provider);
  const runtime = providerRuntime(config);
  const scopes = config.scopes ?? DEFAULT_SCOPES;
  const cacheTtlMs = config.keysCacheTtlMs ?? DEFAULT_KEYS_CACHE_TTL_MS;
  const toleranceSeconds =
    config.clockToleranceSeconds ?? DEFAULT_CLOCK_TOLERANCE_SECONDS;
  if (
    scopes.length === 0 ||
    !Number.isSafeInteger(cacheTtlMs) ||
    cacheTtlMs <= 0 ||
    !Number.isSafeInteger(toleranceSeconds) ||
    toleranceSeconds < 0
  ) {
    throw new OAuthError(
      "Apple provider options are invalid",
      provider,
      "INVALID_CONFIG",
    );
  }

  let keysCache:
    | { readonly keys: readonly AppleJwk[]; readonly fetchedAtMs: number }
    | undefined;

  async function fetchKeys(force: boolean): Promise<readonly AppleJwk[]> {
    const now = runtime.nowMs();
    if (
      !force &&
      keysCache !== undefined &&
      now - keysCache.fetchedAtMs < cacheTtlMs
    ) {
      return keysCache.keys;
    }
    const response = await runtime.fetch(KEYS_URL);
    await requireOk(
      response,
      provider,
      "KEYS_FETCH_FAILED",
      "Apple public-key request",
    );
    const data = await jsonRecord(response, provider, "KEYS_FETCH_FAILED");
    const keys = Array.isArray(data["keys"])
      ? data["keys"]
          .map(parseJwk)
          .filter((key): key is AppleJwk => key !== undefined)
      : [];
    if (keys.length === 0) {
      throw new OAuthError(
        "Apple returned no usable public keys",
        provider,
        "KEYS_FETCH_FAILED",
      );
    }
    keysCache = { keys, fetchedAtMs: now };
    return keys;
  }

  async function keyFor(kid: string): Promise<AppleJwk> {
    let key = (await fetchKeys(false)).find(
      (candidate) => candidate.kid === kid,
    );
    if (key === undefined && keysCache !== undefined) {
      key = (await fetchKeys(true)).find((candidate) => candidate.kid === kid);
    }
    if (key === undefined) {
      throw new OAuthError(
        `Apple public key ${kid} was not found`,
        provider,
        "KEY_NOT_FOUND",
      );
    }
    return key;
  }

  function clientSecret(): string {
    return generateAppleClientSecret({
      clientId,
      teamId,
      keyId,
      privateKey,
      issuedAtSeconds: Math.floor(runtime.nowMs() / 1_000),
    });
  }

  return {
    provider,

    getAuthorizationUrl(
      state: string,
      redirectUri: string,
      options: AuthorizationRequestOptions = {},
    ): string {
      const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: "code",
        response_mode: "form_post",
        scope: scopes.join(" "),
        state,
      });
      if (options.codeChallenge !== undefined) {
        params.set("code_challenge", options.codeChallenge);
        params.set("code_challenge_method", "S256");
      }
      return `${AUTH_URL}?${params.toString()}`;
    },

    exchangeCode(
      code: string,
      redirectUri: string,
      options: TokenExchangeOptions = {},
    ): Promise<OAuthTokenSet> {
      const params = new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret(),
        code,
        grant_type: "authorization_code",
        redirect_uri: redirectUri,
      });
      if (options.codeVerifier !== undefined)
        params.set("code_verifier", options.codeVerifier);
      return requestFormTokens(runtime, TOKEN_URL, params, provider, false);
    },

    async getUserInfo(tokens: OAuthTokenSet | string): Promise<OAuthUserInfo> {
      const idToken = typeof tokens === "string" ? tokens : tokens.idToken;
      if (idToken === undefined || idToken === "") {
        throw new OAuthError(
          "Apple token response did not include id_token",
          provider,
          "INVALID_ID_TOKEN",
        );
      }
      const payload = await verifyAppleIdentityToken(
        idToken,
        clientId,
        runtime.nowMs(),
        toleranceSeconds,
        keyFor,
      );
      if (payload.email === undefined || payload.email === "") {
        throw new OAuthError(
          "No email found in Apple identity token",
          provider,
          "NO_EMAIL",
        );
      }
      return {
        id: payload.sub,
        email: payload.email,
        name: null,
        emailVerified:
          payload.email_verified === true || payload.email_verified === "true",
      };
    },

    refreshToken(refreshToken: string): Promise<OAuthTokenSet> {
      return requestFormTokens(
        runtime,
        TOKEN_URL,
        new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret(),
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        }),
        provider,
        true,
      );
    },
  };
}
