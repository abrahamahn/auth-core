import {
  accessToken,
  jsonRecord,
  optionalString,
  providerRuntime,
  requireConfig,
  requiredString,
  requireOk,
  tokenError,
  tokenSetFromResponse,
} from "../http.js";
import { OAuthError } from "../types.js";

import type {
  AuthorizationRequestOptions,
  OAuthProviderClient,
  OAuthRuntime,
  OAuthTokenSet,
  OAuthUserInfo,
  TokenExchangeOptions,
} from "../types.js";

const AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const USERINFO_URL = "https://openidconnect.googleapis.com/v1/userinfo";
const DEFAULT_SCOPES = ["openid", "email", "profile"] as const;

export interface GoogleProviderConfig extends OAuthRuntime {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly scopes?: readonly string[];
  readonly requestOfflineAccess?: boolean;
  readonly forceConsent?: boolean;
}

export function createGoogleProvider(
  config: GoogleProviderConfig,
): OAuthProviderClient {
  const provider = "google";
  const clientId = requireConfig(config.clientId, "clientId", provider);
  const clientSecret = requireConfig(
    config.clientSecret,
    "clientSecret",
    provider,
  );
  const runtime = providerRuntime(config);
  const scopes = config.scopes ?? DEFAULT_SCOPES;
  if (scopes.length === 0) {
    throw new OAuthError(
      "At least one scope is required",
      provider,
      "INVALID_CONFIG",
    );
  }

  async function requestTokens(
    params: URLSearchParams,
    refresh: boolean,
  ): Promise<OAuthTokenSet> {
    const response = await runtime.fetch(TOKEN_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });
    const errorCode = refresh
      ? "TOKEN_REFRESH_FAILED"
      : "TOKEN_EXCHANGE_FAILED";
    await requireOk(
      response,
      provider,
      errorCode,
      refresh ? "Token refresh" : "Code exchange",
    );
    const data = await jsonRecord(response, provider, errorCode);
    tokenError(data, provider, errorCode);
    return tokenSetFromResponse(data, provider, runtime.nowMs());
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
        scope: scopes.join(" "),
        state,
      });
      if (config.requestOfflineAccess ?? true)
        params.set("access_type", "offline");
      if (config.forceConsent === true) params.set("prompt", "consent");
      if (options.prompt !== undefined) params.set("prompt", options.prompt);
      if (options.loginHint !== undefined)
        params.set("login_hint", options.loginHint);
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
        client_secret: clientSecret,
        code,
        grant_type: "authorization_code",
        redirect_uri: redirectUri,
      });
      if (options.codeVerifier !== undefined)
        params.set("code_verifier", options.codeVerifier);
      return requestTokens(params, false);
    },

    async getUserInfo(tokens: OAuthTokenSet | string): Promise<OAuthUserInfo> {
      const response = await runtime.fetch(USERINFO_URL, {
        headers: { Authorization: `Bearer ${accessToken(tokens)}` },
      });
      await requireOk(
        response,
        provider,
        "USERINFO_FAILED",
        "User info request",
      );
      const data = await jsonRecord(response, provider, "USERINFO_FAILED");
      const email = requiredString(data, "email", provider, "NO_EMAIL");
      const result: OAuthUserInfo = {
        id: requiredString(data, "sub", provider, "USERINFO_FAILED"),
        email,
        name: optionalString(data, "name") ?? null,
        emailVerified:
          data["email_verified"] === true || data["email_verified"] === "true",
      };
      const picture = optionalString(data, "picture");
      return picture === undefined ? result : { ...result, picture };
    },

    refreshToken(refreshToken: string): Promise<OAuthTokenSet> {
      return requestTokens(
        new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        }),
        true,
      );
    },
  };
}
