import {
  accessToken,
  jsonRecord,
  optionalNumber,
  optionalString,
  providerRuntime,
  requireConfig,
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

const AUTH_URL = "https://github.com/login/oauth/authorize";
const TOKEN_URL = "https://github.com/login/oauth/access_token";
const USERINFO_URL = "https://api.github.com/user";
const EMAILS_URL = "https://api.github.com/user/emails";
const DEFAULT_SCOPES = ["user:email", "read:user"] as const;
const API_HEADERS = {
  Accept: "application/vnd.github+json",
  "X-GitHub-Api-Version": "2022-11-28",
} as const;

export interface GitHubProviderConfig extends OAuthRuntime {
  readonly clientId: string;
  readonly clientSecret: string;
  readonly scopes?: readonly string[];
  readonly allowSignup?: boolean;
}

function verifiedGitHubEmail(value: unknown): string | undefined {
  if (!Array.isArray(value)) return undefined;
  const emails = value.filter(
    (item): item is Record<string, unknown> =>
      item !== null && typeof item === "object" && !Array.isArray(item),
  );
  const primary = emails.find(
    (email) => email["primary"] === true && email["verified"] === true,
  );
  const fallback = emails.find((email) => email["verified"] === true);
  return optionalString(primary ?? fallback ?? {}, "email");
}

export function createGitHubProvider(
  config: GitHubProviderConfig,
): OAuthProviderClient {
  const provider = "github";
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
    body: Record<string, string>,
    refresh: boolean,
  ): Promise<OAuthTokenSet> {
    const response = await runtime.fetch(TOKEN_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
      },
      body: JSON.stringify(body),
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
        scope: scopes.join(" "),
        state,
        allow_signup: String(config.allowSignup ?? true),
      });
      if (options.prompt !== undefined) params.set("prompt", options.prompt);
      if (options.loginHint !== undefined)
        params.set("login", options.loginHint);
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
      return requestTokens(
        {
          client_id: clientId,
          client_secret: clientSecret,
          code,
          redirect_uri: redirectUri,
          ...(options.codeVerifier === undefined
            ? {}
            : { code_verifier: options.codeVerifier }),
        },
        false,
      );
    },

    async getUserInfo(tokens: OAuthTokenSet | string): Promise<OAuthUserInfo> {
      const authorization = `Bearer ${accessToken(tokens)}`;
      const [userResponse, emailsResponse] = await Promise.all([
        runtime.fetch(USERINFO_URL, {
          headers: { ...API_HEADERS, Authorization: authorization },
        }),
        runtime.fetch(EMAILS_URL, {
          headers: { ...API_HEADERS, Authorization: authorization },
        }),
      ]);
      await requireOk(
        userResponse,
        provider,
        "USERINFO_FAILED",
        "User info request",
      );
      const user = await jsonRecord(userResponse, provider, "USERINFO_FAILED");

      let email = optionalString(user, "email");
      let emailVerified = false;
      if (emailsResponse.ok) {
        let emails: unknown;
        try {
          emails = await emailsResponse.json();
        } catch {
          throw new OAuthError(
            "GitHub returned invalid email data",
            provider,
            "USERINFO_FAILED",
          );
        }
        const verified = verifiedGitHubEmail(emails);
        if (verified !== undefined) {
          email = verified;
          emailVerified = true;
        }
      } else {
        await emailsResponse.body?.cancel().catch(() => undefined);
      }
      if (email === undefined) {
        throw new OAuthError(
          "No email found on GitHub account",
          provider,
          "NO_EMAIL",
        );
      }

      const numericId = optionalNumber(user, "id");
      const stringId = optionalString(user, "id");
      const id = numericId === undefined ? stringId : String(numericId);
      if (id === undefined) {
        throw new OAuthError(
          "GitHub response is missing id",
          provider,
          "USERINFO_FAILED",
        );
      }
      const result: OAuthUserInfo = {
        id,
        email,
        name: optionalString(user, "name") ?? null,
        emailVerified,
      };
      const picture = optionalString(user, "avatar_url");
      return picture === undefined ? result : { ...result, picture };
    },

    refreshToken(refreshToken: string): Promise<OAuthTokenSet> {
      return requestTokens(
        {
          client_id: clientId,
          client_secret: clientSecret,
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        },
        true,
      );
    },
  };
}
