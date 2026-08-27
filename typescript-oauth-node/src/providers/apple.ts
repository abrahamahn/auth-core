import { createPublicKey, sign, verify } from "node:crypto";

import {
  jsonRecord,
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

const AUTH_URL = "https://appleid.apple.com/auth/authorize";
const TOKEN_URL = "https://appleid.apple.com/auth/token";
const KEYS_URL = "https://appleid.apple.com/auth/keys";
const ISSUER = "https://appleid.apple.com";
const DEFAULT_SCOPES = ["email", "name"] as const;
const DEFAULT_KEYS_CACHE_TTL_MS = 60 * 60 * 1_000;
const DEFAULT_CLOCK_TOLERANCE_SECONDS = 300;
const CLIENT_SECRET_LIFETIME_SECONDS = 180 * 24 * 60 * 60;

interface AppleJwk {
  readonly kty: string;
  readonly kid: string;
  readonly use?: string;
  readonly alg?: string;
  readonly n: string;
  readonly e: string;
}

interface AppleIdTokenPayload {
  readonly iss: string;
  readonly aud: string | readonly string[];
  readonly exp: number;
  readonly iat: number;
  readonly sub: string;
  readonly email?: string;
  readonly email_verified?: string | boolean;
}

interface JwtHeader {
  readonly alg: string;
  readonly kid: string;
}

export interface AppleProviderConfig extends OAuthRuntime {
  readonly clientId: string;
  readonly teamId: string;
  readonly keyId: string;
  readonly privateKey: string;
  readonly scopes?: readonly string[];
  readonly keysCacheTtlMs?: number;
  readonly clockToleranceSeconds?: number;
}

export interface AppleClientSecretOptions {
  readonly clientId: string;
  readonly teamId: string;
  readonly keyId: string;
  readonly privateKey: string;
  readonly issuedAtSeconds?: number;
  readonly lifetimeSeconds?: number;
}

function encodeJson(value: unknown): string {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function decodePart(value: string, provider: "apple"): Record<string, unknown> {
  try {
    const parsed = JSON.parse(
      Buffer.from(value, "base64url").toString("utf8"),
    ) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed))
      throw new Error();
    return parsed as Record<string, unknown>;
  } catch {
    throw new OAuthError(
      "Apple returned a malformed identity token",
      provider,
      "INVALID_ID_TOKEN",
    );
  }
}

function splitJwt(token: string): readonly [string, string, string] {
  const parts = token.split(".");
  if (parts.length !== 3 || parts.some((part) => part === "")) {
    throw new OAuthError(
      "Apple returned a malformed identity token",
      "apple",
      "INVALID_ID_TOKEN",
    );
  }
  return parts as [string, string, string];
}

function parseHeader(encoded: string): JwtHeader {
  const record = decodePart(encoded, "apple");
  const alg = optionalString(record, "alg");
  const kid = optionalString(record, "kid");
  if (alg === undefined || kid === undefined) {
    throw new OAuthError(
      "Apple identity token header is incomplete",
      "apple",
      "INVALID_ID_TOKEN",
    );
  }
  return { alg, kid };
}

function parsePayload(encoded: string): AppleIdTokenPayload {
  const record = decodePart(encoded, "apple");
  const issuer = optionalString(record, "iss");
  const subject = optionalString(record, "sub");
  const audienceValue = record["aud"];
  const audience =
    typeof audienceValue === "string"
      ? audienceValue
      : Array.isArray(audienceValue) &&
          audienceValue.every((entry) => typeof entry === "string")
        ? audienceValue
        : undefined;
  const expiresAt = record["exp"];
  const issuedAt = record["iat"];
  if (
    issuer === undefined ||
    subject === undefined ||
    audience === undefined ||
    typeof expiresAt !== "number" ||
    !Number.isSafeInteger(expiresAt) ||
    typeof issuedAt !== "number" ||
    !Number.isSafeInteger(issuedAt)
  ) {
    throw new OAuthError(
      "Apple identity token claims are incomplete",
      "apple",
      "INVALID_ID_TOKEN",
    );
  }
  const email = optionalString(record, "email");
  return {
    iss: issuer,
    aud: audience,
    exp: expiresAt,
    iat: issuedAt,
    sub: subject,
    ...(email === undefined ? {} : { email }),
    ...(record["email_verified"] === undefined
      ? {}
      : { email_verified: record["email_verified"] as string | boolean }),
  };
}

function parseJwk(value: unknown): AppleJwk | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return undefined;
  const record = value as Record<string, unknown>;
  const kty = optionalString(record, "kty");
  const kid = optionalString(record, "kid");
  const modulus = optionalString(record, "n");
  const exponent = optionalString(record, "e");
  if (
    kty === undefined ||
    kid === undefined ||
    modulus === undefined ||
    exponent === undefined
  ) {
    return undefined;
  }
  const use = optionalString(record, "use");
  const alg = optionalString(record, "alg");
  return {
    kty,
    kid,
    n: modulus,
    e: exponent,
    ...(use === undefined ? {} : { use }),
    ...(alg === undefined ? {} : { alg }),
  };
}

/** Create the ES256 client assertion required by Sign in with Apple. */
export function generateAppleClientSecret(
  options: AppleClientSecretOptions,
): string {
  const issuedAt = options.issuedAtSeconds ?? Math.floor(Date.now() / 1_000);
  const lifetime = options.lifetimeSeconds ?? CLIENT_SECRET_LIFETIME_SECONDS;
  if (
    !Number.isSafeInteger(issuedAt) ||
    issuedAt < 0 ||
    !Number.isSafeInteger(lifetime) ||
    lifetime <= 0
  ) {
    throw new OAuthError(
      "Apple client secret timestamps are invalid",
      "apple",
      "INVALID_CONFIG",
    );
  }
  if (lifetime > CLIENT_SECRET_LIFETIME_SECONDS) {
    throw new OAuthError(
      "Apple client secret lifetime exceeds 180 days",
      "apple",
      "INVALID_CONFIG",
    );
  }
  const header = encodeJson({ alg: "ES256", kid: options.keyId, typ: "JWT" });
  const payload = encodeJson({
    iss: options.teamId,
    iat: issuedAt,
    exp: issuedAt + lifetime,
    aud: ISSUER,
    sub: options.clientId,
  });
  const input = `${header}.${payload}`;
  let signature: Buffer;
  try {
    signature = sign("sha256", Buffer.from(input, "utf8"), {
      key: options.privateKey,
      dsaEncoding: "ieee-p1363",
    });
  } catch {
    throw new OAuthError(
      "Apple private key could not sign a client secret",
      "apple",
      "INVALID_CONFIG",
    );
  }
  return `${input}.${signature.toString("base64url")}`;
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

  async function verifyIdentityToken(
    idToken: string,
  ): Promise<AppleIdTokenPayload> {
    const [encodedHeader, encodedPayload, encodedSignature] = splitJwt(idToken);
    const header = parseHeader(encodedHeader);
    if (header.alg !== "RS256") {
      throw new OAuthError(
        "Apple identity token must use RS256",
        provider,
        "INVALID_ALGORITHM",
      );
    }
    const jwk = await keyFor(header.kid);
    if (jwk.kty !== "RSA" || (jwk.alg !== undefined && jwk.alg !== "RS256")) {
      throw new OAuthError(
        "Apple public key is not an RS256 key",
        provider,
        "INVALID_ALGORITHM",
      );
    }
    let publicKey;
    try {
      publicKey = createPublicKey({
        key: { kty: "RSA", n: jwk.n, e: jwk.e },
        format: "jwk",
      });
    } catch {
      throw new OAuthError(
        "Apple public key is invalid",
        provider,
        "INVALID_ID_TOKEN",
      );
    }
    const valid = verify(
      "RSA-SHA256",
      Buffer.from(`${encodedHeader}.${encodedPayload}`, "utf8"),
      publicKey,
      Buffer.from(encodedSignature, "base64url"),
    );
    if (!valid) {
      throw new OAuthError(
        "Apple identity token signature is invalid",
        provider,
        "INVALID_SIGNATURE",
      );
    }

    const payload = parsePayload(encodedPayload);
    if (payload.iss !== ISSUER) {
      throw new OAuthError(
        "Apple identity token issuer is invalid",
        provider,
        "INVALID_ISSUER",
      );
    }
    const audiences =
      typeof payload.aud === "string" ? [payload.aud] : payload.aud;
    if (!audiences.includes(clientId)) {
      throw new OAuthError(
        "Apple identity token audience is invalid",
        provider,
        "INVALID_AUDIENCE",
      );
    }
    const nowSeconds = Math.floor(runtime.nowMs() / 1_000);
    if (nowSeconds >= payload.exp + toleranceSeconds) {
      throw new OAuthError(
        "Apple identity token has expired",
        provider,
        "TOKEN_EXPIRED",
      );
    }
    if (payload.iat > nowSeconds + toleranceSeconds) {
      throw new OAuthError(
        "Apple identity token was issued in the future",
        provider,
        "INVALID_IAT",
      );
    }
    return payload;
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
      return requestTokens(params, false);
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
      const payload = await verifyIdentityToken(idToken);
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
      return requestTokens(
        new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret(),
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        }),
        true,
      );
    },
  };
}
