import { createPublicKey, sign, verify } from "node:crypto";

import { optionalString } from "../http.js";
import { OAuthError } from "../types.js";

const ISSUER = "https://appleid.apple.com";
const CLIENT_SECRET_LIFETIME_SECONDS = 180 * 24 * 60 * 60;

export interface AppleJwk {
  readonly kty: string;
  readonly kid: string;
  readonly use?: string;
  readonly alg?: string;
  readonly n: string;
  readonly e: string;
}

export interface AppleIdTokenPayload {
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

export function parseJwk(value: unknown): AppleJwk | undefined {
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

export async function verifyAppleIdentityToken(
  idToken: string,
  clientId: string,
  nowMs: number,
  toleranceSeconds: number,
  keyFor: (kid: string) => Promise<AppleJwk>,
): Promise<AppleIdTokenPayload> {
  const provider = "apple";
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
  const nowSeconds = Math.floor(nowMs / 1_000);
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
