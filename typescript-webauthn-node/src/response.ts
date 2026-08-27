import type {
  AuthenticationExtensionsClientOutputs,
  AuthenticationResponseJSON,
  AuthenticatorAttachment,
  AuthenticatorTransportFuture,
  RegistrationResponseJSON,
} from "@simplewebauthn/server";

import { AuthWebAuthnError } from "./error.js";

const TRANSPORTS = new Set<AuthenticatorTransportFuture>([
  "ble",
  "cable",
  "hybrid",
  "internal",
  "nfc",
  "smart-card",
  "usb",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function invalidResponse(message: string): AuthWebAuthnError {
  return new AuthWebAuthnError("invalid-response", message);
}

function requiredString(
  record: Record<string, unknown>,
  key: string,
  label: string,
): string {
  const value = record[key];
  if (typeof value !== "string" || value === "")
    throw invalidResponse(`${label} is required`);
  return value;
}

function optionalString(
  record: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = record[key];
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string")
    throw invalidResponse(`${key} must be a string`);
  return value;
}

function credentialType(value: unknown): "public-key" {
  if (value !== "public-key")
    throw invalidResponse("credential type must be public-key");
  return value;
}

function authenticatorAttachment(
  value: unknown,
): AuthenticatorAttachment | undefined {
  if (value === undefined || value === null) return undefined;
  if (value !== "platform" && value !== "cross-platform") {
    throw invalidResponse("authenticatorAttachment is invalid");
  }
  return value;
}

function clientExtensionResults(
  value: unknown,
): AuthenticationExtensionsClientOutputs {
  if (value === undefined) return {};
  if (!isRecord(value))
    throw invalidResponse("clientExtensionResults must be an object");
  return value;
}

function transports(
  value: unknown,
): AuthenticatorTransportFuture[] | undefined {
  if (value === undefined) return undefined;
  if (
    !Array.isArray(value) ||
    !value.every((entry) => TRANSPORTS.has(entry as never))
  ) {
    throw invalidResponse("credential transports are invalid");
  }
  return value as AuthenticatorTransportFuture[];
}

export function parseWebAuthnRegistrationResponse(
  value: unknown,
): RegistrationResponseJSON {
  if (!isRecord(value) || !isRecord(value["response"])) {
    throw invalidResponse("registration response must be an object");
  }
  const response = value["response"];
  const responseTransports = transports(response["transports"]);
  const attachment = authenticatorAttachment(value["authenticatorAttachment"]);
  const authenticatorData = optionalString(response, "authenticatorData");
  const publicKey = optionalString(response, "publicKey");
  const publicKeyAlgorithm = response["publicKeyAlgorithm"];
  if (
    publicKeyAlgorithm !== undefined &&
    (!Number.isSafeInteger(publicKeyAlgorithm) ||
      typeof publicKeyAlgorithm !== "number")
  ) {
    throw invalidResponse("publicKeyAlgorithm must be an integer");
  }

  return {
    id: requiredString(value, "id", "credential id"),
    rawId: requiredString(value, "rawId", "raw credential id"),
    response: {
      clientDataJSON: requiredString(response, "clientDataJSON", "client data"),
      attestationObject: requiredString(
        response,
        "attestationObject",
        "attestation object",
      ),
      ...(authenticatorData === undefined ? {} : { authenticatorData }),
      ...(responseTransports === undefined
        ? {}
        : { transports: responseTransports }),
      ...(publicKeyAlgorithm === undefined ? {} : { publicKeyAlgorithm }),
      ...(publicKey === undefined ? {} : { publicKey }),
    },
    clientExtensionResults: clientExtensionResults(
      value["clientExtensionResults"],
    ),
    type: credentialType(value["type"]),
    ...(attachment === undefined
      ? {}
      : { authenticatorAttachment: attachment }),
  };
}

export function parseWebAuthnAuthenticationResponse(
  value: unknown,
): AuthenticationResponseJSON {
  if (!isRecord(value) || !isRecord(value["response"])) {
    throw invalidResponse("authentication response must be an object");
  }
  const response = value["response"];
  const attachment = authenticatorAttachment(value["authenticatorAttachment"]);
  const userHandle = optionalString(response, "userHandle");

  return {
    id: requiredString(value, "id", "credential id"),
    rawId: requiredString(value, "rawId", "raw credential id"),
    response: {
      clientDataJSON: requiredString(response, "clientDataJSON", "client data"),
      authenticatorData: requiredString(
        response,
        "authenticatorData",
        "authenticator data",
      ),
      signature: requiredString(response, "signature", "signature"),
      ...(userHandle === undefined ? {} : { userHandle }),
    },
    clientExtensionResults: clientExtensionResults(
      value["clientExtensionResults"],
    ),
    type: credentialType(value["type"]),
    ...(attachment === undefined
      ? {}
      : { authenticatorAttachment: attachment }),
  };
}

export function readWebAuthnResponseTransports(
  value: unknown,
): readonly AuthenticatorTransportFuture[] {
  if (!isRecord(value) || !isRecord(value["response"])) return [];
  return transports(value["response"]["transports"]) ?? [];
}
