import { describe, expect, it } from "vitest";

import {
  AuthWebAuthnError,
  createAuthWebAuthnServer,
  parseWebAuthnAuthenticationResponse,
  parseWebAuthnRegistrationResponse,
} from "../src/index.js";

const config = {
  rpName: "Example",
  rpId: "example.com",
  expectedOrigin: "https://login.example.com",
} as const;

describe("AuthWebAuthnServer", () => {
  it("generates scoped registration and authentication options", async () => {
    const server = createAuthWebAuthnServer(config);
    const registration = await server.generateRegistrationOptions({
      userName: "user@example.com",
      userDisplayName: "Example User",
      excludeCredentials: [{ id: "existing", transports: ["internal"] }],
    });
    expect(registration.rp.id).toBe("example.com");
    expect(registration.rp.name).toBe("Example");
    expect(registration.user.name).toBe("user@example.com");
    expect(registration.challenge).not.toBe("");
    expect(registration.excludeCredentials).toEqual([
      { id: "existing", type: "public-key", transports: ["internal"] },
    ]);

    const authentication = await server.generateAuthenticationOptions({
      allowCredentials: [{ id: "existing", transports: ["internal"] }],
    });
    expect(authentication.rpId).toBe("example.com");
    expect(authentication.allowCredentials).toEqual([
      { id: "existing", type: "public-key", transports: ["internal"] },
    ]);
  });

  it("rejects unsafe or mismatched relying-party configuration", () => {
    expect(() =>
      createAuthWebAuthnServer({
        ...config,
        expectedOrigin: "http://login.example.com",
      }),
    ).toThrow(AuthWebAuthnError);
    expect(() =>
      createAuthWebAuthnServer({
        ...config,
        expectedOrigin: "https://unrelated.test",
      }),
    ).toThrow(/rpId/u);
  });
});

describe("WebAuthn browser response normalization", () => {
  it("normalizes registration and authentication responses", () => {
    expect(
      parseWebAuthnRegistrationResponse({
        id: "credential-a",
        rawId: "credential-a",
        type: "public-key",
        response: {
          clientDataJSON: "client-data",
          attestationObject: "attestation",
          transports: ["internal", "hybrid"],
        },
      }),
    ).toMatchObject({
      id: "credential-a",
      response: { transports: ["internal", "hybrid"] },
      clientExtensionResults: {},
    });
    expect(
      parseWebAuthnAuthenticationResponse({
        id: "credential-a",
        rawId: "credential-a",
        type: "public-key",
        response: {
          clientDataJSON: "client-data",
          authenticatorData: "authenticator-data",
          signature: "signature",
          userHandle: null,
        },
      }),
    ).toMatchObject({
      id: "credential-a",
      response: { signature: "signature" },
    });
  });

  it("rejects malformed credential type and transports", () => {
    expect(() =>
      parseWebAuthnRegistrationResponse({
        id: "credential-a",
        rawId: "credential-a",
        type: "password",
        response: { clientDataJSON: "data", attestationObject: "attestation" },
      }),
    ).toThrow(/public-key/u);
    expect(() =>
      parseWebAuthnRegistrationResponse({
        id: "credential-a",
        rawId: "credential-a",
        type: "public-key",
        response: {
          clientDataJSON: "data",
          attestationObject: "attestation",
          transports: ["telepathy"],
        },
      }),
    ).toThrow(/transports/u);
  });
});
