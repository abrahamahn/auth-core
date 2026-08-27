import { describe, expect, it } from "vitest";

import { extractRequestInfo, parseUserAgentDeviceInfo } from "../src/index.js";

describe("HTTP request metadata", () => {
  it("extracts and bounds client metadata", () => {
    expect(
      extractRequestInfo(
        { ip: "203.0.113.8", headers: { "user-agent": "abcdef" } },
        3,
      ),
    ).toEqual({ ipAddress: "203.0.113.8", userAgent: "abc" });
    expect(() => extractRequestInfo({ headers: {} }, -1)).toThrow(RangeError);
  });

  it("classifies common browser sessions", () => {
    expect(
      parseUserAgentDeviceInfo(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) AppleWebKit Safari/605.1",
      ),
    ).toEqual({ deviceName: "Safari on iOS", deviceType: "mobile" });
    expect(parseUserAgentDeviceInfo()).toEqual({
      deviceName: null,
      deviceType: null,
    });
  });
});
