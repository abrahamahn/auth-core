export interface AuthRequestInfo {
  readonly ipAddress: string | undefined;
  readonly userAgent: string | undefined;
}

export interface AuthRequestWithClientInfo {
  readonly ip?: string | undefined;
  readonly headers: {
    readonly "user-agent"?: string | undefined;
    readonly [key: string]: string | string[] | undefined;
  };
}

export interface AuthCookieOptions {
  readonly path?: string | undefined;
  readonly domain?: string | undefined;
  readonly expires?: Date | undefined;
  readonly maxAge?: number | undefined;
  readonly httpOnly?: boolean | undefined;
  readonly secure?: boolean | undefined;
  readonly sameSite?: boolean | "lax" | "strict" | "none" | undefined;
}

export interface AuthCookieReply {
  setCookie(name: string, value: string, options?: AuthCookieOptions): unknown;
  clearCookie(name: string, options?: AuthCookieOptions): unknown;
}

export type DeviceType = "desktop" | "mobile" | "tablet" | "unknown";

export interface DeviceInfo {
  readonly deviceName: string | null;
  readonly deviceType: DeviceType | null;
}

/** Extract bounded client metadata from a request after the host applies trusted-proxy policy. */
export function extractRequestInfo(
  request: AuthRequestWithClientInfo,
  maxUserAgentLength = 500,
): AuthRequestInfo {
  if (!Number.isSafeInteger(maxUserAgentLength) || maxUserAgentLength < 0) {
    throw new RangeError("maxUserAgentLength must be a non-negative integer");
  }

  const rawUserAgent = request.headers["user-agent"];
  return {
    ipAddress: request.ip,
    userAgent:
      typeof rawUserAgent === "string" && rawUserAgent !== ""
        ? rawUserAgent.substring(0, maxUserAgentLength)
        : undefined,
  };
}

/** Parse a user agent into a stable, coarse session label without vendor dependencies. */
export function parseUserAgentDeviceInfo(
  userAgent?: string | null,
): DeviceInfo {
  if (userAgent == null || userAgent === "") {
    return { deviceName: null, deviceType: null };
  }

  let browser = "Unknown browser";
  if (userAgent.includes("OPR") || userAgent.includes("Opera"))
    browser = "Opera";
  else if (userAgent.includes("Edg")) browser = "Edge";
  else if (userAgent.includes("Firefox")) browser = "Firefox";
  else if (userAgent.includes("Chrome")) browser = "Chrome";
  else if (userAgent.includes("Safari")) browser = "Safari";

  let os = "Unknown device";
  if (userAgent.includes("iPhone") || userAgent.includes("iPad")) os = "iOS";
  else if (userAgent.includes("Android")) os = "Android";
  else if (userAgent.includes("Windows")) os = "Windows";
  else if (userAgent.includes("Mac OS") || userAgent.includes("Macintosh"))
    os = "macOS";
  else if (userAgent.includes("Linux")) os = "Linux";

  let deviceType: DeviceType = "unknown";
  if (userAgent.includes("iPad")) deviceType = "tablet";
  else if (userAgent.includes("iPhone") || userAgent.includes("Android"))
    deviceType = "mobile";
  else if (
    userAgent.includes("Windows") ||
    userAgent.includes("Mac OS") ||
    userAgent.includes("Macintosh") ||
    userAgent.includes("Linux")
  ) {
    deviceType = "desktop";
  }

  return { deviceName: `${browser} on ${os}`, deviceType };
}
