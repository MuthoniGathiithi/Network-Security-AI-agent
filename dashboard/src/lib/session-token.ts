/*
 * Signed session tokens: "v1.<payload>.<signature>", both base64url, where
 * the signature is HMAC-SHA256 over "v1.<payload>".
 *
 * Uses only Web Crypto, so it runs in route handlers and proxy.ts alike.
 * Holds no secrets itself: the key is passed in by the caller.
 */

export const SESSION_COOKIE = "soc_session";

export type SessionPayload = {
  /** Subject; the dashboard has a single operator account */
  sub: "admin";
  /** Issued at, seconds since epoch */
  iat: number;
  /** Expires at, seconds since epoch */
  exp: number;
};

const VERSION = "v1";
const encoder = new TextEncoder();
const decoder = new TextDecoder();

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(text: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return null;
  const padded = text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4);
  try {
    return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

function importKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

/** Create a signed token valid for ttlSeconds from now. */
export async function signSession(secret: string, ttlSeconds: number, now = Date.now()): Promise<string> {
  const iat = Math.floor(now / 1000);
  const payload: SessionPayload = { sub: "admin", iat, exp: iat + ttlSeconds };
  const body = `${VERSION}.${toBase64Url(encoder.encode(JSON.stringify(payload)))}`;
  const signature = await crypto.subtle.sign("HMAC", await importKey(secret), encoder.encode(body));
  return `${body}.${toBase64Url(new Uint8Array(signature))}`;
}

/**
 * Verify a token's signature and expiry.
 *
 * @returns the payload, or null if the token is missing, malformed,
 *   tampered with, signed with another key, or expired
 */
export async function verifySessionToken(
  secret: string,
  token: string | undefined,
  now = Date.now(),
): Promise<SessionPayload | null> {
  if (!token || token.length > 1024) return null;

  const parts = token.split(".");
  if (parts.length !== 3 || parts[0] !== VERSION) return null;

  const signature = fromBase64Url(parts[2]);
  const payloadBytes = fromBase64Url(parts[1]);
  if (!signature || !payloadBytes) return null;

  // crypto.subtle.verify compares in constant time
  const valid = await crypto.subtle.verify(
    "HMAC",
    await importKey(secret),
    signature,
    encoder.encode(`${parts[0]}.${parts[1]}`),
  );
  if (!valid) return null;

  let payload: SessionPayload;
  try {
    payload = JSON.parse(decoder.decode(payloadBytes));
  } catch {
    return null;
  }
  if (payload.sub !== "admin" || typeof payload.exp !== "number" || typeof payload.iat !== "number") {
    return null;
  }
  if (payload.exp <= Math.floor(now / 1000)) return null;
  return payload;
}
