import "server-only";

import { scrypt, timingSafeEqual } from "node:crypto";

/*
 * Password verification against a scrypt hash in the format written by
 * scripts/hash-password.mjs:  scrypt:N:r:p:<salt b64url>:<hash b64url>
 */

const MAX_PASSWORD_LENGTH = 1024; // bound the work an attacker can request

function scryptAsync(
  password: string,
  salt: Buffer,
  keylen: number,
  options: { N: number; r: number; p: number },
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    // maxmem must cover 128 * N * r bytes, which exceeds the 32 MiB default
    scrypt(password, salt, keylen, { ...options, maxmem: 256 * 1024 * 1024 }, (err, key) =>
      err ? reject(err) : resolve(key),
    );
  });
}

/**
 * Check a password against the stored hash in constant time.
 *
 * @returns true if the password matches
 */
export async function verifyPassword(password: string, storedHash: string): Promise<boolean> {
  if (!password || password.length > MAX_PASSWORD_LENGTH) return false;

  const [scheme, n, r, p, saltB64, hashB64] = storedHash.split(":");
  if (scheme !== "scrypt") return false;

  const expected = Buffer.from(hashB64, "base64url");
  const actual = await scryptAsync(password, Buffer.from(saltB64, "base64url"), expected.length, {
    N: Number(n),
    r: Number(r),
    p: Number(p),
  });
  return actual.length === expected.length && timingSafeEqual(actual, expected);
}
