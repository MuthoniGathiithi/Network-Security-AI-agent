#!/usr/bin/env node
/*
 * Generate DASHBOARD_PASSWORD_HASH and a SESSION_SECRET.
 *
 *   node scripts/hash-password.mjs
 *
 * Prompts for the password without echoing it, so it doesn't end up in
 * your shell history. Paste the printed lines into .env.local or the
 * Vercel environment variables.
 */

import { randomBytes, scrypt } from "node:crypto";
import { stdin, stdout } from "node:process";

// scrypt cost: ~100 ms per check, 32 MiB of memory
const N = 32768;
const R = 8;
const P = 1;
const KEY_LENGTH = 32;
const MIN_LENGTH = 12;

function readHidden(prompt) {
  return new Promise((resolve, reject) => {
    if (!stdin.isTTY) {
      // Piped input (e.g. CI): read the first line
      let data = "";
      stdin.setEncoding("utf8");
      stdin.on("data", (chunk) => (data += chunk));
      stdin.on("end", () => resolve(data.split(/\r?\n/)[0]));
      stdin.on("error", reject);
      return;
    }
    stdout.write(prompt);
    stdin.setRawMode(true);
    stdin.resume();
    stdin.setEncoding("utf8");
    let value = "";
    const onData = (char) => {
      if (char === "\r" || char === "\n" || char === "\u0004") {
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener("data", onData);
        stdout.write("\n");
        resolve(value);
      } else if (char === "\u0003") {
        stdout.write("\n");
        process.exit(130);
      } else if (char === "\u007f" || char === "\b") {
        value = value.slice(0, -1);
      } else {
        value += char;
      }
    };
    stdin.on("data", onData);
  });
}

const password = await readHidden("Dashboard password: ");
if (password.length < MIN_LENGTH) {
  console.error(`Password must be at least ${MIN_LENGTH} characters.`);
  process.exit(1);
}
if (stdin.isTTY) {
  const confirm = await readHidden("Repeat password: ");
  if (confirm !== password) {
    console.error("Passwords do not match.");
    process.exit(1);
  }
}

const salt = randomBytes(16);
const hash = await new Promise((resolve, reject) =>
  scrypt(password, salt, KEY_LENGTH, { N, r: R, p: P, maxmem: 256 * 1024 * 1024 }, (err, key) =>
    err ? reject(err) : resolve(key),
  ),
);

console.log("\n# Add to .env.local or Vercel environment variables:");
console.log(`DASHBOARD_PASSWORD_HASH=scrypt:${N}:${R}:${P}:${salt.toString("base64url")}:${hash.toString("base64url")}`);
console.log(`SESSION_SECRET=${randomBytes(32).toString("base64url")}`);
