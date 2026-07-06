import "server-only";

/*
 * Server-side configuration from environment variables.
 *
 * Importing this module from a Client Component is a build error (the
 * `server-only` import above), so the API key can't end up in browser code.
 * None of these variables may be prefixed with NEXT_PUBLIC_, which would
 * inline them into the client bundle.
 *
 * Values are read lazily at request time rather than at build time, so they
 * can be changed in the Vercel dashboard without rebuilding.
 */

export type ServerConfig = {
  /** Base URL of the sensor's API, e.g. https://sensor.example.com */
  apiUrl: string;
  /** Bearer key matching the sensor's SOC_API_KEY */
  apiKey: string;
  /** Per-request timeout for calls to the sensor */
  apiTimeoutMs: number;
};

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

const MIN_API_KEY_LENGTH = 32; // matches the sensor's Settings.MIN_API_KEY_LENGTH
const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new ConfigError(`${name} is not set. See dashboard/.env.example.`);
  }
  return value;
}

function parseApiUrl(raw: string): string {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ConfigError(`SOC_API_URL is not a valid URL: ${raw}`);
  }
  const local = LOCAL_HOSTS.has(url.hostname);
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) {
    // The API key travels in a header; over plain HTTP anyone on the path
    // could read it
    throw new ConfigError(
      "SOC_API_URL must use https:// (http:// is only allowed for localhost)",
    );
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new ConfigError("SOC_API_URL must not contain credentials, a query or a fragment");
  }
  // Normalize: no trailing slash, so paths can be appended directly
  return url.toString().replace(/\/+$/, "");
}

function parseTimeout(raw: string | undefined): number {
  if (!raw?.trim()) return 30_000;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1_000 || value > 600_000) {
    throw new ConfigError("SOC_API_TIMEOUT_MS must be an integer between 1000 and 600000");
  }
  return value;
}

let cached: ServerConfig | undefined;

/**
 * Read and validate the server configuration.
 *
 * @throws ConfigError if a variable is missing or invalid; the message
 *   names the variable but never includes the key itself
 */
export function getServerConfig(): ServerConfig {
  if (cached) return cached;

  const apiKey = required("SOC_API_KEY");
  if (apiKey.length < MIN_API_KEY_LENGTH) {
    throw new ConfigError(`SOC_API_KEY must be at least ${MIN_API_KEY_LENGTH} characters`);
  }

  cached = {
    apiUrl: parseApiUrl(required("SOC_API_URL")),
    apiKey,
    apiTimeoutMs: parseTimeout(process.env.SOC_API_TIMEOUT_MS),
  };
  return cached;
}

/** For tests: forget the cached config so the next call re-reads the env. */
export function resetServerConfigForTests(): void {
  cached = undefined;
  cachedAuth = undefined;
}

export type AuthConfig = {
  /** HMAC key for signing session cookies */
  sessionSecret: string;
  /** scrypt hash of the dashboard password (scripts/hash-password.mjs) */
  passwordHash: string;
  /** How long a sign-in lasts */
  sessionTtlSeconds: number;
};

const MIN_SESSION_SECRET_LENGTH = 32;
// scrypt:N:r:p:salt:hash, with base64url salt and hash. Uses ":" rather than
// "$" because Next.js expands $VARIABLES inside .env files.
const PASSWORD_HASH_PATTERN = /^scrypt:\d+:\d+:\d+:[A-Za-z0-9_-]{16,}:[A-Za-z0-9_-]{32,}$/;

let cachedAuth: AuthConfig | undefined;

/**
 * Read and validate the sign-in configuration.
 *
 * @throws ConfigError if a variable is missing or invalid
 */
export function getAuthConfig(): AuthConfig {
  if (cachedAuth) return cachedAuth;

  const sessionSecret = required("SESSION_SECRET");
  if (sessionSecret.length < MIN_SESSION_SECRET_LENGTH) {
    throw new ConfigError(`SESSION_SECRET must be at least ${MIN_SESSION_SECRET_LENGTH} characters`);
  }

  const passwordHash = required("DASHBOARD_PASSWORD_HASH");
  if (!PASSWORD_HASH_PATTERN.test(passwordHash)) {
    throw new ConfigError(
      "DASHBOARD_PASSWORD_HASH is not a valid hash. Generate one with: node scripts/hash-password.mjs",
    );
  }

  const ttlRaw = process.env.SESSION_TTL_HOURS?.trim();
  const ttlHours = ttlRaw ? Number(ttlRaw) : 8;
  if (!Number.isFinite(ttlHours) || ttlHours <= 0 || ttlHours > 168) {
    throw new ConfigError("SESSION_TTL_HOURS must be greater than 0 and at most 168 (one week)");
  }

  cachedAuth = {
    sessionSecret,
    passwordHash,
    sessionTtlSeconds: Math.round(ttlHours * 3600),
  };
  return cachedAuth;
}
