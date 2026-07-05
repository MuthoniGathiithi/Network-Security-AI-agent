import "server-only";

/*
 * Which sensor endpoints the browser may reach through /api/sensor/*.
 *
 * Anything not listed here is rejected, so the proxy can't be used to call
 * arbitrary sensor URLs, and only the listed query parameters are passed on.
 */

export type SensorRoute = {
  method: "GET" | "POST" | "DELETE";
  /** Matched against the path after /api/sensor/ */
  pattern: RegExp;
  /** Sensor path to call; receives the pattern's capture groups */
  target: (match: RegExpMatchArray) => string;
  /** Query parameters forwarded to the sensor */
  query?: readonly string[];
  /** "json" for small JSON bodies, "upload" for multipart pcap uploads */
  body?: "json" | "upload";
  timeoutMs?: number;
};

// IPv4/IPv6 characters only: blocks "..", "/", "?" and anything else that
// could change which sensor endpoint is reached
const IP_SEGMENT = "([0-9A-Fa-f:.]{2,45})";
const LONG_JOB_MS = 300_000;

export const SENSOR_ROUTES: readonly SensorRoute[] = [
  { method: "GET", pattern: /^health$/, target: () => "/health" },
  { method: "GET", pattern: /^status$/, target: () => "/api/status" },

  {
    method: "GET",
    pattern: /^detections$/,
    target: () => "/api/detections",
    query: ["limit", "min_level", "include_features"],
  },
  { method: "DELETE", pattern: /^detections$/, target: () => "/api/detections" },

  { method: "GET", pattern: /^responses$/, target: () => "/api/responses", query: ["limit"] },
  { method: "GET", pattern: /^export$/, target: () => "/api/export", timeoutMs: 120_000 },

  { method: "GET", pattern: /^blocklist$/, target: () => "/api/blocklist" },
  { method: "POST", pattern: /^blocklist$/, target: () => "/api/blocklist", body: "json" },
  {
    method: "DELETE",
    pattern: new RegExp(`^blocklist/${IP_SEGMENT}$`),
    target: (m) => `/api/blocklist/${encodeURIComponent(m[1])}`,
  },

  { method: "GET", pattern: /^live$/, target: () => "/api/live" },
  { method: "POST", pattern: /^live\/start$/, target: () => "/api/live/start", body: "json" },
  { method: "POST", pattern: /^live\/stop$/, target: () => "/api/live/stop", timeoutMs: 20_000 },

  {
    method: "POST",
    pattern: /^analyze$/,
    target: () => "/api/analyze",
    query: ["auto_block"],
    body: "upload",
    timeoutMs: LONG_JOB_MS,
  },
  {
    method: "POST",
    pattern: /^train$/,
    target: () => "/api/train",
    query: ["save"],
    body: "upload",
    timeoutMs: LONG_JOB_MS,
  },
];

/** Find the allowed route for a method and path, if any. */
export function matchSensorRoute(
  method: string,
  path: string,
): { route: SensorRoute; target: string } | null {
  for (const route of SENSOR_ROUTES) {
    if (route.method !== method) continue;
    const match = path.match(route.pattern);
    if (match) return { route, target: route.target(match) };
  }
  return null;
}

/** Copy only the route's allowed query parameters. */
export function allowedQuery(route: SensorRoute, search: URLSearchParams): URLSearchParams {
  const out = new URLSearchParams();
  for (const name of route.query ?? []) {
    const value = search.get(name);
    if (value !== null) out.set(name, value);
  }
  return out;
}
