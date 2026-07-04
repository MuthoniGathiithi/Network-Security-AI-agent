import "server-only";

import { SocApiError, errorMessageFromBody } from "@/lib/api-error";
import type {
  Blocklist,
  Detection,
  ExportData,
  LiveInfo,
  LiveStatus,
  ResponseAction,
  SensorStatus,
  ThreatLevel,
} from "@/lib/types";
import { getServerConfig } from "./config";

/*
 * Typed client for the sensor API. Server-only: it attaches the API key,
 * which must never reach the browser. Browser code goes through the
 * dashboard's own route handlers instead.
 */

type RequestOptions = {
  method?: "GET" | "POST" | "DELETE";
  query?: Record<string, string | number | boolean | undefined>;
  json?: unknown;
  /** Override the default timeout (e.g. for long analyses) */
  timeoutMs?: number;
};

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const config = getServerConfig();
  const url = new URL(`${config.apiUrl}${path}`);
  for (const [key, value] of Object.entries(options.query ?? {})) {
    if (value !== undefined) url.searchParams.set(key, String(value));
  }

  const headers: Record<string, string> = {
    Authorization: `Bearer ${config.apiKey}`,
    Accept: "application/json",
  };
  if (options.json !== undefined) headers["Content-Type"] = "application/json";

  let response: Response;
  try {
    response = await fetch(url, {
      method: options.method ?? "GET",
      headers,
      body: options.json === undefined ? undefined : JSON.stringify(options.json),
      cache: "no-store", // security data must always be fresh
      signal: AbortSignal.timeout(options.timeoutMs ?? config.apiTimeoutMs),
    });
  } catch (error) {
    // Don't echo the URL's internals or any header; just say what happened
    if (error instanceof DOMException && error.name === "TimeoutError") {
      throw new SocApiError(504, "The sensor did not respond in time");
    }
    throw new SocApiError(502, "Could not reach the sensor. Is the API running and SOC_API_URL correct?");
  }

  const body: unknown = await response.json().catch(() => null);

  if (!response.ok) {
    if (response.status === 401) {
      throw new SocApiError(401, "The sensor rejected the API key. Check that SOC_API_KEY matches on both sides.");
    }
    throw new SocApiError(
      response.status,
      errorMessageFromBody(body, `Sensor returned HTTP ${response.status}`),
    );
  }
  return body as T;
}

export const soc = {
  /** Liveness check; doesn't need the key but sending it is harmless. */
  health: () => request<{ status: string }>("/health", { timeoutMs: 5_000 }),

  status: () => request<SensorStatus>("/api/status"),

  detections: (params: { limit?: number; minLevel?: ThreatLevel; includeFeatures?: boolean } = {}) =>
    request<Detection[]>("/api/detections", {
      query: {
        limit: params.limit,
        min_level: params.minLevel,
        include_features: params.includeFeatures,
      },
    }),

  clearDetections: () => request<{ status: string }>("/api/detections", { method: "DELETE" }),

  responses: (limit?: number) => request<ResponseAction[]>("/api/responses", { query: { limit } }),

  exportData: () => request<ExportData>("/api/export", { timeoutMs: 120_000 }),

  blocklist: () => request<Blocklist>("/api/blocklist"),

  block: (ip: string) =>
    request<ResponseAction>("/api/blocklist", { method: "POST", json: { ip } }),

  unblock: (ip: string) =>
    request<ResponseAction>(`/api/blocklist/${encodeURIComponent(ip)}`, { method: "DELETE" }),

  live: () => request<LiveInfo>("/api/live"),

  startLive: (params: { interface?: string; autoBlock?: boolean } = {}) =>
    request<LiveStatus>("/api/live/start", {
      method: "POST",
      json: { interface: params.interface ?? null, auto_block: params.autoBlock ?? null },
    }),

  stopLive: () => request<LiveStatus>("/api/live/stop", { method: "POST", timeoutMs: 20_000 }),
};
