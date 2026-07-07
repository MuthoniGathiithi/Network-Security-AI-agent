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
import { redirect } from "next/navigation";

import { getServerConfig } from "./config";
import { getSession } from "./session";

/*
 * Typed client for the sensor API. Server-only: it attaches the API key,
 * which must never reach the browser. Browser code goes through the
 * dashboard's own route handlers instead.
 */

type SensorFetchOptions = {
  method?: string;
  query?: Record<string, string | number | boolean | undefined> | URLSearchParams;
  headers?: Record<string, string>;
  body?: BodyInit | null;
  /** Override the default timeout (e.g. for long analyses) */
  timeoutMs?: number;
};

/**
 * Low-level call to the sensor: adds the API key and a timeout, and turns
 * network failures into SocApiError. Returns the raw Response (any status),
 * so it can also be used to stream responses through unchanged.
 */
export async function sensorFetch(path: string, options: SensorFetchOptions = {}): Promise<Response> {
  const config = getServerConfig();
  const url = new URL(`${config.apiUrl}${path}`);
  const query = options.query instanceof URLSearchParams
    ? options.query
    : Object.entries(options.query ?? {});
  for (const [key, value] of query) {
    if (value !== undefined) url.searchParams.set(key, String(value));
  }

  try {
    return await fetch(url, {
      method: options.method ?? "GET",
      headers: {
        ...options.headers,
        Authorization: `Bearer ${config.apiKey}`,
        Accept: "application/json",
      },
      body: options.body,
      cache: "no-store", // security data must always be fresh
      signal: AbortSignal.timeout(options.timeoutMs ?? config.apiTimeoutMs),
      // Required by Node's fetch to stream a request body (uploads)
      ...(options.body instanceof ReadableStream ? { duplex: "half" } : {}),
    } as RequestInit);
  } catch (error) {
    // Don't echo the URL's internals or any header; just say what happened
    if (error instanceof DOMException && error.name === "TimeoutError") {
      throw new SocApiError(504, "The sensor did not respond in time");
    }
    throw new SocApiError(502, "Could not reach the sensor. Is the API running and SOC_API_URL correct?");
  }
}

/** Build a SocApiError from a non-2xx sensor response body. */
export function sensorError(status: number, body: unknown): SocApiError {
  if (status === 401) {
    return new SocApiError(401, "The sensor rejected the API key. Check that SOC_API_KEY matches on both sides.");
  }
  return new SocApiError(status, errorMessageFromBody(body, `Sensor returned HTTP ${status}`));
}

type RequestOptions = {
  method?: "GET" | "POST" | "DELETE";
  query?: Record<string, string | number | boolean | undefined>;
  json?: unknown;
  timeoutMs?: number;
};

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  // Authorization next to the data: no sensor call without a session,
  // even if a page forgets to check
  if (!(await getSession())) redirect("/login");

  const response = await sensorFetch(path, {
    method: options.method,
    query: options.query,
    headers: options.json === undefined ? {} : { "Content-Type": "application/json" },
    body: options.json === undefined ? undefined : JSON.stringify(options.json),
    timeoutMs: options.timeoutMs,
  });

  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) throw sensorError(response.status, body);
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
