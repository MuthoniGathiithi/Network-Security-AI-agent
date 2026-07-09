"use client";

import { SocApiError } from "@/lib/api-error";
import type { LiveStatus, ResponseAction } from "@/lib/types";

/*
 * Browser-side calls to the sensor through the dashboard's /api/sensor
 * proxy (which holds the API key). Same-origin, so the session cookie is
 * sent automatically.
 *
 * If the session has expired (401), the user is sent to the login page and
 * returned to the current page afterwards.
 */

/** Thrown after redirecting to login, so callers can stop quietly. */
export class SessionExpiredError extends Error {
  constructor() {
    super("Your session has expired. Please sign in again.");
    this.name = "SessionExpiredError";
  }
}

export function redirectToLogin(): never {
  const here = `${window.location.pathname}${window.location.search}`;
  // Deliberately a full page load, not router.push(): it discards all
  // in-memory state from the expired session and goes through proxy.ts
  // eslint-disable-next-line @next/next/no-location-assign-relative-destination
  window.location.assign(`/login?next=${encodeURIComponent(here)}`);
  throw new SessionExpiredError();
}

/**
 * Call a sensor endpoint through the proxy.
 *
 * @param path   Endpoint after /api/sensor/, e.g. "blocklist"
 * @throws SessionExpiredError (after redirecting) when signed out,
 *   SocApiError with the server's message for other failures
 */
export async function callSensor<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response: Response;
  try {
    response = await fetch(`/api/sensor/${path}`, { ...init, cache: "no-store" });
  } catch {
    throw new SocApiError(0, "Network error: could not reach the dashboard");
  }

  if (response.status === 401) redirectToLogin();

  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) {
    const message = (body as { error?: unknown } | null)?.error;
    throw new SocApiError(
      response.status,
      typeof message === "string" ? message : `Request failed (HTTP ${response.status})`,
    );
  }
  return body as T;
}

function postJson<T>(path: string, json: unknown): Promise<T> {
  return callSensor<T>(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(json),
  });
}

/** Typed browser helpers for actions the UI performs. */
export const sensorActions = {
  block: (ip: string) => postJson<ResponseAction>("blocklist", { ip }),
  unblock: (ip: string) =>
    callSensor<ResponseAction>(`blocklist/${encodeURIComponent(ip)}`, { method: "DELETE" }),
  startLive: (params: { interface?: string; autoBlock?: boolean } = {}) =>
    postJson<LiveStatus>("live/start", {
      interface: params.interface ?? null,
      auto_block: params.autoBlock ?? null,
    }),
  stopLive: () => callSensor<LiveStatus>("live/stop", { method: "POST" }),
};
