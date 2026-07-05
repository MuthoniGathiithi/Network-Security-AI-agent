import type { NextRequest } from "next/server";

import { SocApiError } from "@/lib/api-error";
import { ConfigError } from "@/lib/server/config";
import { allowedQuery, matchSensorRoute, type SensorRoute } from "@/lib/server/sensor-routes";
import { sensorError, sensorFetch } from "@/lib/server/soc-client";

/*
 * Proxy from the browser to the sensor API.
 *
 * The browser calls /api/sensor/<endpoint>; this handler adds the API key
 * on the server and forwards only allowlisted endpoints (sensor-routes.ts).
 * Errors come back as { "error": "<message>" }.
 */

// Analyses and training can run for minutes
export const maxDuration = 300;

const MAX_JSON_BYTES = 16 * 1024;
// Vercel caps function request bodies at about 4.5 MB; reject larger
// uploads with a clear message instead of a platform error
const DEFAULT_MAX_UPLOAD_MB = 4;

function errorResponse(status: number, message: string): Response {
  return Response.json({ error: message }, { status, headers: { "Cache-Control": "no-store" } });
}

function maxUploadBytes(): number {
  const mb = Number(process.env.DASHBOARD_MAX_UPLOAD_MB);
  return (Number.isFinite(mb) && mb > 0 ? mb : DEFAULT_MAX_UPLOAD_MB) * 1024 * 1024;
}

/**
 * Reject cross-site requests for anything that changes state (CSRF).
 * Browsers always send Origin on these methods; requests without it are
 * refused too.
 */
function isSameOrigin(request: NextRequest): boolean {
  const origin = request.headers.get("origin");
  return origin !== null && origin === request.nextUrl.origin;
}

async function buildBody(
  request: NextRequest,
  route: SensorRoute,
): Promise<{ body?: BodyInit; headers: Record<string, string> } | Response> {
  if (route.body === "json") {
    if (!request.headers.get("content-type")?.startsWith("application/json")) {
      return errorResponse(415, "Expected a JSON body");
    }
    const text = await request.text();
    if (text.length > MAX_JSON_BYTES) return errorResponse(413, "Request body too large");
    return { body: text, headers: { "Content-Type": "application/json" } };
  }

  if (route.body === "upload") {
    const contentType = request.headers.get("content-type") ?? "";
    if (!contentType.startsWith("multipart/form-data")) {
      return errorResponse(415, "Expected a multipart/form-data upload");
    }
    const length = Number(request.headers.get("content-length"));
    if (!Number.isFinite(length) || length <= 0) {
      return errorResponse(411, "Upload must include a Content-Length");
    }
    const limit = maxUploadBytes();
    if (length > limit) {
      return errorResponse(
        413,
        `File is larger than the dashboard's ${Math.floor(limit / 1024 / 1024)} MB upload limit`,
      );
    }
    // Stream the upload straight through without buffering it in memory
    return {
      body: request.body ?? undefined,
      headers: { "Content-Type": contentType, "Content-Length": String(length) },
    };
  }

  return { headers: {} };
}

async function handle(
  request: NextRequest,
  ctx: RouteContext<"/api/sensor/[...path]">,
): Promise<Response> {
  const { path } = await ctx.params;
  const matched = matchSensorRoute(request.method, path.join("/"));
  if (!matched) return errorResponse(404, "Unknown sensor endpoint");

  if (request.method !== "GET" && !isSameOrigin(request)) {
    return errorResponse(403, "Cross-site request refused");
  }

  const { route, target } = matched;
  const built = await buildBody(request, route);
  if (built instanceof Response) return built;

  try {
    const upstream = await sensorFetch(target, {
      method: route.method,
      query: allowedQuery(route, request.nextUrl.searchParams),
      headers: built.headers,
      body: built.body,
      timeoutMs: route.timeoutMs,
    });

    if (upstream.ok) {
      // Stream the sensor's JSON through unchanged (exports can be large)
      return new Response(upstream.body, {
        status: upstream.status,
        headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
      });
    }

    const error = sensorError(upstream.status, await upstream.json().catch(() => null));
    // A sensor 401 means the dashboard's key is wrong (a server
    // misconfiguration), not that the user is signed out
    return errorResponse(error.status === 401 ? 502 : error.status, error.message);
  } catch (error) {
    if (error instanceof SocApiError) return errorResponse(error.status, error.message);
    if (error instanceof ConfigError) {
      return errorResponse(500, `Dashboard is not configured: ${error.message}`);
    }
    console.error("Sensor proxy failed", error);
    return errorResponse(500, "Unexpected error talking to the sensor");
  }
}

export { handle as GET, handle as POST, handle as DELETE };
