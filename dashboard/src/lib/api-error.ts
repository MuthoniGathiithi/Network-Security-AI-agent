/*
 * Error type for failed sensor calls, plus normalization of the API's
 * error bodies. Shared by server and client code.
 */

export class SocApiError extends Error {
  /** HTTP status from the sensor, or 502/504 when it couldn't be reached */
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "SocApiError";
    this.status = status;
  }
}

/**
 * Turn a FastAPI error body into one readable message.
 *
 * The sensor returns `detail` in three shapes:
 *   - a string (most errors)
 *   - a failed ResponseAction object (e.g. blocking an invalid IP), with
 *     the reason in `details.error` or `details.message`
 *   - a list of validation errors `[{loc, msg}, ...]`
 */
export function errorMessageFromBody(body: unknown, fallback: string): string {
  const detail = (body as { detail?: unknown } | null)?.detail;

  if (typeof detail === "string" && detail) return detail;

  if (Array.isArray(detail)) {
    const messages = detail
      .map((item) => {
        const { loc, msg } = (item ?? {}) as { loc?: unknown[]; msg?: string };
        const field = Array.isArray(loc) ? loc.filter((p) => p !== "body").join(".") : "";
        return msg ? (field ? `${field}: ${msg}` : msg) : null;
      })
      .filter(Boolean);
    if (messages.length) return messages.join("; ");
  }

  if (detail && typeof detail === "object") {
    const details = (detail as { details?: Record<string, unknown> }).details;
    const reason = details?.error ?? details?.message;
    if (typeof reason === "string" && reason) return reason;
  }

  return fallback;
}
