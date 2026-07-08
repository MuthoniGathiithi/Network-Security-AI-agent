/**
 * Validate a post-login redirect target from ?next=.
 *
 * Only same-site paths are allowed. Rejects absolute URLs
 * (https://evil.example), protocol-relative URLs (//evil.example),
 * backslash tricks (/\evil.example, which browsers treat like //), and
 * anything else that could send the user to another site after signing in.
 *
 * @returns the path if safe, otherwise "/"
 */
export function safeNextPath(raw: unknown): string {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 2048) return "/";
  if (!raw.startsWith("/") || raw.startsWith("//") || raw.startsWith("/\\")) return "/";
  // Control characters and backslashes have no place in our paths
  if (/[\u0000-\u001f\u007f\\]/.test(raw)) return "/";

  // Parse against a dummy origin: anything resolving elsewhere is rejected
  const base = "http://dashboard.invalid";
  let url: URL;
  try {
    url = new URL(raw, base);
  } catch {
    return "/";
  }
  if (url.origin !== base) return "/";
  if (url.pathname === "/login") return "/";
  return `${url.pathname}${url.search}${url.hash}`;
}
