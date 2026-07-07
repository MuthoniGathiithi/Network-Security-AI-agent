import { NextResponse, type NextRequest } from "next/server";

import { SESSION_COOKIE, verifySessionToken } from "@/lib/session-token";

/*
 * Optimistic auth redirects for pages.
 *
 * Only checks the session cookie's signature and expiry; the real check
 * happens next to the data (soc-client and the /api/sensor route), so a
 * page can't leak sensor data even if this is bypassed or misconfigured.
 */

const LOGIN_PATH = "/login";

export default async function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  const secret = process.env.SESSION_SECRET;

  // Unconfigured or too-short secret: treat as signed out and let the
  // login page explain the configuration problem
  const session =
    secret && secret.length >= 32
      ? await verifySessionToken(secret, request.cookies.get(SESSION_COOKIE)?.value)
      : null;

  if (pathname === LOGIN_PATH) {
    // Already signed in: skip the login form
    return session ? NextResponse.redirect(new URL("/", request.url)) : NextResponse.next();
  }

  if (!session) {
    const login = new URL(LOGIN_PATH, request.url);
    if (pathname !== "/") login.searchParams.set("next", `${pathname}${search}`);
    return NextResponse.redirect(login);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    /*
     * Every page except:
     * - api: route handlers check the session themselves (and the proxy
     *   would buffer pcap uploads in memory, truncating large ones)
     * - _next/static, _next/image, favicon.ico: assets the login page needs
     */
    "/((?!api|_next/static|_next/image|favicon.ico).*)",
  ],
};
