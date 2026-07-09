import "server-only";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { cache } from "react";

import { SESSION_COOKIE, signSession, verifySessionToken, type SessionPayload } from "@/lib/session-token";
import { getAuthConfig } from "./config";

/*
 * Session management (the dashboard's data access layer for auth).
 *
 * Every page, Server Action and Route Handler that touches sensor data
 * must call verifySession() / getSession() itself; proxy.ts redirects are
 * only an optimistic first check.
 */

/** Sign the operator in by setting the session cookie. */
export async function createSession(): Promise<void> {
  const { sessionSecret, sessionTtlSeconds } = getAuthConfig();
  const token = await signSession(sessionSecret, sessionTtlSeconds);
  (await cookies()).set(SESSION_COOKIE, token, {
    httpOnly: true, // not readable by JavaScript, so XSS can't steal it
    // Secure everywhere except plain-http local development
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: sessionTtlSeconds,
  });
}

/** Sign out by deleting the session cookie. */
export async function deleteSession(): Promise<void> {
  (await cookies()).delete(SESSION_COOKIE);
}

/**
 * The current session, or null if signed out or expired.
 * Memoized per request with React's cache.
 */
export const getSession = cache(async (): Promise<SessionPayload | null> => {
  const token = (await cookies()).get(SESSION_COOKIE)?.value;
  return verifySessionToken(getAuthConfig().sessionSecret, token);
});

/** The current session; redirects to /login when signed out. */
export async function verifySession(): Promise<SessionPayload> {
  const session = await getSession();
  if (!session) redirect("/login");
  return session;
}

/** Seconds until the current session expires (0 when signed out). */
export async function getSessionSecondsLeft(): Promise<number> {
  const session = await getSession();
  return session ? Math.max(0, session.exp - Math.floor(Date.now() / 1000)) : 0;
}
