"use server";

import { redirect } from "next/navigation";

import { safeNextPath } from "@/lib/safe-redirect";
import { ConfigError, getAuthConfig } from "@/lib/server/config";
import { verifyPassword } from "@/lib/server/password";
import { createSession } from "@/lib/server/session";

export type LoginState = { error: string | null };

// Every failed attempt takes at least this long, so guessing is slow and
// a wrong password can't be told apart from other failures by timing
const MIN_FAILURE_MS = 750;

async function failSlowly(started: number, error: string): Promise<LoginState> {
  const remaining = MIN_FAILURE_MS - (Date.now() - started);
  if (remaining > 0) await new Promise((resolve) => setTimeout(resolve, remaining));
  return { error };
}

/**
 * Sign in with the dashboard password.
 *
 * Reachable by direct POST like every Server Action; it only ever creates
 * a session after the password checks out.
 */
export async function login(_prev: LoginState, formData: FormData): Promise<LoginState> {
  const started = Date.now();
  const password = formData.get("password");

  let passwordHash: string;
  try {
    passwordHash = getAuthConfig().passwordHash;
  } catch (error) {
    if (error instanceof ConfigError) {
      // Details go to the server log, not to whoever is on the login page
      console.error(`Sign-in is not configured: ${error.message}`);
      return { error: "Sign-in isn't configured on this dashboard. See dashboard/.env.example." };
    }
    throw error;
  }

  if (typeof password !== "string" || !(await verifyPassword(password, passwordHash))) {
    return failSlowly(started, "Incorrect password");
  }

  await createSession();
  redirect(safeNextPath(formData.get("next")));
}
