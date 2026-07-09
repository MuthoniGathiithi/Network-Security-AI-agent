"use server";

import { redirect } from "next/navigation";

import { deleteSession } from "@/lib/server/session";

/**
 * Sign out: delete the session cookie and return to the login page.
 *
 * A Server Action is always a POST checked against the page's origin, so
 * another site can't sign you out with a link or image tag.
 */
export async function logout(): Promise<void> {
  await deleteSession();
  redirect("/login");
}
