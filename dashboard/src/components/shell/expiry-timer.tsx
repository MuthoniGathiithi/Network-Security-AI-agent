"use client";

import { useEffect } from "react";

import { redirectToLogin } from "@/lib/sensor-client";

/**
 * Sends the user to the login page when their session runs out.
 *
 * Needed because pages prefetched while signed in can still be shown from
 * the browser's cache after expiry, without a request that proxy.ts could
 * redirect. Uses seconds remaining (computed on the server) rather than an
 * absolute time, so a wrong clock on the user's machine doesn't matter.
 */
export function ExpiryTimer({ secondsLeft }: { secondsLeft: number }) {
  useEffect(() => {
    const expire = () => {
      try {
        redirectToLogin();
      } catch {
        // redirectToLogin throws to stop callers; nothing to stop here
      }
    };
    if (secondsLeft <= 0) {
      expire();
      return;
    }
    const timer = window.setTimeout(expire, secondsLeft * 1000);
    return () => window.clearTimeout(timer);
  }, [secondsLeft]);

  return null;
}
