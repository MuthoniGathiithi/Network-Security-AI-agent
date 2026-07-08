"use client";

import { useSearchParams } from "next/navigation";
import { useActionState } from "react";

import { login, type LoginState } from "./actions";

const initialState: LoginState = { error: null };

export function LoginForm() {
  const [state, formAction, pending] = useActionState(login, initialState);
  // Validated again on the server (safeNextPath) before redirecting
  const next = useSearchParams().get("next") ?? "/";

  return (
    <form action={formAction} className="space-y-4">
      <input type="hidden" name="next" value={next} />

      <div className="space-y-1.5">
        <label htmlFor="password" className="text-sm font-medium">
          Password
        </label>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          autoFocus
          aria-invalid={state.error ? true : undefined}
          aria-describedby={state.error ? "login-error" : undefined}
          className="border-line bg-background focus:border-accent focus:ring-accent/30 w-full rounded-md border px-3 py-2 text-sm outline-none focus:ring-2"
        />
      </div>

      <p id="login-error" role="alert" aria-live="polite" className="text-threat-critical min-h-5 text-sm">
        {state.error}
      </p>

      <button
        type="submit"
        disabled={pending}
        className="bg-accent text-accent-foreground hover:bg-accent/90 w-full rounded-md px-3 py-2 text-sm font-medium transition-colors disabled:opacity-60"
      >
        {pending ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}
