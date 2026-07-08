import type { Metadata } from "next";
import { Suspense } from "react";

import { ShieldIcon } from "@/components/ui/icons";
import { LoginForm } from "./login-form";

export const metadata: Metadata = {
  title: "Sign in · SOC Dashboard",
};

export default function LoginPage() {
  return (
    <main className="flex flex-1 items-center justify-center px-4 py-12">
      <div className="border-line bg-surface w-full max-w-sm rounded-lg border p-6 shadow-sm">
        <div className="mb-6 flex items-center gap-2">
          <ShieldIcon className="text-accent size-6" />
          <h1 className="font-semibold tracking-tight">SOC Dashboard</h1>
        </div>
        <p className="text-muted mb-6 text-sm">Sign in to view and respond to threats on your network.</p>
        {/* useSearchParams needs a Suspense boundary under Cache Components */}
        <Suspense>
          <LoginForm />
        </Suspense>
      </div>
    </main>
  );
}
