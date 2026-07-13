import { SocApiError } from "@/lib/api-error";
import { ConfigError } from "@/lib/server/config";

/** True for failures we can show to the user as a message. */
export function isDisplayableError(error: unknown): error is SocApiError | ConfigError {
  return error instanceof SocApiError || error instanceof ConfigError;
}

/** Inline message for a section whose sensor data couldn't be loaded. */
export function SensorError({ title, error }: { title: string; error: SocApiError | ConfigError }) {
  return (
    <div role="alert" className="border-threat-critical/40 bg-surface rounded-lg border p-4 text-sm">
      <p className="font-medium">{title}</p>
      <p className="text-muted mt-1">{error.message}</p>
    </div>
  );
}
