import { StatCard, StatCardSkeleton } from "@/components/ui/stat-card";
import { SocApiError } from "@/lib/api-error";
import { formatDateTime, formatNumber } from "@/lib/format";
import { ConfigError } from "@/lib/server/config";
import { soc } from "@/lib/server/soc-client";
import type { SensorStatus } from "@/lib/types";

const GRID = "grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4";

/** Headline numbers from the sensor. Fetched fresh on every request. */
export async function OverviewStats() {
  let status: SensorStatus;
  try {
    status = await soc.status();
  } catch (error) {
    // Only handle sensor/config failures; anything else (including the
    // redirect to /login when signed out) must propagate
    if (error instanceof SocApiError || error instanceof ConfigError) {
      return (
        <div role="alert" className="border-threat-critical/40 bg-surface rounded-lg border p-4 text-sm">
          <p className="font-medium">Can&apos;t load sensor statistics</p>
          <p className="text-muted mt-1">{error.message}</p>
        </div>
      );
    }
    throw error;
  }

  const { stats, model } = status;

  return (
    <div className={GRID}>
      <StatCard
        label="Flows analyzed"
        value={formatNumber(stats.flows_analyzed)}
        hint={`Since ${formatDateTime(stats.start_time)}`}
      />
      <StatCard
        label="Threats detected"
        value={formatNumber(stats.threats_detected)}
        hint="Rated MEDIUM or higher"
        tone={stats.threats_detected > 0 ? "warning" : "default"}
      />
      <StatCard
        label="Critical"
        value={formatNumber(stats.critical_alerts)}
        hint={`${formatNumber(stats.ips_blocked)} IPs blocked`}
        tone={stats.critical_alerts > 0 ? "critical" : "default"}
      />
      <StatCard
        label="Detection model"
        value={model.trained ? "Trained" : "Not trained"}
        hint={
          model.trained
            ? `${formatNumber(model.training_samples ?? 0)} flows, ${formatDateTime(model.trained_at)}`
            : "Every flow is rated LOW until you train it"
        }
        tone={model.trained ? "ok" : "warning"}
      />
    </div>
  );
}

export function OverviewStatsSkeleton() {
  return (
    <div className={GRID} aria-busy="true" aria-label="Loading statistics">
      {Array.from({ length: 4 }, (_, i) => (
        <StatCardSkeleton key={i} />
      ))}
    </div>
  );
}
