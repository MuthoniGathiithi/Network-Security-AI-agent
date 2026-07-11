import type { ReactNode } from "react";

type Tone = "default" | "critical" | "warning" | "ok";

const TONE_CLASS: Record<Tone, string> = {
  default: "text-foreground",
  critical: "text-threat-critical",
  warning: "text-threat-medium",
  ok: "text-threat-low",
};

type StatCardProps = {
  label: string;
  value: ReactNode;
  /** Short supporting line under the value */
  hint?: ReactNode;
  tone?: Tone;
};

export function StatCard({ label, value, hint, tone = "default" }: StatCardProps) {
  return (
    <div className="border-line bg-surface rounded-lg border p-4">
      <p className="text-muted text-sm">{label}</p>
      <p className={`mt-1 text-2xl font-semibold tabular-nums ${TONE_CLASS[tone]}`}>{value}</p>
      {hint && <p className="text-muted mt-1 text-xs">{hint}</p>}
    </div>
  );
}

/** Placeholder with the same size as a StatCard, shown while loading. */
export function StatCardSkeleton() {
  return (
    <div className="border-line bg-surface rounded-lg border p-4" aria-hidden="true">
      <div className="bg-surface-raised h-4 w-24 animate-pulse rounded" />
      <div className="bg-surface-raised mt-2 h-7 w-16 animate-pulse rounded" />
      <div className="bg-surface-raised mt-2 h-3 w-32 animate-pulse rounded" />
    </div>
  );
}
