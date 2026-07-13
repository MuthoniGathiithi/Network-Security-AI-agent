import Link from "next/link";

import { SensorError, isDisplayableError } from "@/components/ui/sensor-error";
import { ThreatBadge } from "@/components/ui/threat-badge";
import { formatDateTime } from "@/lib/format";
import { soc } from "@/lib/server/soc-client";
import type { Detection } from "@/lib/types";

const LIMIT = 8;

function Frame({ children }: { children: React.ReactNode }) {
  return (
    <section aria-labelledby="recent-threats" className="border-line bg-surface mt-6 rounded-lg border">
      <div className="border-line flex items-center justify-between border-b px-4 py-3">
        <h2 id="recent-threats" className="text-sm font-medium">
          Recent high and critical threats
        </h2>
        <Link href="/detections?min_level=HIGH" className="text-accent text-sm hover:underline">
          View all
        </Link>
      </div>
      {children}
    </section>
  );
}

/** The latest HIGH and CRITICAL detections, newest first. */
export async function RecentThreats() {
  let detections: Detection[];
  try {
    detections = await soc.detections({ minLevel: "HIGH", limit: LIMIT });
  } catch (error) {
    if (isDisplayableError(error)) {
      return (
        <div className="mt-6">
          <SensorError title="Can't load recent threats" error={error} />
        </div>
      );
    }
    throw error;
  }

  if (detections.length === 0) {
    return (
      <Frame>
        <p className="text-muted px-4 py-8 text-center text-sm">No high or critical threats so far.</p>
      </Frame>
    );
  }

  return (
    <Frame>
      <ul className="divide-line divide-y">
        {detections.map((d, i) => (
          // Detections have no ID; time + endpoints + index is unique enough here
          <li
            key={`${d.timestamp}-${d.src_ip}-${d.dst_ip}-${i}`}
            className="flex flex-wrap items-center gap-x-4 gap-y-1 px-4 py-3 text-sm"
          >
            <ThreatBadge level={d.threat_level} />
            <span className="min-w-32 font-medium">{d.attack_type}</span>
            <span className="text-muted font-mono text-xs">
              {d.src_ip} <span aria-label="to">→</span> {d.dst_ip}
            </span>
            <span className="text-muted ml-auto text-xs tabular-nums">{formatDateTime(d.timestamp)}</span>
          </li>
        ))}
      </ul>
    </Frame>
  );
}

export function RecentThreatsSkeleton() {
  return (
    <Frame>
      <ul className="divide-line divide-y" aria-busy="true" aria-label="Loading recent threats">
        {Array.from({ length: 4 }, (_, i) => (
          <li key={i} className="flex items-center gap-4 px-4 py-3">
            <div className="bg-surface-raised h-5 w-16 animate-pulse rounded-full" />
            <div className="bg-surface-raised h-4 w-28 animate-pulse rounded" />
            <div className="bg-surface-raised h-3 w-40 animate-pulse rounded" />
          </li>
        ))}
      </ul>
    </Frame>
  );
}
