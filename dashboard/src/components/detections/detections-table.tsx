import { SensorError, isDisplayableError } from "@/components/ui/sensor-error";
import { ThreatBadge } from "@/components/ui/threat-badge";
import { formatDateTime, formatNumber } from "@/lib/format";
import { soc } from "@/lib/server/soc-client";
import type { Detection } from "@/lib/types";

export const DETECTIONS_LIMIT = 200;

const COLUMNS = ["Time", "Level", "Attack type", "Source", "Destination", "Confidence", "ML score", "MITRE"];

function TableFrame({ children, caption }: { children: React.ReactNode; caption: string }) {
  return (
    // Only the table scrolls sideways on small screens, not the page
    <div className="border-line bg-surface overflow-x-auto rounded-lg border">
      <table className="w-full min-w-[56rem] text-left text-sm">
        <caption className="sr-only">{caption}</caption>
        <thead className="border-line text-muted border-b text-xs">
          <tr>
            {COLUMNS.map((c) => (
              <th key={c} scope="col" className="px-4 py-2.5 font-medium whitespace-nowrap">
                {c}
              </th>
            ))}
          </tr>
        </thead>
        {children}
      </table>
    </div>
  );
}

/** Newest detections first, one row per analyzed flow. */
export async function DetectionsTable() {
  let detections: Detection[];
  try {
    detections = await soc.detections({ limit: DETECTIONS_LIMIT });
  } catch (error) {
    if (isDisplayableError(error)) return <SensorError title="Can't load detections" error={error} />;
    throw error;
  }

  if (detections.length === 0) {
    return (
      <div className="border-line bg-surface text-muted rounded-lg border px-4 py-12 text-center text-sm">
        No detections yet. Analyze a capture or start live capture to see results here.
      </div>
    );
  }

  return (
    <>
      <TableFrame caption="Detections, newest first">
        <tbody className="divide-line divide-y">
          {detections.map((d, i) => (
            <tr key={`${d.timestamp}-${d.src_ip}-${d.dst_ip}-${i}`} className="hover:bg-surface-raised">
              <td className="text-muted px-4 py-2.5 text-xs whitespace-nowrap tabular-nums">
                {formatDateTime(d.timestamp)}
              </td>
              <td className="px-4 py-2.5">
                <ThreatBadge level={d.threat_level} />
              </td>
              <td className="px-4 py-2.5 whitespace-nowrap">{d.attack_type}</td>
              <td className="px-4 py-2.5 font-mono text-xs">{d.src_ip}</td>
              <td className="px-4 py-2.5 font-mono text-xs">{d.dst_ip}</td>
              <td className="px-4 py-2.5 tabular-nums">{Math.round(d.confidence * 100)}%</td>
              <td className="px-4 py-2.5 tabular-nums">{d.ml_score.toFixed(2)}</td>
              <td className="px-4 py-2.5 font-mono text-xs whitespace-nowrap">
                {d.mitre_techniques.join(", ")}
              </td>
            </tr>
          ))}
        </tbody>
      </TableFrame>
      <p className="text-muted mt-3 text-xs">
        {detections.length === DETECTIONS_LIMIT
          ? `Showing the newest ${formatNumber(DETECTIONS_LIMIT)} detections.`
          : `${formatNumber(detections.length)} detections.`}
      </p>
    </>
  );
}

export function DetectionsTableSkeleton() {
  return (
    <TableFrame caption="Loading detections">
      <tbody className="divide-line divide-y" aria-busy="true">
        {Array.from({ length: 8 }, (_, i) => (
          <tr key={i}>
            {COLUMNS.map((c) => (
              <td key={c} className="px-4 py-3">
                <div className="bg-surface-raised h-4 w-full max-w-24 animate-pulse rounded" />
              </td>
            ))}
          </tr>
        ))}
      </tbody>
    </TableFrame>
  );
}
