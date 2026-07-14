import { SensorError, isDisplayableError } from "@/components/ui/sensor-error";
import { formatNumber } from "@/lib/format";
import { soc } from "@/lib/server/soc-client";
import { THREAT_LEVELS, type Detection, type ThreatLevel } from "@/lib/types";

// The sensor keeps at most this many detections in memory (DetectionAgent
// max_history), so the chart covers that window
const MAX_DETECTIONS = 10_000;

const FILL: Record<ThreatLevel, string> = {
  LOW: "bg-threat-low-fill",
  MEDIUM: "bg-threat-medium-fill",
  HIGH: "bg-threat-high-fill",
  CRITICAL: "bg-threat-critical-fill",
};

function Frame({ total, children }: { total?: number; children: React.ReactNode }) {
  return (
    <section aria-labelledby="threat-distribution" className="border-line bg-surface mt-6 rounded-lg border">
      <div className="border-line border-b px-4 py-3">
        <h2 id="threat-distribution" className="text-sm font-medium">
          Detections by threat level
        </h2>
        <p className="text-muted mt-0.5 text-xs">
          {total === undefined
            ? "Loading…"
            : `${formatNumber(total)} most recent flows the sensor has kept in memory`}
        </p>
      </div>
      {children}
    </section>
  );
}

/**
 * Horizontal bar chart of detection counts per level, built as a table:
 * the level, a bar sized to the largest count, and the value at the bar's
 * tip. Every value is printed, so nothing depends on hovering or on color.
 */
export async function ThreatDistribution() {
  let detections: Detection[];
  try {
    detections = await soc.detections({ limit: MAX_DETECTIONS });
  } catch (error) {
    if (isDisplayableError(error)) {
      return (
        <div className="mt-6">
          <SensorError title="Can't load threat levels" error={error} />
        </div>
      );
    }
    throw error;
  }

  const counts = Object.fromEntries(THREAT_LEVELS.map((l) => [l, 0])) as Record<ThreatLevel, number>;
  for (const d of detections) counts[d.threat_level] += 1;
  const total = detections.length;
  const max = Math.max(1, ...Object.values(counts));

  if (total === 0) {
    return (
      <Frame total={0}>
        <p className="text-muted px-4 py-8 text-center text-sm">No flows analyzed yet.</p>
      </Frame>
    );
  }

  return (
    <Frame total={total}>
      <table className="w-full text-sm">
        <caption className="sr-only">Number of detections at each threat level</caption>
        <thead className="sr-only">
          <tr>
            <th scope="col">Threat level</th>
            <th scope="col">Detections</th>
          </tr>
        </thead>
        <tbody>
          {THREAT_LEVELS.map((level) => {
            const count = counts[level];
            const share = count / total;
            // Non-zero counts get at least 4px so they stay visible on
            // narrow screens; zero gets no bar
            const width = count === 0 ? "0" : `max(${(count / max) * 100}%, 4px)`;
            return (
              <tr key={level} className="hover:bg-surface-raised transition-colors">
                <th scope="row" className="w-24 py-2.5 pr-3 pl-4 text-left text-xs font-semibold tracking-wide">
                  {level}
                </th>
                <td className="py-2.5 pr-4">
                  <div className="flex items-center gap-2">
                    <div className="min-w-0 flex-1">
                      <div
                        aria-hidden="true"
                        // Rounded at the value end, square at the baseline
                        className={`h-3 rounded-r-[4px] ${FILL[level]}`}
                        style={{ width }}
                      />
                    </div>
                    <span className="w-28 shrink-0 text-right tabular-nums">
                      {formatNumber(count)}
                      <span className="text-muted ml-1 text-xs">({Math.round(share * 100)}%)</span>
                    </span>
                  </div>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </Frame>
  );
}

export function ThreatDistributionSkeleton() {
  return (
    <Frame>
      <div className="space-y-4 px-4 py-4" aria-busy="true" aria-label="Loading threat levels">
        {[90, 40, 20, 8].map((w) => (
          <div key={w} className="flex items-center gap-3">
            <div className="bg-surface-raised h-3 w-14 animate-pulse rounded" />
            <div className="bg-surface-raised h-3 animate-pulse rounded" style={{ width: `${w * 0.7}%` }} />
          </div>
        ))}
      </div>
    </Frame>
  );
}
