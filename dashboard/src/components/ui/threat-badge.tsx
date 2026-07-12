import type { ThreatLevel } from "@/lib/types";

/*
 * Full class names per level (Tailwind only generates classes it can see
 * written out in the source, so they can't be built from strings).
 */
const STYLES: Record<ThreatLevel, string> = {
  LOW: "text-threat-low bg-threat-low/10 border-threat-low/30",
  MEDIUM: "text-threat-medium bg-threat-medium/10 border-threat-medium/30",
  HIGH: "text-threat-high bg-threat-high/10 border-threat-high/30",
  CRITICAL: "text-threat-critical bg-threat-critical/15 border-threat-critical/40",
};

/**
 * Threat level as a labelled pill. The level is always written out, so the
 * meaning never depends on color alone.
 */
export function ThreatBadge({ level }: { level: ThreatLevel }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold tracking-wide ${STYLES[level]}`}
    >
      {level}
    </span>
  );
}
