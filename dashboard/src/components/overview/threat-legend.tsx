import { ThreatBadge } from "@/components/ui/threat-badge";
import type { ThreatLevel } from "@/lib/types";

// Mirrors the backend: thresholds in DetectionAgent.calibrate(), actions in
// ResponseAgent.respond_to_detection()
const LEVELS: { level: ThreatLevel; meaning: string; action: string }[] = [
  { level: "LOW", meaning: "Looks like normal traffic.", action: "Logged only." },
  {
    level: "MEDIUM",
    meaning: "Unusual: scored above 99% of the traffic the model was trained on.",
    action: "Logged only.",
  },
  {
    level: "HIGH",
    meaning: "More unusual than anything in the training traffic, or part of a port scan.",
    action: "Alert sent to Slack or webhooks.",
  },
  {
    level: "CRITICAL",
    meaning: "Far outside normal traffic.",
    action: "Alert sent. The source IP is blocked if auto-block is on.",
  },
];

/** Static explanation of what each threat level means. */
export function ThreatLegend() {
  return (
    <section aria-labelledby="threat-levels" className="border-line bg-surface mt-6 rounded-lg border">
      <h2 id="threat-levels" className="border-line border-b px-4 py-3 text-sm font-medium">
        Threat levels
      </h2>
      <dl className="divide-line divide-y">
        {LEVELS.map(({ level, meaning, action }) => (
          <div key={level} className="grid gap-1 px-4 py-3 text-sm sm:grid-cols-[7rem_1fr_1fr] sm:gap-4">
            <dt>
              <ThreatBadge level={level} />
            </dt>
            <dd>{meaning}</dd>
            <dd className="text-muted">{action}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}
