import { Suspense } from "react";

import { OverviewStats, OverviewStatsSkeleton } from "@/components/overview/overview-stats";
import { ThreatLegend } from "@/components/overview/threat-legend";
import { PageHeader } from "@/components/ui/page-header";

export default function OverviewPage() {
  return (
    <>
      <PageHeader title="Overview" description="Threat summary for your network sensor." />
      {/* Live sensor data: streamed per request, never cached */}
      <Suspense fallback={<OverviewStatsSkeleton />}>
        <OverviewStats />
      </Suspense>
      {/* Static: part of the prerendered shell, shows instantly */}
      <ThreatLegend />
    </>
  );
}
