import { Suspense } from "react";

import { OverviewStats, OverviewStatsSkeleton } from "@/components/overview/overview-stats";
import { RecentThreats, RecentThreatsSkeleton } from "@/components/overview/recent-threats";
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
      {/* Separate boundary: each section shows as soon as its data arrives */}
      <Suspense fallback={<RecentThreatsSkeleton />}>
        <RecentThreats />
      </Suspense>
      {/* Static: part of the prerendered shell, shows instantly */}
      <ThreatLegend />
    </>
  );
}
