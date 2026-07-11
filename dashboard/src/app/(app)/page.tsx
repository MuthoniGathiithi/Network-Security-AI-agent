import { Suspense } from "react";

import { OverviewStats, OverviewStatsSkeleton } from "@/components/overview/overview-stats";
import { PageHeader } from "@/components/ui/page-header";

export default function OverviewPage() {
  return (
    <>
      <PageHeader title="Overview" description="Threat summary for your network sensor." />
      {/* Live sensor data: streamed per request, never cached */}
      <Suspense fallback={<OverviewStatsSkeleton />}>
        <OverviewStats />
      </Suspense>
    </>
  );
}
