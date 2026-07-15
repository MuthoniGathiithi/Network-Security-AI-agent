import { Suspense } from "react";

import { DetectionsTable, DetectionsTableSkeleton } from "@/components/detections/detections-table";
import { PageHeader } from "@/components/ui/page-header";

export default function DetectionsPage() {
  return (
    <>
      <PageHeader title="Detections" description="Flows the agent analyzed, newest first." />
      <Suspense fallback={<DetectionsTableSkeleton />}>
        <DetectionsTable />
      </Suspense>
    </>
  );
}
