import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";

import { scansApi } from "@/api/scans";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/page-header";
import { QuerySection } from "@/components/async-state";
import { ScanEmptyState } from "@/components/scan-empty-state";
import { DataTable, PaginationBar, type DataColumn } from "@/components/data-table";
import { formatDate, titleCase } from "@/lib/format";
import type { HistoricalEventRead } from "@/api/types";

export const Route = createFileRoute("/_app/scans/$scanId/historical")({
  component: HistoricalPage,
});

const LIMIT = 25;
const currentYear = new Date().getFullYear();
const YEARS = Array.from({ length: 15 }, (_, i) => currentYear - i);

function HistoricalPage() {
  const { scanId } = Route.useParams();
  const [year, setYear] = useState("all");
  const [offset, setOffset] = useState(0);

  const events = useQuery({
    queryKey: ["historical", scanId, year, offset],
    queryFn: () => scansApi.historical(scanId, { year: year === "all" ? undefined : Number(year), limit: LIMIT, offset }),
  });

  const columns: DataColumn<HistoricalEventRead>[] = [
    { key: "value", header: "Value", cell: (row) => <span className="break-all font-mono text-xs text-foreground">{row.value}</span> },
    { key: "type", header: "Type", cell: (row) => <Badge variant="outline">{titleCase(row.asset_type)}</Badge> },
    { key: "source", header: "Source", cell: (row) => <span className="text-xs text-muted-foreground">{row.source_id}</span> },
    { key: "status", header: "Status", cell: (row) => row.status },
    { key: "first-seen", header: "First seen", cell: (row) => <span className="text-muted-foreground">{formatDate(row.first_seen)}</span> },
    { key: "last-seen", header: "Last seen", cell: (row) => <span className="text-muted-foreground">{formatDate(row.last_seen)}</span> },
    { key: "year", header: "Year", cell: (row) => row.year ?? "-" },
  ];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Historical intelligence"
        description="Observations sourced from Wayback Machine, Common Crawl, and URLScan archives."
      />

      <Select value={year} onValueChange={(v) => { setYear(v); setOffset(0); }}>
        <SelectTrigger className="w-40">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All years</SelectItem>
          {YEARS.map((y) => (
            <SelectItem key={y} value={String(y)}>
              {y}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <QuerySection
        isLoading={events.isLoading}
        isError={events.isError}
        error={events.error}
        onRetry={() => events.refetch()}
        data={events.data}
        isEmpty={(d) => d.items.length === 0}
        emptyTitle="No historical observations available"
        emptyDescription="No archived records were found for this target, or the historical modules weren't run."
        emptyState={
          <ScanEmptyState
            title="No historical observations available"
            moduleIds={["historical_intelligence"]}
          />
        }
      >
        {(data) => (
          <div className="flex flex-col gap-2">
            <DataTable columns={columns} rows={data.items} rowKey={(r) => r.id} />
            <PaginationBar offset={offset} limit={LIMIT} total={data.total} onOffsetChange={setOffset} />
          </div>
        )}
      </QuerySection>
    </div>
  );
}
