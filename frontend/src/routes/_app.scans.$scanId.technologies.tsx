import { useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";

import { scansApi } from "@/api/scans";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/page-header";
import { QuerySection } from "@/components/async-state";
import { ScanEmptyState } from "@/components/scan-empty-state";
import { DataTable, PaginationBar, type DataColumn } from "@/components/data-table";
import { ConfidenceBadge } from "@/components/severity-badge";
import type { TechnologyRead } from "@/api/types";

export const Route = createFileRoute("/_app/scans/$scanId/technologies")({
  component: TechnologiesPage,
});

const LIMIT = 25;

function TechnologiesPage() {
  const { scanId } = Route.useParams();
  const [category, setCategory] = useState("all");
  const [offset, setOffset] = useState(0);

  // Cheap snapshot fetch purely to build the category filter's option list -
  // Cloud resources are folded into this Technologies view (filtered by
  // category) rather than a separate page, per the product's nav design.
  const snapshot = useQuery({
    queryKey: ["technologies", scanId, "categories-snapshot"],
    queryFn: () => scansApi.technologies(scanId, { limit: 200, offset: 0 }),
  });

  const categories = useMemo(() => {
    const set = new Set<string>();
    for (const t of snapshot.data?.items ?? []) if (t.category) set.add(t.category);
    return Array.from(set).sort();
  }, [snapshot.data]);

  const technologies = useQuery({
    queryKey: ["technologies", scanId, category, offset],
    queryFn: () => scansApi.technologies(scanId, { category: category === "all" ? undefined : category, limit: LIMIT, offset }),
  });

  const columns: DataColumn<TechnologyRead>[] = [
    {
      key: "name",
      header: "Technology",
      cell: (row) => (
        <div>
          <span className="font-medium text-foreground">{row.name}</span>
          {row.version && <span className="ml-1.5 font-mono text-xs text-muted-foreground">{row.version}</span>}
        </div>
      ),
    },
    { key: "category", header: "Category", cell: (row) => row.category ?? "-" },
    { key: "vendor", header: "Vendor", cell: (row) => <span className="text-muted-foreground">{row.vendor ?? "-"}</span> },
    { key: "host", header: "Host", cell: (row) => <span className="font-mono text-xs text-muted-foreground">{row.host ?? "-"}</span> },
    {
      key: "version-confidence",
      header: "Version confidence",
      cell: (row) => (row.version ? <ConfidenceBadge value={row.version_confidence} /> : <span className="text-muted-foreground">-</span>),
    },
    { key: "confidence", header: "Confidence", cell: (row) => <ConfidenceBadge value={row.confidence} /> },
  ];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Technologies"
        description="Fingerprinted software, frameworks, and cloud resources. Filter by category to view cloud infrastructure."
      />

      <Select value={category} onValueChange={(v) => { setCategory(v); setOffset(0); }}>
        <SelectTrigger className="w-56">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All categories</SelectItem>
          {categories.map((c) => (
            <SelectItem key={c} value={c}>
              {c}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <QuerySection
        isLoading={technologies.isLoading}
        isError={technologies.isError}
        error={technologies.error}
        onRetry={() => technologies.refetch()}
        data={technologies.data}
        isEmpty={(d) => d.items.length === 0}
        emptyTitle="No technologies fingerprinted"
        emptyState={
          <ScanEmptyState
            title="No technologies fingerprinted"
            moduleIds={["technology_intelligence", "web_surface"]}
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
