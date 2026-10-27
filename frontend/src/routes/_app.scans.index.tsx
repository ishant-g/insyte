import { useState } from "react";
import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Plus } from "lucide-react";

import { scansApi } from "@/api/scans";
import type { ScanStatus } from "@/api/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/page-header";
import { QuerySection } from "@/components/async-state";
import { DataTable, PaginationBar, type DataColumn } from "@/components/data-table";
import { ScanStatusBadge } from "@/components/scan-status-badge";
import { ExposureBandBadge } from "@/components/severity-badge";
import { formatDateTime, titleCase } from "@/lib/format";
import type { ScanListItem } from "@/api/types";

export const Route = createFileRoute("/_app/scans/")({
  component: ScansList,
});

const STATUSES: ScanStatus[] = ["queued", "running", "partial", "completed", "failed", "cancelled"];
const LIMIT = 25;

function ScansList() {
  const [status, setStatus] = useState<string>("all");
  const [target, setTarget] = useState("");
  const [offset, setOffset] = useState(0);

  const scans = useQuery({
    queryKey: ["scans", "list", status, target, offset],
    queryFn: () =>
      scansApi.list({
        limit: LIMIT,
        offset,
        status: status === "all" ? undefined : status,
        target: target.trim() || undefined,
      }),
  });

  const columns: DataColumn<ScanListItem>[] = [
    {
      key: "target",
      header: "Target",
      cell: (row) => (
        <Link to="/scans/$scanId" params={{ scanId: row.id }} className="font-mono font-medium text-foreground hover:text-primary">
          {row.target_value}
        </Link>
      ),
    },
    { key: "type", header: "Type", cell: (row) => <span className="text-muted-foreground">{row.target_type}</span> },
    { key: "mode", header: "Mode", cell: (row) => (row.mode === "passive" ? "Passive" : "Web Surface") },
    { key: "status", header: "Status", cell: (row) => <ScanStatusBadge status={row.status} progress={row.progress} /> },
    {
      key: "exposure",
      header: "Exposure",
      cell: (row) => (row.exposure_band ? <ExposureBandBadge band={row.exposure_band} /> : <span className="text-muted-foreground">-</span>),
    },
    { key: "created", header: "Created", cell: (row) => <span className="text-muted-foreground">{formatDateTime(row.created_at)}</span> },
  ];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Scans"
        description="Every scan run on this deployment, across all targets."
        actions={
          <Button asChild size="sm">
            <Link to="/new-scan">
              <Plus className="h-4 w-4" />
              New scan
            </Link>
          </Button>
        }
      />

      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Filter by target…"
          value={target}
          onChange={(e) => {
            setTarget(e.target.value);
            setOffset(0);
          }}
          className="max-w-xs font-mono"
        />
        <Select
          value={status}
          onValueChange={(v) => {
            setStatus(v);
            setOffset(0);
          }}
        >
          <SelectTrigger className="w-44">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            {STATUSES.map((s) => (
              <SelectItem key={s} value={s}>
                {titleCase(s)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>

      <QuerySection
        isLoading={scans.isLoading}
        isError={scans.isError}
        error={scans.error}
        onRetry={() => scans.refetch()}
        data={scans.data}
        isEmpty={(d) => d.items.length === 0}
        emptyTitle="No scans found"
        emptyDescription="Try a different filter, or start a new scan."
      >
        {(data) => (
          <div className="flex flex-col gap-3">
            <DataTable columns={columns} rows={data.items} rowKey={(r) => r.id} />
            <PaginationBar offset={offset} limit={LIMIT} total={data.total} onOffsetChange={setOffset} />
          </div>
        )}
      </QuerySection>
    </div>
  );
}
