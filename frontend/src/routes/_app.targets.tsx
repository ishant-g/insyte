import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";

import { scansApi } from "@/api/scans";
import type { ScanListItem } from "@/api/types";
import { PageHeader } from "@/components/page-header";
import { QuerySection } from "@/components/async-state";
import { DataTable, type DataColumn } from "@/components/data-table";
import { ScanStatusBadge } from "@/components/scan-status-badge";
import { ExposureBandBadge } from "@/components/severity-badge";
import { formatDateTime, formatNumber } from "@/lib/format";
import { Button } from "@/components/ui/button";
import { Plus } from "lucide-react";

export const Route = createFileRoute("/_app/targets")({
  component: Targets,
});

const FETCH_LIMIT = 200;

interface TargetSummary {
  target_value: string;
  target_type: string;
  scan_count: number;
  latest: ScanListItem;
}

// There is no dedicated /api/targets endpoint - targets are derived
// client-side by grouping recent scans by target_value. Capped at the most
// recent FETCH_LIMIT scans; if that cap is hit, older targets that only
// ever had earlier scans won't appear (surfaced via the note below rather
// than silently dropped).
function groupByTarget(scans: ScanListItem[]): TargetSummary[] {
  const map = new Map<string, TargetSummary>();
  for (const scan of scans) {
    const existing = map.get(scan.target_value);
    if (!existing) {
      map.set(scan.target_value, {
        target_value: scan.target_value,
        target_type: scan.target_type,
        scan_count: 1,
        latest: scan,
      });
    } else {
      existing.scan_count += 1;
      if (new Date(scan.created_at) > new Date(existing.latest.created_at)) {
        existing.latest = scan;
      }
    }
  }
  return Array.from(map.values()).sort(
    (a, b) => new Date(b.latest.created_at).getTime() - new Date(a.latest.created_at).getTime(),
  );
}

function Targets() {
  const scans = useQuery({
    queryKey: ["scans", "for-targets"],
    queryFn: () => scansApi.list({ limit: FETCH_LIMIT, offset: 0 }),
  });

  const targets = scans.data ? groupByTarget(scans.data.items) : undefined;

  const columns: DataColumn<TargetSummary>[] = [
    {
      key: "target",
      header: "Target",
      cell: (row) => (
        <Link
          to="/scans/$scanId"
          params={{ scanId: row.latest.id }}
          className="font-mono font-medium text-foreground hover:text-primary"
        >
          {row.target_value}
        </Link>
      ),
    },
    { key: "type", header: "Type", cell: (row) => <span className="text-muted-foreground">{row.target_type}</span> },
    { key: "scans", header: "Scans", cell: (row) => formatNumber(row.scan_count) },
    {
      key: "status",
      header: "Latest status",
      cell: (row) => <ScanStatusBadge status={row.latest.status} progress={row.latest.progress} />,
    },
    {
      key: "exposure",
      header: "Latest exposure",
      cell: (row) => (row.latest.exposure_band ? <ExposureBandBadge band={row.latest.exposure_band} /> : <span className="text-muted-foreground">-</span>),
    },
    {
      key: "last-scanned",
      header: "Last scanned",
      cell: (row) => <span className="text-muted-foreground">{formatDateTime(row.latest.created_at)}</span>,
    },
  ];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Targets"
        description="Domains and IPs that have been scanned before, grouped from scan history."
        actions={
          <Button asChild size="sm">
            <Link to="/new-scan">
              <Plus className="h-4 w-4" />
              New scan
            </Link>
          </Button>
        }
      />

      <QuerySection
        isLoading={scans.isLoading}
        isError={scans.isError}
        error={scans.error}
        onRetry={() => scans.refetch()}
        data={targets}
        isEmpty={(d) => d.length === 0}
        emptyTitle="No targets scanned yet"
        emptyDescription="Run your first scan to see it appear here."
      >
        {(data) => (
          <div className="flex flex-col gap-2">
            <DataTable columns={columns} rows={data} rowKey={(r) => r.target_value} />
            {scans.data && scans.data.total > FETCH_LIMIT && (
              <p className="text-xs text-muted-foreground">
                Showing targets from the {FETCH_LIMIT} most recent scans out of {formatNumber(scans.data.total)} total.
                older targets may not be listed.
              </p>
            )}
          </div>
        )}
      </QuerySection>
    </div>
  );
}
