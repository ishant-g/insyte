import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";

import { useMergedAssets } from "@/hooks/use-merged-assets";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/page-header";
import { LoadingBlock, ErrorBlock } from "@/components/async-state";
import { ScanEmptyState } from "@/components/scan-empty-state";
import { DataTable, PaginationBar, type DataColumn } from "@/components/data-table";
import { ConfidenceBadge } from "@/components/severity-badge";
import { formatDate, formatNumber, titleCase } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { AssetRead } from "@/api/types";

export const Route = createFileRoute("/_app/scans/$scanId/domains")({
  component: DomainsPage,
});

const LIMIT = 25;
const TYPES = ["domain", "subdomain"];

function DomainsPage() {
  const { scanId } = Route.useParams();
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);
  // Default to in-scope only: shared-hosting reverse lookups can dump
  // hundreds of unrelated co-hosted hostnames into this list.
  const [scope, setScope] = useState<"in" | "all">("in");

  const assets = useMergedAssets(scanId, TYPES, { search, inScope: scope === "in" ? true : undefined });
  const outOfScope = useMergedAssets(scanId, TYPES, { search, inScope: false, countOnly: true });
  const page = assets.items.slice(offset, offset + LIMIT);

  const inScopeCount = scope === "in" ? assets.total : assets.total - outOfScope.total;
  const allCount = scope === "in" ? assets.total + outOfScope.total : assets.total;

  const columns: DataColumn<AssetRead>[] = [
    {
      key: "value",
      header: "Host",
      cell: (row) => (
        <div className="flex items-center gap-2">
          <span className="font-mono text-foreground">{row.value}</span>
          {row.is_target && (
            <Badge variant="outline" className="text-[10px]">
              target
            </Badge>
          )}
        </div>
      ),
    },
    { key: "type", header: "Type", cell: (row) => titleCase(row.asset_type) },
    {
      key: "scope",
      header: "Scope",
      cell: (row) => (
        <span className={cn("text-xs", row.in_scope ? "text-foreground" : "text-muted-foreground")}>
          {row.in_scope ? "In scope" : "Out of scope"}
        </span>
      ),
    },
    { key: "confidence", header: "Confidence", cell: (row) => <ConfidenceBadge value={row.confidence} /> },
    {
      key: "sources",
      header: "Sources",
      cell: (row) => <span className="text-xs text-muted-foreground">{row.sources.join(", ") || "-"}</span>,
    },
    { key: "first-seen", header: "First seen", cell: (row) => <span className="text-muted-foreground">{formatDate(row.first_seen)}</span> },
  ];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Domains & Subdomains"
        description="Hostnames discovered for this target, with source attribution and confidence."
      />

      <div className="flex flex-wrap items-center gap-3">
        <Input
          placeholder="Filter by hostname…"
          value={search}
          onChange={(e) => {
            setSearch(e.target.value);
            setOffset(0);
          }}
          className="max-w-sm font-mono"
        />
        <div className="flex items-center gap-1 rounded-lg border border-border/70 bg-card p-1 text-xs shadow-sm">
          <Button
            type="button"
            size="sm"
            variant={scope === "in" ? "default" : "ghost"}
            className="h-7"
            onClick={() => {
              setScope("in");
              setOffset(0);
            }}
          >
            In scope ({formatNumber(Math.max(0, inScopeCount))})
          </Button>
          <Button
            type="button"
            size="sm"
            variant={scope === "all" ? "default" : "ghost"}
            className="h-7"
            onClick={() => {
              setScope("all");
              setOffset(0);
            }}
          >
            All ({formatNumber(Math.max(0, allCount))})
          </Button>
        </div>
        {scope === "in" && outOfScope.total > 0 && (
          <span className="text-xs text-muted-foreground">
            {formatNumber(outOfScope.total)} out-of-scope {outOfScope.total === 1 ? "host" : "hosts"} hidden
          </span>
        )}
      </div>

      {assets.isLoading ? (
        <LoadingBlock />
      ) : assets.isError ? (
        <ErrorBlock error={assets.error} onRetry={assets.refetch} />
      ) : assets.items.length === 0 ? (
        <ScanEmptyState
          title="No domains or subdomains discovered"
          moduleIds={["domain_intelligence", "subdomain_intelligence"]}
        />
      ) : (
        <div className="flex flex-col gap-2">
          <DataTable columns={columns} rows={page} rowKey={(r) => r.id} />
          <PaginationBar offset={offset} limit={LIMIT} total={assets.items.length} onOffsetChange={setOffset} />
          {assets.truncated && (
            <p className="text-xs text-warning">
              More than {formatNumber(assets.items.length)} matching assets exist server-side; this view is capped. Refine your search to see more specific results.
            </p>
          )}
        </div>
      )}
    </div>
  );
}
