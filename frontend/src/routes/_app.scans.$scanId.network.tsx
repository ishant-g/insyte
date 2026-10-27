import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";

import { scansApi } from "@/api/scans";
import { useMergedAssets } from "@/hooks/use-merged-assets";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/page-header";
import { LoadingBlock, ErrorBlock, QuerySection } from "@/components/async-state";
import { ScanEmptyState } from "@/components/scan-empty-state";
import { DataTable, PaginationBar, type DataColumn } from "@/components/data-table";
import { ConfidenceBadge } from "@/components/severity-badge";
import { formatDate, formatNumber, titleCase } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { AssetRead, DnsRecordRead } from "@/api/types";

export const Route = createFileRoute("/_app/scans/$scanId/network")({
  component: NetworkPage,
});

const LIMIT = 25;

function NetworkPage() {
  const { scanId } = Route.useParams();
  const [search, setSearch] = useState("");
  const [offset, setOffset] = useState(0);

  const assets = useMergedAssets(scanId, ["ipv4", "ipv6", "asn"], { search });
  const page = assets.items.slice(offset, offset + LIMIT);

  const dnsRecords = useQuery({
    queryKey: ["dns-records", scanId],
    queryFn: () => scansApi.dnsRecords(scanId),
  });

  const cloudAssets = useQuery({
    queryKey: ["assets", scanId, "cloud_resource"],
    queryFn: () => scansApi.assets(scanId, { asset_type: "cloud_resource", limit: 200 }),
  });

  const cloudColumns: DataColumn<AssetRead>[] = [
    {
      key: "value",
      header: "Resource",
      cell: (row) => <span className="font-mono text-xs text-foreground">{row.value}</span>,
    },
    {
      key: "provider",
      header: "Provider",
      cell: (row) => {
        const signal = row.attributes?.signal;
        return <span className="text-xs text-foreground">{typeof signal === "string" ? signal : titleCase(row.label ?? "cloud")}</span>;
      },
    },
    { key: "confidence", header: "Confidence", cell: (row) => <ConfidenceBadge value={row.confidence} /> },
    { key: "sources", header: "Sources", cell: (row) => <span className="text-xs text-muted-foreground">{row.sources.join(", ") || "-"}</span> },
  ];

  const columns: DataColumn<AssetRead>[] = [
    {
      key: "value",
      header: "Value",
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
    { key: "sources", header: "Sources", cell: (row) => <span className="text-xs text-muted-foreground">{row.sources.join(", ") || "-"}</span> },
    { key: "first-seen", header: "First seen", cell: (row) => <span className="text-muted-foreground">{formatDate(row.first_seen)}</span> },
  ];

  const dnsColumns: DataColumn<DnsRecordRead>[] = [
    { key: "name", header: "Name", cell: (row) => <span className="font-mono text-foreground">{row.name}</span> },
    { key: "type", header: "Type", cell: (row) => <Badge variant="outline">{row.record_type}</Badge> },
    { key: "value", header: "Value", cell: (row) => <span className="font-mono text-xs text-muted-foreground break-all">{row.value}</span> },
    { key: "ttl", header: "TTL", cell: (row) => (row.ttl != null ? `${formatNumber(row.ttl)}s` : "-") },
  ];

  return (
    <div className="flex flex-col gap-6">
      <PageHeader title="IPs / ASN" description="IP addresses and autonomous system numbers associated with this target." />

      <Input
        placeholder="Filter by IP or ASN…"
        value={search}
        onChange={(e) => {
          setSearch(e.target.value);
          setOffset(0);
        }}
        className="max-w-sm font-mono"
      />

      {assets.isLoading ? (
        <LoadingBlock />
      ) : assets.isError ? (
        <ErrorBlock error={assets.error} onRetry={assets.refetch} />
      ) : assets.items.length === 0 ? (
        <ScanEmptyState
          title="No IPs or ASNs discovered"
          moduleIds={["dns_intelligence", "ip_asn_intelligence"]}
        />
      ) : (
        <div className="flex flex-col gap-2">
          <DataTable columns={columns} rows={page} rowKey={(r) => r.id} />
          <PaginationBar offset={offset} limit={LIMIT} total={assets.items.length} onOffsetChange={setOffset} />
          {assets.truncated && (
            <p className="text-xs text-warning">
              More matching assets exist server-side than shown here. Refine your search for a complete view.
            </p>
          )}
        </div>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Cloud attribution</CardTitle>
        </CardHeader>
        <CardContent>
          <QuerySection
            isLoading={cloudAssets.isLoading}
            isError={cloudAssets.isError}
            error={cloudAssets.error}
            onRetry={() => cloudAssets.refetch()}
            data={cloudAssets.data}
            isEmpty={(d) => d.items.length === 0}
            emptyTitle="No cloud attribution"
            emptyState={
              <ScanEmptyState
                title="No cloud attribution"
                description="IP-range matching against published cloud provider ranges found no cloud tenancy for this target's IPs."
                moduleIds={["cloud_detection"]}
              />
            }
          >
            {(data) => <DataTable columns={cloudColumns} rows={data.items} rowKey={(r) => r.id} />}
          </QuerySection>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">DNS records</CardTitle>
        </CardHeader>
        <CardContent>
          <QuerySection
            isLoading={dnsRecords.isLoading}
            isError={dnsRecords.isError}
            error={dnsRecords.error}
            onRetry={() => dnsRecords.refetch()}
            data={dnsRecords.data}
            isEmpty={(d) => d.length === 0}
            emptyTitle="No DNS records collected"
            emptyState={
              <ScanEmptyState
                title="No DNS records collected"
                moduleIds={["dns_intelligence"]}
              />
            }
          >
            {(records) => <DataTable columns={dnsColumns} rows={records} rowKey={(r) => r.id} />}
          </QuerySection>
        </CardContent>
      </Card>
    </div>
  );
}
