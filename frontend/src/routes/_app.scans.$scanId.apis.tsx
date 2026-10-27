import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ShieldQuestion } from "lucide-react";

import { scansApi } from "@/api/scans";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { PageHeader } from "@/components/page-header";
import { QuerySection } from "@/components/async-state";
import { ScanEmptyState } from "@/components/scan-empty-state";
import { DataTable, PaginationBar, type DataColumn } from "@/components/data-table";
import { ConfidenceBadge } from "@/components/severity-badge";
import { SafeLink } from "@/components/safe-link";
import { truncateMiddle } from "@/lib/format";
import type { ApiEndpointRead } from "@/api/types";

export const Route = createFileRoute("/_app/scans/$scanId/apis")({
  component: ApisPage,
});

const LIMIT = 25;

function ApisPage() {
  const { scanId } = Route.useParams();
  const [apiType, setApiType] = useState("");
  const [offset, setOffset] = useState(0);

  const apis = useQuery({
    queryKey: ["apis", scanId, apiType, offset],
    queryFn: () => scansApi.apis(scanId, { api_type: apiType.trim() || undefined, limit: LIMIT, offset }),
  });

  const columns: DataColumn<ApiEndpointRead>[] = [
    {
      key: "path",
      header: "Endpoint",
      cell: (row) => (
        <div className="flex flex-col">
          <SafeLink url={row.url} className="text-xs">
            {row.method ? `${row.method} ` : ""}
            {truncateMiddle(row.path || row.url, 60)}
          </SafeLink>
          <span className="font-mono text-[11px] text-muted-foreground">{row.host}</span>
        </div>
      ),
    },
    { key: "type", header: "Type", cell: (row) => <Badge variant="outline">{row.api_type}</Badge> },
    { key: "version", header: "Version", cell: (row) => row.api_version ?? "-" },
    { key: "auth", header: "Auth hint", cell: (row) => <span className="text-xs text-muted-foreground">{row.auth_hint ?? "-"}</span> },
    {
      key: "validated",
      header: "Status",
      cell: () => (
        <Tooltip>
          <TooltipTrigger asChild>
            <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
              <ShieldQuestion className="h-3.5 w-3.5" />
              Not validated
            </span>
          </TooltipTrigger>
          <TooltipContent>Discovered endpoint. Never confirmed reachable by Insyte.</TooltipContent>
        </Tooltip>
      ),
    },
    { key: "confidence", header: "Confidence", cell: (row) => <ConfidenceBadge value={row.confidence} /> },
    { key: "source", header: "Source", cell: (row) => <span className="text-xs text-muted-foreground">{row.source_artifact ? truncateMiddle(row.source_artifact, 30) : "-"}</span> },
  ];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="APIs"
        description="API endpoints discovered from JavaScript, robots/OpenAPI specs, and crawled paths. None of these are validated as reachable."
      />

      <Input
        placeholder="API type (e.g. rest, graphql, openapi)…"
        value={apiType}
        onChange={(e) => {
          setApiType(e.target.value);
          setOffset(0);
        }}
        className="max-w-xs"
      />

      <QuerySection
        isLoading={apis.isLoading}
        isError={apis.isError}
        error={apis.error}
        onRetry={() => apis.refetch()}
        data={apis.data}
        isEmpty={(d) => d.items.length === 0}
        emptyTitle="No API endpoints discovered"
        emptyState={
          <ScanEmptyState
            title="No API endpoints discovered"
            moduleIds={["api_discovery"]}
            modeNote="API discovery analyzes crawled JavaScript and pages, which only happens in Web Surface Collection mode. This scan ran in Passive mode."
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
