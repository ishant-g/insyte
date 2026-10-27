import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";

import { scansApi } from "@/api/scans";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/page-header";
import { QuerySection } from "@/components/async-state";
import { ScanEmptyState } from "@/components/scan-empty-state";
import { DataTable, PaginationBar, type DataColumn } from "@/components/data-table";
import { SeverityBadge, ConfidenceBadge } from "@/components/severity-badge";
import { SafeLink } from "@/components/safe-link";
import { truncateMiddle, titleCase } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { FindingRead, IndexedExposureRead } from "@/api/types";

export const Route = createFileRoute("/_app/scans/$scanId/exposure")({
  component: ExposurePage,
});

const LIMIT = 25;

function ExposurePage() {
  const { scanId } = Route.useParams();
  const [offset, setOffset] = useState(0);

  const exposures = useQuery({
    queryKey: ["indexed-exposures", scanId, offset],
    queryFn: () => scansApi.indexedExposures(scanId, { limit: LIMIT, offset }),
  });

  const dorkFindings = useQuery({
    queryKey: ["findings", scanId, "google_dorking"],
    queryFn: () => scansApi.findings(scanId, { limit: 200 }),
  });
  const dorks = (dorkFindings.data?.items ?? []).filter((f) => f.module_id === "google_dorking");

  const dorkColumns: DataColumn<FindingRead>[] = [
    { key: "severity", header: "Severity", cell: (row) => <SeverityBadge severity={row.severity} /> },
    {
      key: "title",
      header: "Indexed result",
      cell: (row) => (
        <div>
          <div className="font-medium text-foreground">{row.title}</div>
          {row.location && (
            <SafeLink url={row.location} className="mt-0.5 block truncate text-xs">
              {truncateMiddle(row.location, 72)}
            </SafeLink>
          )}
          {row.description && <div className="mt-0.5 line-clamp-2 text-xs text-muted-foreground">{row.description}</div>}
        </div>
      ),
    },
    { key: "confidence", header: "Confidence", cell: (row) => <ConfidenceBadge value={row.confidence} /> },
  ];

  const columns: DataColumn<IndexedExposureRead>[] = [
    {
      key: "url",
      header: "Artifact",
      cell: (row) => (
        <SafeLink url={row.url} className="text-xs">
          {truncateMiddle(row.url, 68)}
        </SafeLink>
      ),
    },
    { key: "type", header: "Type", cell: (row) => <Badge variant="outline">{titleCase(row.exposure_type)}</Badge> },
    { key: "host", header: "Host", cell: (row) => <span className="font-mono text-xs text-muted-foreground">{row.host ?? "-"}</span> },
    { key: "class", header: "Observation class", cell: (row) => <span className="text-xs text-muted-foreground">{titleCase(row.observation_class)}</span> },
    {
      key: "retrievable",
      header: "Retrievable",
      cell: (row) => <span className={cn("text-xs", row.retrievable ? "text-foreground" : "text-muted-foreground")}>{row.retrievable ? "Yes" : "No"}</span>,
    },
    { key: "severity", header: "Severity", cell: (row) => <SeverityBadge severity={row.severity} /> },
    { key: "confidence", header: "Confidence", cell: (row) => <ConfidenceBadge value={row.confidence} /> },
  ];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="Indexed exposure"
        description="Potentially-exposed artifacts (e.g. .env, .git, backups) found via search-index discovery: never brute-forced against the target."
      />

      <QuerySection
        isLoading={exposures.isLoading}
        isError={exposures.isError}
        error={exposures.error}
        onRetry={() => exposures.refetch()}
        data={exposures.data}
        isEmpty={(d) => d.items.length === 0}
        emptyTitle="No indexed exposures found"
        emptyDescription="No potentially-exposed artifacts were discovered via passive search-index sources."
        emptyState={
          <ScanEmptyState
            title="No indexed exposures found"
            description="In Passive mode this check only pattern-matches a small set of known URLs. It does not crawl the site, so coverage is intentionally narrow."
            moduleIds={["indexed_exposure"]}
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
      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold text-foreground">Search-engine dorking</h2>
        <QuerySection
          isLoading={dorkFindings.isLoading}
          isError={dorkFindings.isError}
          error={dorkFindings.error}
          onRetry={() => dorkFindings.refetch()}
          data={dorks}
          isEmpty={(d) => d.length === 0}
          emptyTitle="No dork hits"
          emptyState={
            <ScanEmptyState
              title="No dork hits"
              description="Google dorking needs a Google Programmable Search API key and search engine ID. Without them this module skips."
              moduleIds={["google_dorking"]}
            />
          }
        >
          {(rows) => (
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Google-indexed exposures</CardTitle>
              </CardHeader>
              <CardContent>
                <DataTable columns={dorkColumns} rows={rows} rowKey={(r) => r.id} />
              </CardContent>
            </Card>
          )}
        </QuerySection>
      </section>
    </div>
  );
}
