import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { FileText } from "lucide-react";

import { scansApi } from "@/api/scans";
import { useScanDetail } from "@/lib/scan-context";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/page-header";
import { QuerySection } from "@/components/async-state";
import { ScanEmptyState } from "@/components/scan-empty-state";
import { DataTable, type DataColumn } from "@/components/data-table";
import { ConfidenceBadge, SeverityBadge } from "@/components/severity-badge";
import { SafeLink } from "@/components/safe-link";
import { truncateMiddle, titleCase } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { FindingRead, IndexedExposureRead, ScanDetailRead } from "@/api/types";

export const Route = createFileRoute("/_app/scans/$scanId/documents")({
  component: DocumentsPage,
});

function moduleData(scan: ScanDetailRead | undefined, moduleId: string): Record<string, unknown> {
  const m = scan?.modules?.find((x) => x.module_id === moduleId);
  return (m?.data ?? {}) as Record<string, unknown>;
}

function DocumentsPage() {
  const { scanId } = Route.useParams();
  const scanQuery = useScanDetail();
  const scan = scanQuery.data;

  const exposures = useQuery({
    queryKey: ["indexed-exposures", scanId, "documents"],
    queryFn: () => scansApi.indexedExposures(scanId, { limit: 200 }),
  });

  const findings = useQuery({
    queryKey: ["findings", scanId, "document_intelligence"],
    queryFn: () => scansApi.findings(scanId, { limit: 200 }),
  });

  const summary = (moduleData(scan, "document_intelligence").summary ?? {}) as {
    by_type?: Record<string, number>;
    total_documents?: number;
    archive_count?: number;
  };
  const byType = summary.by_type ?? {};
  const typeEntries = Object.entries(byType).sort((a, b) => b[1] - a[1]);

  const docExposures = (exposures.data?.items ?? []).filter((e) => e.exposure_type === "document");
  const docFindings = (findings.data?.items ?? []).filter((f) => f.module_id === "document_intelligence");

  const exposureColumns: DataColumn<IndexedExposureRead>[] = [
    {
      key: "url",
      header: "Artifact",
      cell: (row) => (
        <SafeLink url={row.url} className="text-xs">
          {truncateMiddle(row.url, 68)}
        </SafeLink>
      ),
    },
    { key: "host", header: "Host", cell: (row) => <span className="font-mono text-xs text-muted-foreground">{row.host ?? "-"}</span> },
    {
      key: "retrievable",
      header: "Retrievable",
      cell: (row) => (
        <span className={cn("text-xs", row.retrievable ? "text-foreground" : "text-muted-foreground")}>
          {row.retrievable ? "Yes" : "No"}
        </span>
      ),
    },
    { key: "severity", header: "Severity", cell: (row) => <SeverityBadge severity={row.severity} /> },
    { key: "confidence", header: "Confidence", cell: (row) => <ConfidenceBadge value={row.confidence} /> },
  ];

  const findingColumns: DataColumn<FindingRead>[] = [
    { key: "severity", header: "Severity", cell: (row) => <SeverityBadge severity={row.severity} /> },
    {
      key: "title",
      header: "Finding",
      cell: (row) => (
        <div>
          <div className="font-medium text-foreground">{row.title}</div>
          {row.description && <div className="mt-0.5 line-clamp-2 text-xs text-muted-foreground">{row.description}</div>}
        </div>
      ),
    },
    { key: "confidence", header: "Confidence", cell: (row) => <ConfidenceBadge value={row.confidence} /> },
  ];

  const hasInventory = typeEntries.length > 0 || (summary.total_documents ?? 0) > 0;

  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        title="Documents"
        description="Document and archive files catalogued by extension from known URLs, plus exposure findings for retrievable archives."
      />

      <section className="flex flex-col gap-3">
        <div className="flex items-center gap-2">
          <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <FileText className="h-4 w-4" />
          </span>
          <h2 className="text-sm font-semibold text-foreground">Inventory by file type</h2>
        </div>
        {!hasInventory ? (
          <ScanEmptyState
            title="No documents catalogued"
            description="Document cataloguing reads the scan's known URL set and groups files by extension. In Passive mode that set is small, so coverage is narrow by design."
            moduleIds={["document_intelligence"]}
          />
        ) : (
          <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
            <Card>
              <CardContent className="p-4">
                <p className="text-2xl font-bold text-foreground">{summary.total_documents ?? 0}</p>
                <p className="text-xs text-muted-foreground">Documents found</p>
              </CardContent>
            </Card>
            {typeEntries.map(([type, count]) => (
              <Card key={type}>
                <CardContent className="flex items-center justify-between p-4">
                  <div>
                    <p className="text-2xl font-bold text-foreground">{count}</p>
                    <p className="text-xs capitalize text-muted-foreground">{titleCase(type)}</p>
                  </div>
                  <Badge variant="secondary">{type}</Badge>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </section>

      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold text-foreground">Archive exposures</h2>
        <QuerySection
          isLoading={exposures.isLoading}
          isError={exposures.isError}
          error={exposures.error}
          onRetry={() => exposures.refetch()}
          data={docExposures}
          isEmpty={(d) => d.length === 0}
          emptyTitle="No archive exposures"
          emptyState={
            <ScanEmptyState
              title="No archive exposures"
              description="Retrievable archives (.zip, .tar, backups) would appear here. None were confirmed for this target."
              moduleIds={["document_intelligence"]}
            />
          }
        >
          {(rows) => <DataTable columns={exposureColumns} rows={rows} rowKey={(r) => r.id} />}
        </QuerySection>
      </section>

      {docFindings.length > 0 && (
        <section className="flex flex-col gap-3">
          <h2 className="text-sm font-semibold text-foreground">Related findings</h2>
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Document findings</CardTitle>
            </CardHeader>
            <CardContent>
              <DataTable columns={findingColumns} rows={docFindings} rowKey={(r) => r.id} />
            </CardContent>
          </Card>
        </section>
      )}
    </div>
  );
}
