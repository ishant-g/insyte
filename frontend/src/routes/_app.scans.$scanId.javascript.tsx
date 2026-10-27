import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { KeyRound } from "lucide-react";

import { scansApi } from "@/api/scans";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "@/components/ui/sheet";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/page-header";
import { QuerySection } from "@/components/async-state";
import { ScanEmptyState } from "@/components/scan-empty-state";
import { DataTable, PaginationBar, type DataColumn } from "@/components/data-table";
import { SeverityBadge } from "@/components/severity-badge";
import { SafeLink } from "@/components/safe-link";
import { formatBytes, truncateMiddle } from "@/lib/format";
import type { FindingRead, JavaScriptRead } from "@/api/types";

export const Route = createFileRoute("/_app/scans/$scanId/javascript")({
  component: JavaScriptPage,
});

const LIMIT = 25;
const SECRET_OPTIONS = [
  { value: "all", label: "All files" },
  { value: "true", label: "With secret indicators" },
  { value: "false", label: "Without secret indicators" },
];

function JavaScriptPage() {
  const { scanId } = Route.useParams();
  const [hasSecrets, setHasSecrets] = useState("all");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<JavaScriptRead | null>(null);

  const files = useQuery({
    queryKey: ["javascript", scanId, hasSecrets, offset],
    queryFn: () =>
      scansApi.javascript(scanId, {
        has_secrets: hasSecrets === "all" ? undefined : hasSecrets === "true",
        limit: LIMIT,
        offset,
      }),
  });

  const sourceMapFindings = useQuery({
    queryKey: ["findings", scanId, "source_map_intelligence"],
    queryFn: () => scansApi.findings(scanId, { limit: 200 }),
  });
  const sourceMaps = (sourceMapFindings.data?.items ?? []).filter((f) => f.module_id === "source_map_intelligence");

  const sourceMapColumns: DataColumn<FindingRead>[] = [
    { key: "severity", header: "Severity", cell: (row) => <SeverityBadge severity={row.severity} /> },
    {
      key: "title",
      header: "Source map finding",
      cell: (row) => (
        <div>
          <div className="font-medium text-foreground">{row.title}</div>
          {row.location && <div className="mt-0.5 truncate font-mono text-xs text-muted-foreground">{row.location}</div>}
          {row.description && <div className="mt-0.5 line-clamp-2 text-xs text-muted-foreground">{row.description}</div>}
        </div>
      ),
    },
  ];

  const columns: DataColumn<JavaScriptRead>[] = [
    {
      key: "url",
      header: "File",
      cell: (row) => (
        <SafeLink url={row.url} className="text-xs">
          {truncateMiddle(row.url, 70)}
        </SafeLink>
      ),
    },
    { key: "party", header: "Origin", cell: (row) => (row.is_third_party ? <Badge variant="outline">Third-party</Badge> : <Badge variant="outline">First-party</Badge>) },
    { key: "size", header: "Size", cell: (row) => formatBytes(row.size) },
    { key: "libs", header: "Libraries", cell: (row) => <span className="text-xs text-muted-foreground">{row.libraries.length}</span> },
    { key: "endpoints", header: "Endpoints", cell: (row) => <span className="text-xs text-muted-foreground">{row.endpoints.length}</span> },
    {
      key: "secrets",
      header: "Secret indicators",
      cell: (row) =>
        row.secret_indicators.length > 0 ? (
          <span className="inline-flex items-center gap-1 text-xs font-medium text-severity-high">
            <KeyRound className="h-3.5 w-3.5" />
            {row.secret_indicators.length}
          </span>
        ) : (
          <span className="text-xs text-muted-foreground">None</span>
        ),
    },
    {
      key: "sourcemap",
      header: "Source map",
      cell: (row) => (row.has_source_map ? <span className="text-xs text-foreground">Yes</span> : <span className="text-xs text-muted-foreground">No</span>),
    },
  ];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader
        title="JavaScript"
        description="First- and third-party scripts, with libraries, discovered endpoints, and masked secret indicators. Click a row for detail."
      />

      <Select value={hasSecrets} onValueChange={(v) => { setHasSecrets(v); setOffset(0); }}>
        <SelectTrigger className="w-64">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {SECRET_OPTIONS.map((o) => (
            <SelectItem key={o.value} value={o.value}>
              {o.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <QuerySection
        isLoading={files.isLoading}
        isError={files.isError}
        error={files.error}
        onRetry={() => files.refetch()}
        data={files.data}
        isEmpty={(d) => d.items.length === 0}
        emptyTitle="No JavaScript files discovered"
        emptyState={
          <ScanEmptyState
            title="No JavaScript files discovered"
            moduleIds={["javascript_intelligence"]}
            modeNote="JavaScript analysis downloads and inspects scripts from crawled pages, which only happens in Web Surface Collection mode. This scan ran in Passive mode."
          />
        }
      >
        {(data) => (
          <div className="flex flex-col gap-2">
            <DataTable columns={columns} rows={data.items} rowKey={(r) => r.id} onRowClick={setSelected} />
            <PaginationBar offset={offset} limit={LIMIT} total={data.total} onOffsetChange={setOffset} />
          </div>
        )}
      </QuerySection>

      <section className="flex flex-col gap-3">
        <h2 className="text-sm font-semibold text-foreground">Source maps</h2>
        <QuerySection
          isLoading={sourceMapFindings.isLoading}
          isError={sourceMapFindings.isError}
          error={sourceMapFindings.error}
          onRetry={() => sourceMapFindings.refetch()}
          data={sourceMaps}
          isEmpty={(d) => d.length === 0}
          emptyTitle="No source map findings"
          emptyState={
            <ScanEmptyState
              title="No source map findings"
              description="Publicly retrievable source maps and the internal paths they reveal would appear here."
              moduleIds={["source_map_intelligence"]}
            />
          }
        >
          {(rows) => <DataTable columns={sourceMapColumns} rows={rows} rowKey={(r) => r.id} />}
        </QuerySection>
      </section>

      <Sheet open={!!selected} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
          {selected && (
            <>
              <SheetHeader>
                <SheetTitle className="break-all font-mono text-sm">{selected.url}</SheetTitle>
                <SheetDescription>
                  {selected.is_third_party ? "Third-party" : "First-party"} · {formatBytes(selected.size)}
                </SheetDescription>
              </SheetHeader>

              <div className="mt-4 flex flex-col gap-4 text-sm">
                {selected.secret_indicators.length > 0 && (
                  <div>
                    <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                      Secret indicators
                    </h3>
                    <p className="mb-2 text-xs text-muted-foreground">
                      Values are pre-masked by the backend. Insyte never attempts to decode or reveal them.
                    </p>
                    <ul className="flex flex-col gap-1.5">
                      {selected.secret_indicators.map((s, i) => (
                        <li key={i} className="flex items-center justify-between gap-2 rounded-md border border-border px-2.5 py-1.5">
                          <span className="font-mono text-xs text-foreground">{s.masked}</span>
                          <div className="flex items-center gap-1.5">
                            <span className="text-xs text-muted-foreground">{s.type}</span>
                            <SeverityBadge severity={s.severity} />
                          </div>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {selected.libraries.length > 0 && (
                  <div>
                    <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Libraries</h3>
                    <div className="flex flex-wrap gap-1.5">
                      {selected.libraries.map((l, i) => (
                        <Badge key={i} variant="secondary">
                          {l.name}
                          {l.version && <span className="ml-1 opacity-70">{l.version}</span>}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {selected.integrations.length > 0 && (
                  <div>
                    <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Integrations</h3>
                    <div className="flex flex-wrap gap-1.5">
                      {selected.integrations.map((integ, i) => (
                        <Badge key={i} variant="outline">
                          {integ.name} · {integ.category}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                {selected.endpoints.length > 0 && (
                  <div>
                    <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                      Endpoints referenced
                    </h3>
                    <ul className="flex flex-col gap-1">
                      {selected.endpoints.map((e, i) => (
                        <li key={i} className="font-mono text-xs text-muted-foreground break-all">
                          {e}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {selected.domains.length > 0 && (
                  <div>
                    <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Domains referenced</h3>
                    <div className="flex flex-wrap gap-1.5">
                      {selected.domains.map((d, i) => (
                        <Badge key={i} variant="outline" className="font-mono">
                          {d}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}

                <Separator />
                <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                  <span>Source map</span>
                  <span className="text-foreground">
                    {selected.has_source_map ? (
                      selected.source_map_url ? (
                        <SafeLink url={selected.source_map_url}>{truncateMiddle(selected.source_map_url, 30)}</SafeLink>
                      ) : (
                        "Present"
                      )
                    ) : (
                      "Not found"
                    )}
                  </span>
                  <span>SHA-256</span>
                  <span className="break-all font-mono text-foreground">{selected.content_sha256 ?? "-"}</span>
                </div>
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}
