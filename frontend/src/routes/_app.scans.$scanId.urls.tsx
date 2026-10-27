import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";

import { scansApi } from "@/api/scans";
import { useScanDetail } from "@/lib/scan-context";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader } from "@/components/page-header";
import { QuerySection } from "@/components/async-state";
import { ScanEmptyState } from "@/components/scan-empty-state";
import { DataTable, PaginationBar, type DataColumn } from "@/components/data-table";
import { ConfidenceBadge, SeverityBadge } from "@/components/severity-badge";
import { SafeLink } from "@/components/safe-link";
import { truncateMiddle, formatNumber } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { FindingRead, ScanDetailRead, UrlRead } from "@/api/types";

export const Route = createFileRoute("/_app/scans/$scanId/urls")({
  component: UrlsPage,
});

const LIMIT = 25;
const BOOL_OPTIONS = [
  { value: "all", label: "Any" },
  { value: "true", label: "Yes" },
  { value: "false", label: "No" },
];

function toBool(v: string): boolean | undefined {
  return v === "all" ? undefined : v === "true";
}

function moduleData(scan: ScanDetailRead | undefined, moduleId: string): Record<string, unknown> {
  const m = scan?.modules?.find((x) => x.module_id === moduleId);
  return (m?.data ?? {}) as Record<string, unknown>;
}

function UrlsPage() {
  const { scanId } = Route.useParams();
  const scanQuery = useScanDetail();
  const scan = scanQuery.data;
  const [classification, setClassification] = useState("");
  // Default to in-scope: co-hosted and unrelated hosts are noise by default.
  const [inScope, setInScope] = useState("true");
  const [retrieved, setRetrieved] = useState("all");
  const [offset, setOffset] = useState(0);

  const urls = useQuery({
    queryKey: ["urls", scanId, classification, inScope, retrieved, offset],
    queryFn: () =>
      scansApi.urls(scanId, {
        classification: classification.trim() || undefined,
        in_scope: toBool(inScope),
        retrieved: toBool(retrieved),
        limit: LIMIT,
        offset,
      }),
  });

  // Cheap count (limit 1) of what the in-scope default hides, so the user
  // knows the filter is active and how much it removed.
  const outOfScopeCount = useQuery({
    queryKey: ["urls", scanId, classification, "out-of-scope-count"],
    queryFn: () =>
      scansApi.urls(scanId, {
        classification: classification.trim() || undefined,
        in_scope: false,
        limit: 1,
        offset: 0,
      }),
    select: (d) => d.total,
  });

  const robotsFindings = useQuery({
    queryKey: ["findings", scanId, "robots_sitemap_intelligence"],
    queryFn: () => scansApi.findings(scanId, { limit: 200 }),
  });
  const sensitivePaths = (robotsFindings.data?.items ?? []).filter((f) => f.module_id === "robots_sitemap_intelligence");

  const robotsData = moduleData(scan, "robots_sitemap_intelligence");
  const robotsTxt = (robotsData.robots_txt ?? {}) as {
    present?: boolean;
    user_agent_groups?: { user_agent: string; disallow: number; allow: number }[];
    crawl_delay?: number | null;
    sitemap_directives?: string[];
  };
  const robotsSummary = (robotsData.summary ?? {}) as {
    robots_present?: boolean;
    disallow_count?: number;
    allow_count?: number;
    sensitive_disallow_matches?: number;
    sitemap_urls_total?: number;
    sensitive_sitemap_matches?: number;
  };

  const sensitiveColumns: DataColumn<FindingRead>[] = [
    { key: "severity", header: "Severity", cell: (row) => <SeverityBadge severity={row.severity} /> },
    {
      key: "title",
      header: "Sensitive path",
      cell: (row) => (
        <div>
          <div className="font-medium text-foreground">{row.title}</div>
          {row.location && <div className="mt-0.5 truncate font-mono text-xs text-muted-foreground">{row.location}</div>}
        </div>
      ),
    },
    { key: "confidence", header: "Confidence", cell: (row) => <ConfidenceBadge value={row.confidence} /> },
  ];

  const columns: DataColumn<UrlRead>[] = [
    {
      key: "url",
      header: "URL",
      cell: (row) => (
        <SafeLink url={row.url} className="text-xs" showIcon>
          {truncateMiddle(row.url, 72)}
        </SafeLink>
      ),
    },
    { key: "host", header: "Host", cell: (row) => <span className="font-mono text-xs text-muted-foreground">{row.host}</span> },
    { key: "classification", header: "Class", cell: (row) => <Badge variant="outline">{row.classification}</Badge> },
    {
      key: "status",
      header: "Status",
      cell: (row) => (row.status_code != null ? <span className="font-mono">{row.status_code}</span> : <span className="text-muted-foreground">-</span>),
    },
    {
      key: "retrieved",
      header: "Retrieved",
      cell: (row) => (
        <span className={cn("text-xs", row.retrieved ? "text-foreground" : "text-muted-foreground")}>
          {row.retrieved ? "Yes" : "No"}
        </span>
      ),
    },
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
  ];

  return (
    <div className="flex flex-col gap-4">
      <PageHeader title="URLs" description="URLs discovered across crawling, JS analysis, and historical sources." />

      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Classification (e.g. page, api, static)…"
          value={classification}
          onChange={(e) => {
            setClassification(e.target.value);
            setOffset(0);
          }}
          className="max-w-xs"
        />
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          Scope
          <Select
            value={inScope}
            onValueChange={(v) => {
              setInScope(v);
              setOffset(0);
            }}
          >
            <SelectTrigger className="w-28">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="true">In scope</SelectItem>
              <SelectItem value="false">Out of scope</SelectItem>
              <SelectItem value="all">All</SelectItem>
            </SelectContent>
          </Select>
          {inScope === "true" && (outOfScopeCount.data ?? 0) > 0 && (
            <span>{formatNumber(outOfScopeCount.data ?? 0)} out-of-scope hidden</span>
          )}
        </div>
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          Retrieved
          <Select
            value={retrieved}
            onValueChange={(v) => {
              setRetrieved(v);
              setOffset(0);
            }}
          >
            <SelectTrigger className="w-24">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {BOOL_OPTIONS.map((o) => (
                <SelectItem key={o.value} value={o.value}>
                  {o.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </div>

      <QuerySection
        isLoading={urls.isLoading}
        isError={urls.isError}
        error={urls.error}
        onRetry={() => urls.refetch()}
        data={urls.data}
        isEmpty={(d) => d.items.length === 0}
        emptyTitle="No URLs discovered"
        emptyState={
          <ScanEmptyState
            title="No URLs discovered"
            moduleIds={["url_collection"]}
            modeNote="URL collection crawls linked pages, which only happens in Web Surface Collection mode. This scan ran in Passive mode, so no crawl was performed."
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
        <h2 className="text-sm font-semibold text-foreground">Robots.txt and sitemap</h2>
        {robotsTxt.present ? (
          <div className="flex flex-col gap-3">
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-4">
              <Card>
                <CardContent className="p-4">
                  <p className="text-2xl font-bold text-foreground">{formatNumber(robotsSummary.disallow_count ?? 0)}</p>
                  <p className="text-xs text-muted-foreground">Disallow rules</p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4">
                  <p className="text-2xl font-bold text-foreground">{formatNumber(robotsSummary.sensitive_disallow_matches ?? 0)}</p>
                  <p className="text-xs text-muted-foreground">Sensitive disallow matches</p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4">
                  <p className="text-2xl font-bold text-foreground">{formatNumber(robotsSummary.sitemap_urls_total ?? 0)}</p>
                  <p className="text-xs text-muted-foreground">Sitemap URLs</p>
                </CardContent>
              </Card>
              <Card>
                <CardContent className="p-4">
                  <p className="text-2xl font-bold text-foreground">{formatNumber(robotsSummary.sensitive_sitemap_matches ?? 0)}</p>
                  <p className="text-xs text-muted-foreground">Sensitive sitemap matches</p>
                </CardContent>
              </Card>
            </div>
            {(robotsTxt.user_agent_groups ?? []).length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Crawler directives</CardTitle>
                </CardHeader>
                <CardContent className="flex flex-col gap-1.5">
                  {(robotsTxt.user_agent_groups ?? []).slice(0, 12).map((g, i) => (
                    <div key={i} className="flex items-center justify-between gap-2 rounded-lg border border-border/60 px-3 py-2 text-xs">
                      <span className="font-mono text-foreground">{g.user_agent}</span>
                      <span className="text-muted-foreground">
                        {g.disallow} disallow · {g.allow} allow
                        {robotsTxt.crawl_delay != null && ` · crawl delay ${robotsTxt.crawl_delay}s`}
                      </span>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}
            {sensitivePaths.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Sensitive paths flagged</CardTitle>
                </CardHeader>
                <CardContent>
                  <DataTable columns={sensitiveColumns} rows={sensitivePaths} rowKey={(r) => r.id} />
                </CardContent>
              </Card>
            )}
          </div>
        ) : (
          <ScanEmptyState
            title="No robots.txt data"
            description="No robots.txt was found for this target, or the module did not run."
            moduleIds={["robots_sitemap_intelligence"]}
          />
        )}
      </section>
    </div>
  );
}
