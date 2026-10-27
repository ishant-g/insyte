import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { ShieldCheck, ShieldQuestion, Skull } from "lucide-react";

import { scansApi } from "@/api/scans";
import type { FindingRead, Severity } from "@/api/types";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Badge } from "@/components/ui/badge";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetDescription,
} from "@/components/ui/sheet";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/page-header";
import { QuerySection } from "@/components/async-state";
import { ScanEmptyState } from "@/components/scan-empty-state";
import { DataTable, PaginationBar, type DataColumn } from "@/components/data-table";
import { SeverityBadge, ConfidenceBadge } from "@/components/severity-badge";
import { SafeLink } from "@/components/safe-link";
import { formatDate, isSafeUrl, titleCase } from "@/lib/format";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_app/scans/$scanId/findings")({
  component: FindingsPage,
});

const LIMIT = 25;
const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "informational"];

function FindingsPage() {
  return (
    <div className="flex flex-col gap-4">
      <PageHeader title="Findings" description="Security findings and CVE correlations for this scan's assets." />
      <Tabs defaultValue="findings">
        <TabsList>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="cves">CVE intelligence</TabsTrigger>
        </TabsList>
        <TabsContent value="findings">
          <FindingsTab />
        </TabsContent>
        <TabsContent value="cves">
          <CvesTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function FindingsTab() {
  const { scanId } = Route.useParams();
  const [severity, setSeverity] = useState("all");
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<FindingRead | null>(null);

  const findings = useQuery({
    queryKey: ["findings", scanId, severity, offset],
    queryFn: () => scansApi.findings(scanId, { severity: severity === "all" ? undefined : severity, limit: LIMIT, offset }),
  });

  const detail = useQuery({
    queryKey: ["finding", scanId, selected?.id],
    queryFn: () => scansApi.finding(scanId, selected!.id),
    enabled: !!selected,
  });

  const columns: DataColumn<FindingRead>[] = [
    { key: "severity", header: "Severity", cell: (row) => <SeverityBadge severity={row.severity} /> },
    {
      key: "title",
      header: "Finding",
      cell: (row) => (
        <div>
          <div className="font-medium text-foreground">{row.title}</div>
          <div className="text-xs text-muted-foreground">{row.category}</div>
        </div>
      ),
    },
    { key: "location", header: "Location", cell: (row) => <span className="font-mono text-xs text-muted-foreground break-all">{row.location ?? "-"}</span> },
    { key: "exposure", header: "Exposure", cell: (row) => <Badge variant="outline">{titleCase(row.exposure)}</Badge> },
    { key: "confidence", header: "Confidence", cell: (row) => <ConfidenceBadge band={row.confidence_band} value={row.confidence} /> },
    { key: "cve", header: "CVEs", cell: (row) => (row.cve_ids.length > 0 ? <span className="font-mono text-xs">{row.cve_ids.length}</span> : <span className="text-muted-foreground">-</span>) },
  ];

  return (
    <div className="mt-3 flex flex-col gap-3">
      <Select value={severity} onValueChange={(v) => { setSeverity(v); setOffset(0); }}>
        <SelectTrigger className="w-44">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All severities</SelectItem>
          {SEVERITIES.map((s) => (
            <SelectItem key={s} value={s}>
              {titleCase(s)}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <QuerySection
        isLoading={findings.isLoading}
        isError={findings.isError}
        error={findings.error}
        onRetry={() => findings.refetch()}
        data={findings.data}
        isEmpty={(d) => d.items.length === 0}
        emptyTitle="No findings recorded"
        emptyDescription="No security findings matched this filter."
        emptyState={
          <ScanEmptyState
            title="No findings recorded"
            description="No security findings matched this filter. Findings are produced by the email-security, exposure, and web-surface modules."
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

      <Sheet open={!!selected} onOpenChange={(open) => !open && setSelected(null)}>
        <SheetContent className="w-full overflow-y-auto sm:max-w-lg">
          {selected && (
            <>
              <SheetHeader>
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={selected.severity} />
                  <ConfidenceBadge band={selected.confidence_band} value={selected.confidence} />
                </div>
                <SheetTitle>{selected.title}</SheetTitle>
                <SheetDescription>{selected.category}</SheetDescription>
              </SheetHeader>
              <div className="mt-4 flex flex-col gap-4 text-sm">
                {selected.description && <p className="text-foreground">{selected.description}</p>}
                {selected.recommendation && (
                  <div className="rounded-md border border-border bg-muted/30 p-3">
                    <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Recommendation</p>
                    <p className="text-foreground">{selected.recommendation}</p>
                  </div>
                )}
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <span className="text-muted-foreground">Location</span>
                  <span className="break-all font-mono text-foreground">{selected.location ?? "-"}</span>
                  <span className="text-muted-foreground">Exposure</span>
                  <span className="text-foreground">{titleCase(selected.exposure)}</span>
                  <span className="text-muted-foreground">Risk score</span>
                  <span className="font-mono text-foreground">{selected.risk_score}</span>
                  <span className="text-muted-foreground">Sources</span>
                  <span className="text-foreground">{selected.sources.join(", ") || "-"}</span>
                  <span className="text-muted-foreground">Found</span>
                  <span className="text-foreground">{formatDate(selected.created_at)}</span>
                </div>
                {selected.reference_links.length > 0 && (
                  <div>
                    <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">References</p>
                    <ul className="flex flex-col gap-1">
                      {selected.reference_links.map((link, i) => (
                        <li key={i}>
                          <SafeLink url={link} className="text-xs" showIcon>
                            {link}
                          </SafeLink>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {detail.data?.evidence && Object.keys(detail.data.evidence).length > 0 && (
                  <div>
                    <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Evidence</p>
                    <pre className="max-h-64 overflow-auto rounded-md border border-border bg-muted/30 p-2.5 text-[11px] text-muted-foreground">
                      {JSON.stringify(detail.data.evidence, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </>
          )}
        </SheetContent>
      </Sheet>
    </div>
  );
}

function CvesTab() {
  const { scanId } = Route.useParams();
  const [definitiveOnly, setDefinitiveOnly] = useState(false);
  const [offset, setOffset] = useState(0);

  const cves = useQuery({
    queryKey: ["cves", scanId, definitiveOnly, offset],
    queryFn: () => scansApi.cves(scanId, { definitive_only: definitiveOnly || undefined, limit: LIMIT, offset }),
  });

  return (
    <div className="mt-3 flex flex-col gap-3">
      <label className="flex w-fit items-center gap-2 text-sm text-foreground">
        <Checkbox checked={definitiveOnly} onCheckedChange={(v) => { setDefinitiveOnly(!!v); setOffset(0); }} />
        Definitive matches only
      </label>

      <QuerySection
        isLoading={cves.isLoading}
        isError={cves.isError}
        error={cves.error}
        onRetry={() => cves.refetch()}
        data={cves.data}
        isEmpty={(d) => d.items.length === 0}
        emptyTitle="No CVEs correlated"
        emptyDescription="No known CVEs were matched against fingerprinted technology versions for this scan."
        emptyState={
          <ScanEmptyState
            title="No CVEs correlated"
            description="CVE matching needs fingerprinted technology versions. Technologies without a detected version, or without a vendor mapping, are skipped by the correlator."
            moduleIds={["technology_intelligence"]}
          />
        }
      >
        {(data) => (
          <div className="flex flex-col gap-3">
            {data.items.map((cve) => (
              <div key={cve.id} className="rounded-lg border border-border bg-card p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <SafeLink
                      url={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve.cve_id)}`}
                      className="font-mono text-sm font-semibold"
                    >
                      {cve.cve_id}
                    </SafeLink>
                    {cve.definitive ? (
                      <Badge className="gap-1 border-success/40 bg-success/10 text-success">
                        <ShieldCheck className="h-3 w-3" />
                        Confirmed version match
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="gap-1 text-muted-foreground">
                        <ShieldQuestion className="h-3 w-3" />
                        Potentially affected: version confidence insufficient for definitive mapping
                      </Badge>
                    )}
                    {cve.known_exploited && (
                      <Badge variant="destructive" className="gap-1">
                        <Skull className="h-3 w-3" />
                        Known Exploited (CISA KEV)
                      </Badge>
                    )}
                  </div>
                  <ConfidenceBadge value={cve.match_confidence} />
                </div>

                <p className="mt-1.5 text-sm text-muted-foreground">
                  {cve.technology_name}
                  {cve.detected_version && <span className="font-mono"> {cve.detected_version}</span>}
                </p>

                {cve.description && <p className="mt-2 text-sm text-foreground">{cve.description}</p>}

                <div className="mt-3 flex flex-wrap gap-4 text-xs">
                  <span className={cn("font-mono", cve.cvss_score == null && "text-muted-foreground")}>
                    <span className="text-muted-foreground">CVSS </span>
                    {cve.cvss_score != null ? `${cve.cvss_score.toFixed(1)} (${cve.cvss_severity ?? "-"})` : "not scored"}
                  </span>
                  <span className={cn("font-mono", cve.epss_score == null && "text-muted-foreground")}>
                    <span className="text-muted-foreground">EPSS </span>
                    {cve.epss_score != null ? `${(cve.epss_score * 100).toFixed(1)}%` : "not scored"}
                    {cve.epss_percentile != null && ` (p${Math.round(cve.epss_percentile * 100)})`}
                  </span>
                </div>

                {cve.reference_links.length > 0 && (
                  <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1">
                    {cve.reference_links.slice(0, 4).map((link, i) => (
                      <SafeLink key={i} url={link} className="text-xs" showIcon>
                        {isSafeUrl(link) ? new URL(link).hostname : link}
                      </SafeLink>
                    ))}
                  </div>
                )}
              </div>
            ))}
            <Separator className="my-1" />
            <PaginationBar offset={offset} limit={LIMIT} total={data.total} onOffsetChange={setOffset} />
          </div>
        )}
      </QuerySection>
    </div>
  );
}
