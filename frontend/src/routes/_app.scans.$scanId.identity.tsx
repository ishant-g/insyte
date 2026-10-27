import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { AtSign, Building2, Code2, Share2, ShieldAlert } from "lucide-react";

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
import type { AssetRead, FindingRead, ScanDetailRead } from "@/api/types";

export const Route = createFileRoute("/_app/scans/$scanId/identity")({
  component: IdentityPage,
});

function moduleData(scan: ScanDetailRead | undefined, moduleId: string): Record<string, unknown> {
  const m = scan?.modules?.find((x) => x.module_id === moduleId);
  return (m?.data ?? {}) as Record<string, unknown>;
}

interface SocialProfile {
  platform: string;
  url: string;
  status: string;
  confidence: number;
}

interface OrgCandidate {
  name: string;
  source: string;
  url: string | null;
  confidence: number;
}

function SectionTitle({ icon: Icon, title, hint }: { icon: React.ComponentType<{ className?: string }>; title: string; hint?: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="flex h-7 w-7 items-center justify-center rounded-lg bg-primary/10 text-primary">
        <Icon className="h-4 w-4" />
      </span>
      <div>
        <h2 className="text-sm font-semibold text-foreground">{title}</h2>
        {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
      </div>
    </div>
  );
}

function IdentityPage() {
  const { scanId } = Route.useParams();
  const scanQuery = useScanDetail();
  const scan = scanQuery.data;

  const emails = useQuery({
    queryKey: ["assets", scanId, "email"],
    queryFn: () => scansApi.assets(scanId, { asset_type: "email", limit: 200 }),
  });

  const corpFindingsQuery = useQuery({
    queryKey: ["findings", scanId, "corporate_intelligence"],
    queryFn: () => scansApi.findings(scanId, { limit: 100 }),
  });

  const repos = useQuery({
    queryKey: ["assets", scanId, "repository"],
    queryFn: () => scansApi.assets(scanId, { asset_type: "repository", limit: 100 }),
  });

  const repoColumns: DataColumn<AssetRead>[] = [
    {
      key: "value",
      header: "Repository",
      cell: (row) => <span className="font-mono text-xs text-foreground">{row.value}</span>,
    },
    {
      key: "sources",
      header: "Sources",
      cell: (row) => <span className="text-xs text-muted-foreground">{row.sources.join(", ") || "-"}</span>,
    },
    { key: "confidence", header: "Confidence", cell: (row) => <ConfidenceBadge value={row.confidence} /> },
  ];

  const emailColumns: DataColumn<AssetRead>[] = [
    {
      key: "value",
      header: "Email address",
      cell: (row) => <span className="font-mono text-xs text-foreground">{row.value}</span>,
    },
    {
      key: "sources",
      header: "Sources",
      cell: (row) => <span className="text-xs text-muted-foreground">{row.sources.join(", ") || "-"}</span>,
    },
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

  const osintData = moduleData(scan, "email_osint");
  const socialData = moduleData(scan, "social_footprint");
  const corpData = (moduleData(scan, "corporate_intelligence").corporate_intelligence ?? {}) as Record<string, unknown>;

  const profiles = (socialData.social_profiles ?? []) as SocialProfile[];
  const socialNote = ((socialData.summary ?? {}) as Record<string, unknown>).note as string | undefined;
  const verifiedOrgs = (corpData.verified_matches ?? []) as OrgCandidate[];
  const unverifiedOrgs = (corpData.unverified_candidates ?? []) as OrgCandidate[];
  const corpNote = corpData.note as string | undefined;
  const breaches = osintData.domain_breaches as { alias_count: number; breach_names: string[] } | null | undefined;
  const emailPattern = osintData.email_pattern as string | undefined;

  const corpFindings = (corpFindingsQuery.data?.items ?? []).filter((f) => f.module_id === "corporate_intelligence");

  return (
    <div className="flex flex-col gap-8">
      <PageHeader
        title="Identity"
        description="People, accounts, and organizations linked to this target: harvested email addresses, breach exposure, social profiles, and corporate records."
      />

      <section className="flex flex-col gap-3">
        <SectionTitle icon={AtSign} title="Email addresses" hint="Harvested from public sources. Breach metadata only, no passwords." />
        {(emailPattern || breaches !== undefined) && (
          <div className="flex flex-wrap gap-2">
            {emailPattern && (
              <Badge variant="secondary" className="gap-1.5">
                Likely pattern <span className="font-mono">{emailPattern}</span>
              </Badge>
            )}
            {breaches && breaches.breach_names.length > 0 && (
              <Badge variant="outline" className="gap-1.5 border-warning/40 bg-warning/10 text-warning">
                <ShieldAlert className="h-3 w-3" />
                {breaches.alias_count} {breaches.alias_count === 1 ? "alias" : "aliases"} in {breaches.breach_names.length}{" "}
                {breaches.breach_names.length === 1 ? "breach" : "breaches"}: {breaches.breach_names.slice(0, 3).join(", ")}
                {breaches.breach_names.length > 3 && ` +${breaches.breach_names.length - 3} more`}
              </Badge>
            )}
          </div>
        )}
        <QuerySection
          isLoading={emails.isLoading}
          isError={emails.isError}
          error={emails.error}
          onRetry={() => emails.refetch()}
          data={emails.data}
          isEmpty={(d) => d.items.length === 0}
          emptyTitle="No email addresses found"
          emptyState={
            <ScanEmptyState
              title="No email addresses found"
              description="Email harvesting needs the Hunter.io and HaveIBeenPwned API keys. Without them this module skips and the section stays empty."
              moduleIds={["email_osint"]}
            />
          }
        >
          {(data) => <DataTable columns={emailColumns} rows={data.items} rowKey={(r) => r.id} />}
        </QuerySection>
      </section>

      <section className="flex flex-col gap-3">
        <SectionTitle icon={Share2} title="Social profiles" hint="Profiles referencing the target's brand or domain." />
        {profiles.length === 0 ? (
          <ScanEmptyState
            title="No social profiles found"
            moduleIds={["social_footprint"]}
          />
        ) : (
          <div className="flex flex-col gap-3">
            {socialNote && <p className="text-xs text-muted-foreground">{socialNote}</p>}
            <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
              {profiles.map((p, i) => (
                <Card key={i} className="transition-shadow hover:shadow-md">
                  <CardContent className="flex items-center justify-between gap-2 p-3">
                    <div className="min-w-0">
                      <p className="truncate text-sm font-medium capitalize text-foreground">{p.platform}</p>
                      <SafeLink url={p.url} className="block truncate text-xs">
                        {p.url}
                      </SafeLink>
                    </div>
                    <ConfidenceBadge value={p.confidence} />
                  </CardContent>
                </Card>
              ))}
            </div>
          </div>
        )}
      </section>

      <section className="flex flex-col gap-3">
        <SectionTitle icon={Building2} title="Organizations" hint="Corporate registry matches for the target." />
        {verifiedOrgs.length === 0 && unverifiedOrgs.length === 0 && corpFindings.length === 0 ? (
          <ScanEmptyState
            title="No organization matches"
            moduleIds={["corporate_intelligence"]}
          />
        ) : (
          <div className="flex flex-col gap-3">
            {corpNote && <p className="text-xs text-muted-foreground">{corpNote}</p>}
            {verifiedOrgs.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Corroborated matches</CardTitle>
                </CardHeader>
                <CardContent className="flex flex-col gap-2">
                  {verifiedOrgs.map((o, i) => (
                    <div key={i} className="flex items-center justify-between gap-2 rounded-lg border border-border/60 px-3 py-2">
                      <div className="min-w-0">
                        <p className="truncate text-sm font-medium text-foreground">{o.name}</p>
                        <p className="text-xs text-muted-foreground">{o.source}</p>
                      </div>
                      <div className="flex shrink-0 items-center gap-2">
                        {o.url && <SafeLink url={o.url} className="text-xs">Open record</SafeLink>}
                        <ConfidenceBadge value={o.confidence} />
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}
            {unverifiedOrgs.length > 0 && (
              <Card className="border-dashed">
                <CardHeader>
                  <CardTitle className="text-sm text-muted-foreground">Unverified candidates</CardTitle>
                </CardHeader>
                <CardContent className="flex flex-col gap-2">
                  {unverifiedOrgs.slice(0, 10).map((o, i) => (
                    <div key={i} className="flex items-center justify-between gap-2 rounded-lg border border-border/40 bg-muted/40 px-3 py-2">
                      <div className="min-w-0">
                        <p className="truncate text-sm text-foreground">{o.name}</p>
                        <p className="text-xs text-muted-foreground">{o.source} · name similarity only</p>
                      </div>
                      <ConfidenceBadge value={o.confidence} />
                    </div>
                  ))}
                  {unverifiedOrgs.length > 10 && (
                    <p className="text-xs text-muted-foreground">+ {unverifiedOrgs.length - 10} more candidates.</p>
                  )}
                </CardContent>
              </Card>
            )}
            {corpFindings.length > 0 && (
              <DataTable columns={findingColumns} rows={corpFindings} rowKey={(r) => r.id} />
            )}
          </div>
        )}
      </section>

      <section className="flex flex-col gap-3">
        <SectionTitle icon={Code2} title="Code references" hint="Public repositories mentioning this target." />
        <QuerySection
          isLoading={repos.isLoading}
          isError={repos.isError}
          error={repos.error}
          onRetry={() => repos.refetch()}
          data={repos.data}
          isEmpty={(d) => d.items.length === 0}
          emptyTitle="No code references found"
          emptyState={
            <ScanEmptyState
              title="No code references found"
              description="GitHub code search needs a GitHub API token. Without one this module skips and the section stays empty."
              moduleIds={["github_intelligence"]}
            />
          }
        >
          {(data) => <DataTable columns={repoColumns} rows={data.items} rowKey={(r) => r.id} />}
        </QuerySection>
      </section>
    </div>
  );
}
