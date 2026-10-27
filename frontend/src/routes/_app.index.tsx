import { useState } from "react";
import { createFileRoute, useNavigate, Link } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowRight, Radar, ScanSearch, Sparkles } from "lucide-react";
import { toast } from "sonner";

import { scansApi } from "@/api/scans";
import { catalogueApi } from "@/api/catalogue";
import type { ScanMode } from "@/api/types";
import { ApiError } from "@/lib/api-client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/page-header";
import { QuerySection } from "@/components/async-state";
import { ScanStatusBadge } from "@/components/scan-status-badge";
import { formatDate, formatNumber } from "@/lib/format";
import { ExposureBandBadge } from "@/components/severity-badge";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_app/")({
  component: Overview,
});

const MODES: { value: ScanMode; label: string; description: string }[] = [
  {
    value: "passive",
    label: "Passive Intelligence",
    description: "Third-party and public records, plus a single read-only GET of the homepage, robots.txt and sitemap.xml. No crawling.",
  },
  {
    value: "web_surface",
    label: "Web Surface Collection",
    description: "Everything in Passive, plus a same-origin crawl of linked pages and their JavaScript/CSS.",
  },
];

function Overview() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [target, setTarget] = useState("");
  const [mode, setMode] = useState<ScanMode>("passive");

  const recentScans = useQuery({
    queryKey: ["scans", "recent"],
    queryFn: () => scansApi.list({ limit: 10, offset: 0 }),
  });

  const modules = useQuery({ queryKey: ["modules"], queryFn: catalogueApi.modules });

  // Quick-run creates a scan straight away using recommended modules for the
  // chosen mode; the full module picker at /new-scan is always one click
  // away via "Configure modules" for anyone who wants control before
  // launching - that choice is surfaced, not hidden, next to the button.
  const runQuick = useMutation({
    mutationFn: () => {
      const recommended = (modules.data ?? [])
        .filter((m) => m.recommended && m.mode_support.includes(mode))
        .map((m) => m.id);
      return scansApi.create({ target: target.trim(), mode, modules: recommended.length ? recommended : undefined });
    },
    onSuccess: (scan) => {
      queryClient.invalidateQueries({ queryKey: ["scans"] });
      navigate({ to: "/scans/$scanId", params: { scanId: scan.id } });
    },
    onError: (error) => {
      toast.error(error instanceof ApiError ? error.message : "Failed to start scan.");
    },
  });

  const canSubmit = target.trim().length > 0;

  return (
    <div className="mx-auto flex max-w-5xl flex-col gap-8">
      <section className="rounded-xl border border-border bg-card px-6 py-10">
        <div className="mx-auto max-w-2xl text-center">
          <div className="mx-auto mb-3 inline-flex items-center gap-1.5 rounded-full border border-border bg-muted/40 px-3 py-1 text-xs font-medium text-muted-foreground">
            <Radar className="h-3.5 w-3.5" />
            Passive Exposure Intelligence
          </div>
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">
            See what the public internet knows about a target
          </h1>
          <p className="mt-2 text-sm text-muted-foreground">
            Enter a domain or IP to build an evidence-backed attack-surface report: assets, relationships,
            findings, and CVE correlations, all sourced and cited.
          </p>
        </div>

        <form
          className="mx-auto mt-6 flex max-w-2xl flex-col gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (canSubmit) runQuick.mutate();
          }}
        >
          <div>
            <Label htmlFor="target" className="sr-only">
              Target domain or IP
            </Label>
            <Input
              id="target"
              placeholder="example.com or 203.0.113.10"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="h-11 text-base font-mono"
              autoComplete="off"
              spellCheck={false}
            />
          </div>

          <div className="grid gap-2 sm:grid-cols-2">
            {MODES.map((m) => (
              <button
                type="button"
                key={m.value}
                onClick={() => setMode(m.value)}
                className={cn(
                  "rounded-lg border px-3 py-2.5 text-left text-sm transition-colors",
                  mode === m.value
                    ? "border-primary bg-primary/10"
                    : "border-border bg-background hover:bg-muted/40",
                )}
              >
                <div className="font-medium text-foreground">{m.label}</div>
                <div className="mt-0.5 text-xs text-muted-foreground">{m.description}</div>
              </button>
            ))}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button type="submit" disabled={!canSubmit || runQuick.isPending} className="h-10">
              <Sparkles className="h-4 w-4" />
              {runQuick.isPending ? "Starting scan…" : "Run Full Intelligence"}
            </Button>
            <Button
              type="button"
              variant="outline"
              className="h-10"
              disabled={!canSubmit}
              onClick={() =>
                navigate({ to: "/new-scan", search: { target: target.trim(), mode } })
              }
            >
              Configure modules
              <ArrowRight className="h-4 w-4" />
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            "Run Full Intelligence" starts immediately with the recommended module set for {mode === "passive" ? "Passive Intelligence" : "Web Surface Collection"}.
            Use "Configure modules" to pick individual modules first.
          </p>
        </form>
      </section>

      <section>
        <PageHeader
          title="Recent scans"
          description="The most recently created scans across all targets."
          actions={
            <Button asChild variant="outline" size="sm">
              <Link to="/scans">
                <ScanSearch className="h-4 w-4" />
                All scans
              </Link>
            </Button>
          }
        />
        <Card className="mt-3">
          <CardContent className="p-4">
            <QuerySection
              isLoading={recentScans.isLoading}
              isError={recentScans.isError}
              error={recentScans.error}
              onRetry={() => recentScans.refetch()}
              data={recentScans.data}
              isEmpty={(d) => d.items.length === 0}
              emptyTitle="No scans yet"
              emptyDescription="Run your first scan above to see it appear here."
            >
              {(data) => (
                <div className="divide-y divide-border">
                  {data.items.map((scan) => (
                    <Link
                      key={scan.id}
                      to="/scans/$scanId"
                      params={{ scanId: scan.id }}
                      className="flex flex-wrap items-center justify-between gap-2 py-2.5 text-sm hover:bg-muted/30 -mx-4 px-4 rounded-md transition-colors"
                    >
                      <div className="flex min-w-0 items-center gap-3">
                        <span className="truncate font-mono font-medium text-foreground">{scan.target_value}</span>
                        <span className="text-xs text-muted-foreground">{scan.mode === "passive" ? "Passive" : "Web Surface"}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        {scan.exposure_band && <ExposureBandBadge band={scan.exposure_band} />}
                        <ScanStatusBadge status={scan.status} progress={scan.progress} />
                        <span className="w-24 shrink-0 text-right text-xs text-muted-foreground">
                          {formatDate(scan.created_at)}
                        </span>
                      </div>
                    </Link>
                  ))}
                  {recentScans.data && recentScans.data.total > 0 && (
                    <p className="pt-2 text-xs text-muted-foreground">
                      {formatNumber(recentScans.data.total)} total scan{recentScans.data.total === 1 ? "" : "s"}
                    </p>
                  )}
                </div>
              )}
            </QuerySection>
          </CardContent>
        </Card>
      </section>
    </div>
  );
}
