import { useEffect, useMemo, useState } from "react";
import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { KeyRound, Sparkles } from "lucide-react";
import { toast } from "sonner";
import { z } from "zod";

import { scansApi } from "@/api/scans";
import { catalogueApi } from "@/api/catalogue";
import type { ModuleDescriptor, ScanMode } from "@/api/types";
import { ApiError } from "@/lib/api-client";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Card, CardContent } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { PageHeader } from "@/components/page-header";
import { QuerySection } from "@/components/async-state";

const searchSchema = z.object({
  target: z.string().optional().default(""),
  mode: z.enum(["passive", "web_surface"]).optional().default("passive"),
});

export const Route = createFileRoute("/_app/new-scan")({
  validateSearch: searchSchema,
  component: NewScan,
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

// Client-side nicety only - the backend re-validates and returns a 422 with
// the authoritative error, which we surface verbatim on submit failure.
function looksLikeValidTarget(value: string): boolean {
  const v = value.trim();
  if (!v) return false;
  const domainRe = /^(?!-)[a-z0-9-]{1,63}(?<!-)(\.[a-z0-9-]{1,63})+$/i;
  const ipv4Re = /^(\d{1,3}\.){3}\d{1,3}$/;
  return domainRe.test(v) || ipv4Re.test(v) || v.includes(":");
}

function NewScan() {
  const { target: initialTarget, mode: initialMode } = Route.useSearch();
  const navigate = useNavigate();
  const [target, setTarget] = useState(initialTarget);
  const [mode, setMode] = useState<ScanMode>(initialMode);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [touchedSelection, setTouchedSelection] = useState(false);

  const modulesQuery = useQuery({ queryKey: ["modules"], queryFn: catalogueApi.modules });
  const providersQuery = useQuery({ queryKey: ["providers"], queryFn: catalogueApi.providers });
  const healthQuery = useQuery({
    queryKey: ["health"],
    queryFn: catalogueApi.health,
    refetchInterval: 15000,
    retry: false,
  });
  const workerDown = healthQuery.data != null && !healthQuery.data.worker_alive;

  const providersById = useMemo(() => {
    const map = new Map<string, boolean>();
    for (const p of providersQuery.data ?? []) map.set(p.id, p.configured);
    return map;
  }, [providersQuery.data]);

  const modeModules = useMemo(
    () => (modulesQuery.data ?? []).filter((m) => m.mode_support.includes(mode)),
    [modulesQuery.data, mode],
  );

  // Default the selection to the recommended set for the mode once modules
  // load, unless the user has already started picking manually.
  useEffect(() => {
    if (!touchedSelection && modeModules.length > 0) {
      setSelected(new Set(modeModules.filter((m) => m.recommended).map((m) => m.id)));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [modeModules.length, mode]);

  function isUnavailable(m: ModuleDescriptor): boolean {
    if (!m.requires_api_key) return false;
    if (m.providers.length === 0) return true;
    return !m.providers.some((pid) => providersById.get(pid));
  }

  const grouped = useMemo(() => {
    const groups = new Map<string, { label: string; modules: ModuleDescriptor[] }>();
    for (const m of modeModules) {
      if (!groups.has(m.category)) groups.set(m.category, { label: m.category_label, modules: [] });
      groups.get(m.category)!.modules.push(m);
    }
    return Array.from(groups.values());
  }, [modeModules]);

  function toggle(id: string) {
    setTouchedSelection(true);
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const createScan = useMutation({
    mutationFn: () =>
      scansApi.create({
        target: target.trim(),
        mode,
        modules: selected.size > 0 ? Array.from(selected) : undefined,
      }),
    onSuccess: (scan) => {
      for (const warning of scan.warnings ?? []) {
        toast.warning(warning, { duration: 12000 });
      }
      navigate({ to: "/scans/$scanId", params: { scanId: scan.id } });
    },
    onError: (error) => {
      const message =
        error instanceof ApiError
          ? error.status === 422
            ? `Invalid scan configuration: ${error.message}`
            : error.message
          : "Failed to start scan.";
      toast.error(message);
    },
  });

  const targetHint = target.trim().length > 0 && !looksLikeValidTarget(target)
    ? "This doesn't look like a domain or IP address. The scan may be rejected by the server."
    : null;

  return (
    <div className="mx-auto flex max-w-4xl flex-col gap-6">
      <PageHeader title="New scan" description="Choose a target, mode, and the modules that will run." />

      {workerDown && (
        <Alert variant="destructive">
          <AlertTitle>Scan worker unreachable</AlertTitle>
          <AlertDescription>
            No scan worker is answering. Scans you start now will wait in the queue until a worker comes online.
            Make sure Redis is up and the Celery worker is running.
          </AlertDescription>
        </Alert>
      )}

      <Card>
        <CardContent className="flex flex-col gap-4 p-5">
          <div>
            <Label htmlFor="target">Target</Label>
            <Input
              id="target"
              className="mt-1.5 font-mono"
              placeholder="example.com or 203.0.113.10"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
            {targetHint && <p className="mt-1.5 text-xs text-warning">{targetHint}</p>}
          </div>

          <div>
            <Label>Mode</Label>
            <div className="mt-1.5 grid gap-2 sm:grid-cols-2">
              {MODES.map((m) => (
                <button
                  type="button"
                  key={m.value}
                  onClick={() => {
                    setMode(m.value);
                    setTouchedSelection(false);
                  }}
                  className={cn(
                    "group rounded-xl border px-4 py-3 text-left text-sm transition-all duration-150 hover:-translate-y-px hover:shadow",
                    mode === m.value
                      ? "border-primary/60 bg-primary/[0.06] shadow-primary/10 ring-1 ring-primary/30"
                      : "border-border/70 bg-card shadow-sm hover:border-primary/30",
                  )}
                >
                  <div className="font-medium text-foreground">{m.label}</div>
                  <div className="mt-0.5 text-xs text-muted-foreground">{m.description}</div>
                </button>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      <section>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-foreground">Modules</h2>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setTouchedSelection(true);
                setSelected(new Set(modeModules.map((m) => m.id)));
              }}
            >
              Select all
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setTouchedSelection(true);
                setSelected(new Set());
              }}
            >
              Clear all
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => {
                setTouchedSelection(true);
                setSelected(new Set(modeModules.filter((m) => m.recommended).map((m) => m.id)));
              }}
            >
              Recommended
            </Button>
          </div>
        </div>

        <div className="mt-3">
          <QuerySection
            isLoading={modulesQuery.isLoading}
            isError={modulesQuery.isError}
            error={modulesQuery.error}
            onRetry={() => modulesQuery.refetch()}
            data={grouped}
            isEmpty={(d) => d.length === 0}
            emptyTitle="No modules available for this mode"
          >
            {(groups) => (
              <div className="flex flex-col gap-5">
                {groups.map((group) => (
                  <div key={group.label}>
                    <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                      {group.label}
                    </h3>
                    <div className="grid gap-2 sm:grid-cols-2">
                      {group.modules.map((m) => {
                        const unavailable = isUnavailable(m);
                        const checked = selected.has(m.id);
                        return (
                          <label
                            key={m.id}
                            className={cn(
                              "flex cursor-pointer items-start gap-2.5 rounded-xl border border-border/70 bg-card px-3.5 py-3 text-sm shadow-sm transition-all duration-150 hover:-translate-y-px hover:border-primary/40 hover:shadow",
                              checked && "border-primary/60 bg-primary/[0.06] shadow-primary/10 ring-1 ring-primary/30",
                              unavailable && "opacity-80",
                            )}
                          >
                            <Checkbox checked={checked} onCheckedChange={() => toggle(m.id)} className="mt-0.5" />
                            <div className="min-w-0">
                              <div className="flex flex-wrap items-center gap-1.5">
                                <span className="font-medium text-foreground">{m.name}</span>
                                {m.recommended && (
                                  <span className="rounded border border-primary/40 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-primary">
                                    Recommended
                                  </span>
                                )}
                                {unavailable && (
                                  <span className="inline-flex items-center gap-1 rounded border border-warning/40 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-warning">
                                    <KeyRound className="h-2.5 w-2.5" />
                                    Won't run: no API key
                                  </span>
                                )}
                              </div>
                              <p className="mt-0.5 text-xs text-muted-foreground">{m.description}</p>
                            </div>
                          </label>
                        );
                      })}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </QuerySection>
        </div>
      </section>

      <div className="sticky bottom-4 flex items-center justify-between gap-3 rounded-xl border border-border/70 bg-card/95 px-4 py-3 shadow-lg backdrop-blur-xl">
        <p className="text-xs text-muted-foreground">
          {selected.size} module{selected.size === 1 ? "" : "s"} selected
          {selected.size === 0 && ". Omitting selection runs the server's default module set"}
        </p>
        <Button onClick={() => createScan.mutate()} disabled={!target.trim() || createScan.isPending} className="insyte-btn shadow-sm">
          <Sparkles className="h-4 w-4" />
          {createScan.isPending ? "Starting scan…" : "Run Intelligence"}
        </Button>
      </div>

      {providersQuery.data && providersQuery.data.every((p) => !p.configured && p.requires_api_key) && (
        <Alert className="border-warning/40 bg-warning/[0.06]">
          <KeyRound className="h-4 w-4 text-warning" />
          <AlertTitle className="text-warning">No API keys configured</AlertTitle>
          <AlertDescription>
            No external providers have API keys configured on this deployment. Modules that require one are marked
            above and will be skipped, but passive collection from unauthenticated sources still runs.
          </AlertDescription>
        </Alert>
      )}
    </div>
  );
}
