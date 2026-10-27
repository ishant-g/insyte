import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import {
  AlertTriangle,
  Ban,
  Info,
  KeyRound,
  SearchX,
  Settings2,
  XCircle,
} from "lucide-react";

import { catalogueApi } from "@/api/catalogue";
import { useScanDetail } from "@/lib/scan-context";
import { isTerminalStatus } from "@/lib/scan-context";
import { cn } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import type { ScanModuleRead } from "@/api/types";

/**
 * Honest empty states for scan detail pages.
 *
 * Instead of a generic "No results", this explains WHY a page is empty by
 * reading the scan's real module statuses, skip reasons and provider
 * configuration:
 *   - scan still running      -> "results are still arriving"
 *   - module skipped          -> shows the backend skip_reason, humanized
 *   - module failed           -> shows the error
 *   - module not selected     -> "wasn't selected for this scan"
 *   - provider key missing    -> "needs an API key" + link to Settings
 *   - completed but empty    -> genuine "nothing found"
 *   - web-only page in passive mode -> explains the mode boundary
 */

type EmptyKind = "running" | "failed" | "skipped" | "not-selected" | "mode" | "genuine";

const KIND_STYLE: Record<
  EmptyKind,
  {
    icon: React.ComponentType<{ className?: string }>;
    ring: string;
    iconColor: string;
    panel: string;
  }
> = {
  running: {
    icon: Info,
    ring: "border-primary/30 bg-primary/10",
    iconColor: "text-primary",
    panel: "border-primary/25 bg-primary/[0.04]",
  },
  failed: {
    icon: XCircle,
    ring: "border-destructive/30 bg-destructive/10",
    iconColor: "text-destructive",
    panel: "border-destructive/25 bg-destructive/[0.04]",
  },
  skipped: {
    icon: KeyRound,
    ring: "border-warning/40 bg-warning/10",
    iconColor: "text-warning",
    panel: "border-warning/30 bg-warning/[0.06]",
  },
  "not-selected": {
    icon: Ban,
    ring: "border-border bg-muted/60",
    iconColor: "text-muted-foreground",
    panel: "border-dashed",
  },
  mode: {
    icon: Info,
    ring: "border-chart-5/30 bg-chart-5/10",
    iconColor: "text-chart-5",
    panel: "border-chart-5/25 bg-chart-5/[0.05]",
  },
  genuine: {
    icon: SearchX,
    ring: "border-border bg-muted/60",
    iconColor: "text-muted-foreground",
    panel: "border-dashed",
  },
};

/** Turn backend skip_reason strings into human-readable explanations. */
export function humanizeSkipReason(reason: string | null | undefined): string {
  if (!reason) return "Skipped by the scan orchestrator.";
  const r = reason.toLowerCase();
  if (r.includes("api key") || r.includes("api_key") || r.includes("credentials") || r.includes("unauthorized")) {
    return "Needs an API key: configure one in Settings to enable it.";
  }
  if (r.includes("rate limit") || r.includes("rate_limited") || r.includes("429")) {
    return "Rate limited by the upstream provider. Try re-running later.";
  }
  if (r.includes("mode") || r.includes("not supported") || r.includes("not applicable")) {
    return "Not applicable to this scan's mode.";
  }
  if (r.includes("depend")) {
    return "Skipped because a module it depends on was deselected.";
  }
  if (r.includes("target") && (r.includes("type") || r.includes("invalid"))) {
    return "Not applicable to this target type.";
  }
  return reason;
}

function findModules(scanModules: ScanModuleRead[] | undefined, ids: string[] | undefined): ScanModuleRead[] {
  if (!scanModules) return [];
  if (!ids || ids.length === 0) return scanModules;
  return scanModules.filter((m) => ids.includes(m.module_id));
}

export function ScanEmptyState({
  title,
  description,
  moduleIds,
  modeNote,
  action,
  className,
}: {
  /** Fallback title used when no more specific reason is found. */
  title: string;
  description?: string;
  /** Module IDs that feed this page. Omit to consider all scan modules. */
  moduleIds?: string[];
  /** Shown when the page can never have data in the scan's mode. */
  modeNote?: string;
  action?: React.ReactNode;
  className?: string;
}) {
  const scanQuery = useScanDetail();
  const scan = scanQuery.data;

  const catalogue = useQuery({ queryKey: ["modules"], queryFn: catalogueApi.modules, staleTime: 60_000 });

  // Catalogue unavailable or scan not loaded yet -> generic honest fallback.
  if (!scan) {
    return (
      <EmptyPanel kind="genuine" title={title} description={description} action={action} className={className} />
    );
  }

  const running = !isTerminalStatus(scan.status);

  // 1. Scan still in flight: results may simply not have arrived yet.
  if (running) {
    const modules = findModules(scan.modules, moduleIds);
    const done = modules.filter((m) => m.status === "completed" || m.status === "skipped" || m.status === "failed").length;
    return (
      <EmptyPanel
        kind="running"
        title="Scan still in progress"
        description={
          modules.length > 0
            ? `${done} of ${modules.length} relevant module${modules.length === 1 ? "" : "s"} finished. Results appear here automatically as they complete.`
            : "Results appear here automatically as modules complete."
        }
        action={action}
        className={className}
        live
      />
    );
  }

  // 2. Mode boundary: this page can never have data in this scan's mode.
  if (modeNote && scan.mode === "passive") {
    return (
      <EmptyPanel
        kind="mode"
        title="Not collected in Passive mode"
        description={modeNote}
        action={action}
        className={className}
      />
    );
  }

  const relevant = findModules(scan.modules, moduleIds);
  const skipped = relevant.filter((m) => m.status === "skipped");
  const failed = relevant.filter((m) => m.status === "failed");
  const missingIds = (moduleIds ?? []).filter((id) => !relevant.some((m) => m.module_id === id));
  const completedEmpty = relevant.filter(
    (m) => m.status === "completed" && m.result_count === 0 && m.finding_count === 0,
  );

  // Providers behind the relevant modules that need a key and don't have one.
  const unconfiguredProviders: { id: string; name: string }[] = [];
  if (catalogue.data && scan.provider_status) {
    const providerIds = new Set<string>();
    for (const m of catalogue.data) {
      if (!moduleIds || moduleIds.includes(m.id)) {
        for (const pid of m.providers) providerIds.add(pid);
      }
    }
    for (const pid of providerIds) {
      const st = scan.provider_status[pid];
      if (st && st.requires_api_key && !st.configured) {
        unconfiguredProviders.push({ id: pid, name: st.name || pid });
      }
    }
  }

  const reasons: { label: string; detail?: string; keyHint?: boolean }[] = [];
  for (const m of skipped) {
    reasons.push({
      label: `${m.display_name} was skipped`,
      detail: humanizeSkipReason(m.skip_reason),
      keyHint: /api key/i.test(m.skip_reason ?? ""),
    });
  }
  for (const m of failed) {
    reasons.push({
      label: `${m.display_name} failed`,
      detail: m.error ?? "See scan logs for details.",
    });
  }
  for (const id of missingIds) {
    const pretty = id.replace(/_/g, " ");
    reasons.push({ label: `${pretty} wasn't selected`, detail: "This module wasn't selected when the scan was created." });
  }

  const needsKey = reasons.some((r) => r.keyHint) || unconfiguredProviders.length > 0;

  // 3. Skipped / failed / missing modules explain the emptiness.
  if (reasons.length > 0) {
    const kind: EmptyKind = failed.length > 0 && skipped.length === 0 ? "failed" : "skipped";
    return (
      <EmptyPanel
        kind={kind}
        title={failed.length > 0 && skipped.length === 0 ? title : "Incomplete data: here's why"}
        description={description}
        action={
          <>
            {needsKey && (
              <Button asChild size="sm" className="gap-1.5">
                <Link to="/settings">
                  <Settings2 className="h-3.5 w-3.5" />
                  Open provider settings
                </Link>
              </Button>
            )}
            {action}
          </>
        }
        className={className}
      >
        <ul className="mt-3 flex w-full max-w-md flex-col gap-1.5 text-left">
          {reasons.slice(0, 5).map((r, i) => (
            <li
              key={i}
              className="flex items-start gap-2 rounded-lg border border-border/60 bg-card/60 px-3 py-2 text-xs"
            >
              {r.keyHint ? (
                <KeyRound className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" />
              ) : failed.length > 0 ? (
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-destructive" />
              ) : (
                <Info className="mt-0.5 h-3.5 w-3.5 shrink-0 text-muted-foreground" />
              )}
              <span>
                <span className="font-medium text-foreground">{r.label}</span>
                {r.detail && <span className="text-muted-foreground">: {r.detail}</span>}
              </span>
            </li>
          ))}
          {reasons.length > 5 && (
            <li className="px-3 text-xs text-muted-foreground">+ {reasons.length - 5} more. See the module status on the scan overview.</li>
          )}
        </ul>
        {unconfiguredProviders.length > 0 && (
          <p className="mt-2 max-w-md text-xs text-muted-foreground">
            Missing keys:{" "}
            <span className="font-medium text-foreground">
              {unconfiguredProviders.slice(0, 4).map((p) => p.name).join(", ")}
            </span>
            {unconfiguredProviders.length > 4 && ` +${unconfiguredProviders.length - 4} more`}. Keyless
            providers still ran; only key-gated sources were skipped.
          </p>
        )}
      </EmptyPanel>
    );
  }

  // 4. Modules ran fine but found nothing: genuine empty.
  if (completedEmpty.length > 0 || relevant.length > 0) {
    const names = completedEmpty.slice(0, 3).map((m) => m.display_name).join(", ");
    return (
      <EmptyPanel
        kind="genuine"
        title={title}
        description={
          description ??
          (names
            ? `${names} ran successfully but found nothing for this target. That is a real result, not an error.`
            : "The relevant modules ran successfully but found nothing for this target.")
        }
        action={action}
        className={className}
      />
    );
  }

  // 5. Ultimate fallback.
  return <EmptyPanel kind="genuine" title={title} description={description} action={action} className={className} />;
}

function EmptyPanel({
  kind,
  title,
  description,
  action,
  children,
  className,
  live,
}: {
  kind: EmptyKind;
  title: string;
  description?: React.ReactNode;
  action?: React.ReactNode;
  children?: React.ReactNode;
  className?: string;
  live?: boolean;
}) {
  const style = KIND_STYLE[kind];
  const Icon = style.icon;
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-2 rounded-xl border bg-card px-6 py-12 text-center shadow-sm",
        style.panel,
        className,
      )}
    >
      <span className={cn("flex h-11 w-11 items-center justify-center rounded-full border", style.ring)}>
        {live ? (
          <span className="relative flex h-4 w-4">
            <span className={cn("insyte-live-dot absolute inline-flex h-full w-full rounded-full", "bg-primary/60")} />
            <span className="relative inline-flex h-4 w-4 rounded-full bg-primary" />
          </span>
        ) : (
          <Icon className={cn("h-5 w-5", style.iconColor)} />
        )}
      </span>
      <p className="text-sm font-semibold text-foreground">{title}</p>
      {description && <p className="max-w-md text-sm text-muted-foreground">{description}</p>}
      {children}
      {action && <div className="mt-3 flex flex-wrap items-center justify-center gap-2">{action}</div>}
    </div>
  );
}
