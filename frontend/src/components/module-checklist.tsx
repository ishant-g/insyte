import { CheckCircle2, CircleDashed, KeyRound, LoaderCircle, OctagonX, SkipForward } from "lucide-react";

import { cn } from "@/lib/utils";
import { formatDuration, formatNumber } from "@/lib/format";
import { humanizeSkipReason } from "@/components/scan-empty-state";
import type { ScanModuleRead } from "@/api/types";

const STATUS_META: Record<
  ScanModuleRead["status"],
  {
    icon: React.ComponentType<{ className?: string }>;
    chip: string;
    iconColor: string;
    label: string;
    rowTint: string;
  }
> = {
  completed: {
    icon: CheckCircle2,
    chip: "border-success/30 bg-success/10 text-success",
    iconColor: "text-success",
    label: "Completed",
    rowTint: "",
  },
  running: {
    icon: LoaderCircle,
    chip: "border-primary/30 bg-primary/10 text-primary",
    iconColor: "text-primary",
    label: "Running",
    rowTint: "bg-primary/[0.03]",
  },
  queued: {
    icon: CircleDashed,
    chip: "border-border bg-muted/50 text-muted-foreground",
    iconColor: "text-muted-foreground",
    label: "Queued",
    rowTint: "opacity-70",
  },
  failed: {
    icon: OctagonX,
    chip: "border-destructive/30 bg-destructive/10 text-destructive",
    iconColor: "text-destructive",
    label: "Failed",
    rowTint: "bg-destructive/[0.03]",
  },
  skipped: {
    icon: SkipForward,
    chip: "border-warning/40 bg-warning/10 text-warning",
    iconColor: "text-warning",
    label: "Skipped",
    rowTint: "bg-warning/[0.04]",
  },
};

/** Real per-module status from the backend - no simulated progress bars.
 * Modules stay in whatever order the server reports (their `sequence`).
 * Skip reasons are surfaced prominently and in plain language so an empty
 * module never looks like a successful one. */
export function ModuleChecklist({ modules }: { modules: ScanModuleRead[] }) {
  const sorted = [...modules].sort((a, b) => a.sequence - b.sequence);
  const counts = {
    completed: sorted.filter((m) => m.status === "completed").length,
    skipped: sorted.filter((m) => m.status === "skipped").length,
    failed: sorted.filter((m) => m.status === "failed").length,
    running: sorted.filter((m) => m.status === "running" || m.status === "queued").length,
  };
  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <StatusPill tone="success" label={`${counts.completed} completed`} />
        {counts.skipped > 0 && <StatusPill tone="warning" label={`${counts.skipped} skipped`} />}
        {counts.failed > 0 && <StatusPill tone="destructive" label={`${counts.failed} failed`} />}
        {counts.running > 0 && <StatusPill tone="primary" label={`${counts.running} pending`} />}
      </div>
      <ul className="flex flex-col overflow-hidden rounded-xl border border-border bg-card shadow-sm">
        {sorted.map((m) => {
          const meta = STATUS_META[m.status] ?? STATUS_META.queued;
          const Icon = meta.icon;
          const empty = m.status === "completed" && m.result_count === 0 && m.finding_count === 0;
          return (
            <li
              key={m.module_id}
              className={cn(
                "flex flex-col gap-1 border-b border-border/60 px-3.5 py-2.5 text-sm transition-colors last:border-b-0 hover:bg-muted/30",
                meta.rowTint,
              )}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex min-w-0 items-center gap-2.5">
                  <span className={cn("flex h-7 w-7 shrink-0 items-center justify-center rounded-full border", meta.chip)}>
                    <Icon className={cn("h-3.5 w-3.5", m.status === "running" ? "insyte-loader" : meta.iconColor)} />
                  </span>
                  <span className="truncate font-medium text-foreground">{m.display_name}</span>
                  <span className={cn("rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide", meta.chip)}>
                    {meta.label}
                  </span>
                  {empty && (
                    <span className="text-[11px] text-muted-foreground">(ran, found nothing)</span>
                  )}
                </div>
                <div className="flex items-center gap-3 text-xs text-muted-foreground">
                  {m.status === "completed" && !empty && (
                    <span className="tabular-nums">
                      {formatNumber(m.result_count)} result{m.result_count === 1 ? "" : "s"}
                      {m.finding_count > 0 && (
                        <span className="font-medium text-warning">
                          {" "}· {formatNumber(m.finding_count)} finding{m.finding_count === 1 ? "" : "s"}
                        </span>
                      )}
                    </span>
                  )}
                  {m.duration != null && m.status !== "queued" && (
                    <span className="tabular-nums">{formatDuration(m.duration)}</span>
                  )}
                </div>
              </div>
              {m.status === "skipped" && (
                <p className="flex items-start gap-1.5 rounded-lg border border-warning/25 bg-warning/[0.07] px-2.5 py-1.5 text-xs text-foreground">
                  <KeyRound className="mt-0.5 h-3.5 w-3.5 shrink-0 text-warning" />
                  <span>
                    <span className="font-medium">Why skipped: </span>
                    <span className="text-muted-foreground">{humanizeSkipReason(m.skip_reason)}</span>
                  </span>
                </p>
              )}
              {m.status === "failed" && m.error && (
                <p className="flex items-start gap-1.5 rounded-lg border border-destructive/25 bg-destructive/[0.06] px-2.5 py-1.5 text-xs">
                  <OctagonX className="mt-0.5 h-3.5 w-3.5 shrink-0 text-destructive" />
                  <span className="text-muted-foreground">{m.error}</span>
                </p>
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

function StatusPill({ tone, label }: { tone: "success" | "warning" | "destructive" | "primary"; label: string }) {
  const colors = {
    success: "border-success/30 bg-success/10 text-success",
    warning: "border-warning/40 bg-warning/10 text-warning",
    destructive: "border-destructive/30 bg-destructive/10 text-destructive",
    primary: "border-primary/30 bg-primary/10 text-primary",
  } as const;
  return (
    <span className={cn("rounded-full border px-2 py-0.5 text-[11px] font-semibold", colors[tone])}>{label}</span>
  );
}
