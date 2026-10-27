import { CheckCircle2, CircleDashed, CircleSlash, LoaderCircle, TriangleAlert, XCircle } from "lucide-react";

import { cn } from "@/lib/utils";
import { titleCase } from "@/lib/format";
import type { ScanStatus } from "@/api/types";

const STATUS_STYLE: Record<ScanStatus, { icon: React.ComponentType<{ className?: string }>; className: string }> = {
  queued: { icon: CircleDashed, className: "border-border bg-muted/50 text-muted-foreground" },
  running: { icon: LoaderCircle, className: "border-primary/30 bg-primary/10 text-primary" },
  partial: { icon: TriangleAlert, className: "border-warning/40 bg-warning/10 text-warning" },
  completed: { icon: CheckCircle2, className: "border-success/30 bg-success/10 text-success" },
  failed: { icon: XCircle, className: "border-destructive/30 bg-destructive/10 text-destructive" },
  cancelled: { icon: CircleSlash, className: "border-border bg-muted/50 text-muted-foreground" },
};

export function ScanStatusBadge({ status, progress }: { status: ScanStatus; progress?: number }) {
  const style = STATUS_STYLE[status] ?? STATUS_STYLE.queued;
  const Icon = style.icon;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold shadow-sm",
        style.className,
      )}
    >
      {status === "running" ? (
        <span className="relative flex h-3.5 w-3.5">
          <span className="insyte-live-dot absolute inline-flex h-full w-full rounded-full bg-primary/50" />
          <Icon className="insyte-loader relative h-3.5 w-3.5" />
        </span>
      ) : (
        <Icon className="h-3.5 w-3.5" />
      )}
      {titleCase(status)}
      {status === "running" && progress != null && (
        <span className="tabular-nums opacity-80">{Math.round(progress)}%</span>
      )}
    </span>
  );
}

/** Slim animated progress bar shown while a scan is running. Shows the real
 * progress value: no cosmetic floor, so 0% reads as 0% and matches the
 * badge next to it. */
export function ScanProgressBar({ progress }: { progress: number }) {
  const pct = Math.max(0, Math.min(100, Math.round(progress)));
  return (
    <div className="flex items-center gap-3">
      <div className="h-2 flex-1 overflow-hidden rounded-full bg-muted">
        <div className="insyte-progress-fill h-full rounded-full" style={{ width: `${pct}%` }} />
      </div>
      <span className="w-11 text-right font-mono text-xs font-semibold tabular-nums text-primary">{pct}%</span>
    </div>
  );
}
