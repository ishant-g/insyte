import { cn } from "@/lib/utils";
import { titleCase } from "@/lib/format";
import type { ConfidenceBand, Severity } from "@/api/types";

const SEVERITY_STYLE: Record<string, string> = {
  critical: "border-severity-critical/30 bg-severity-critical/10 text-severity-critical",
  high: "border-severity-high/30 bg-severity-high/10 text-severity-high",
  medium: "border-severity-medium/35 bg-severity-medium/10 text-severity-medium",
  low: "border-severity-low/30 bg-severity-low/10 text-severity-low",
  informational: "border-border bg-muted/50 text-muted-foreground",
};

const SEVERITY_DOT: Record<string, string> = {
  critical: "bg-severity-critical",
  high: "bg-severity-high",
  medium: "bg-severity-medium",
  low: "bg-severity-low",
  informational: "bg-severity-informational",
};

export function SeverityBadge({ severity, className }: { severity: Severity | string; className?: string }) {
  const dot = SEVERITY_DOT[severity] ?? "bg-muted-foreground";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold shadow-sm transition-transform duration-150 hover:scale-[1.04]",
        SEVERITY_STYLE[severity] ?? "border-border bg-muted/50 text-muted-foreground",
        className,
      )}
    >
      <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", dot)} />
      {titleCase(severity)}
    </span>
  );
}

const CONFIDENCE_STYLE: Record<string, string> = {
  very_high: "border-confidence-high/30 bg-confidence-high/10 text-confidence-high",
  high: "border-confidence-high/30 bg-confidence-high/10 text-confidence-high",
  medium: "border-confidence-medium/35 bg-confidence-medium/10 text-confidence-medium",
  low: "border-border bg-muted/50 text-muted-foreground",
  very_low: "border-border bg-muted/50 text-muted-foreground",
};

const CONFIDENCE_DOT: Record<string, string> = {
  very_high: "bg-confidence-high",
  high: "bg-confidence-high",
  medium: "bg-confidence-medium",
  low: "bg-confidence-low",
  very_low: "bg-confidence-low",
};

export function ConfidenceBadge({
  band,
  value,
  className,
}: {
  band?: ConfidenceBand | string;
  value?: number;
  className?: string;
}) {
  // value is already a 0-100 integer (matches every Confidence field in
  // the API) - no additional *100 scaling.
  const label = band ? titleCase(band) : value != null ? `${Math.round(value)}%` : "-";
  const dot = band ? (CONFIDENCE_DOT[band] ?? "bg-muted-foreground") : "bg-muted-foreground";
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium",
        band ? (CONFIDENCE_STYLE[band] ?? "border-border bg-muted/50 text-muted-foreground") : "border-border bg-muted/50 text-foreground",
        className,
      )}
    >
      <span className={cn("h-1.5 w-1.5 shrink-0 rounded-full", dot)} />
      {label}
    </span>
  );
}

const EXPOSURE_BAND_STYLE: Record<string, string> = {
  critical: "border-severity-critical/30 bg-severity-critical/10 text-severity-critical",
  high: "border-severity-high/30 bg-severity-high/10 text-severity-high",
  medium: "border-severity-medium/35 bg-severity-medium/10 text-severity-medium",
  low: "border-severity-low/30 bg-severity-low/10 text-severity-low",
  minimal: "border-border bg-muted/50 text-muted-foreground",
};

export function ExposureBandBadge({ band, className }: { band: string; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-semibold shadow-sm",
        EXPOSURE_BAND_STYLE[band] ?? "border-border bg-muted/50 text-muted-foreground",
        className,
      )}
    >
      {titleCase(band)} exposure
    </span>
  );
}
