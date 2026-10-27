import { cn } from "@/lib/utils";
import { formatNumber } from "@/lib/format";

const TONE_GRADIENT: Record<string, string> = {
  default: "from-primary/15 to-chart-2/10 text-primary",
  critical: "from-severity-critical/20 to-severity-critical/5 text-severity-critical",
  high: "from-severity-high/20 to-severity-high/5 text-severity-high",
  medium: "from-severity-medium/20 to-severity-medium/5 text-severity-medium",
  low: "from-severity-low/20 to-severity-low/5 text-severity-low",
};

export function StatTile({
  label,
  value,
  icon: Icon,
  className,
  tone,
}: {
  label: string;
  value: number | string | null | undefined;
  icon?: React.ComponentType<{ className?: string }>;
  className?: string;
  tone?: "default" | "critical" | "high" | "medium" | "low";
}) {
  const t = tone ?? "default";
  return (
    <div
      className={cn(
        "insyte-card-hover group rounded-xl border border-border/70 bg-card px-4 py-3.5 shadow-sm",
        className,
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">{label}</span>
        {Icon && (
          <span className={cn("flex h-7 w-7 items-center justify-center rounded-lg bg-gradient-to-br shadow-sm transition-transform duration-200 group-hover:scale-110", TONE_GRADIENT[t])}>
            <Icon className="h-3.5 w-3.5" />
          </span>
        )}
      </div>
      <div className="mt-1.5 font-mono text-[1.65rem] font-bold tabular-nums leading-none text-foreground">
        {typeof value === "number" ? formatNumber(value) : (value ?? "-")}
      </div>
    </div>
  );
}
