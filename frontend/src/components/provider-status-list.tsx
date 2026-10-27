import { Link } from "@tanstack/react-router";
import { AlertTriangle, CheckCircle2, Info } from "lucide-react";

import { cn } from "@/lib/utils";
import { formatNumber } from "@/lib/format";
import type { ProviderStatus } from "@/api/types";

/** True when a configured provider's key was rejected by the vendor (HTTP
 * 401/403/400-style auth failures). The backend raises HttpError with
 * "<provider>: credential rejected (HTTP 403)" for these, which lands in the
 * provider's `errors` list. */
export function isKeyRejected(p: ProviderStatus): boolean {
  if (!p.configured || p.available) return false;
  return p.errors.some((e) => /credential rejected|HTTP 40[013]|unauthorized/i.test(e));
}

function httpCode(errors: string[]): string | null {
  for (const e of errors) {
    const m = e.match(/HTTP (\d{3})/);
    if (m) return m[1];
  }
  return null;
}

/** Three honest states, visually distinct:
 * (a) checked and working -> subtle green;
 * (b) not configured / not checked -> grey "Requires API key";
 * (c) configured but failing -> amber/red "Key rejected" with a pointer to
 *     Settings. Never presented with the weight of a real completed check. */
export function ProviderStatusList({ providers }: { providers: Record<string, ProviderStatus> }) {
  const list = Object.values(providers);
  if (list.length === 0) {
    return <p className="text-sm text-muted-foreground">No provider activity recorded for this scan.</p>;
  }

  return (
    <ul className="flex flex-col gap-2">
      {list.map((p) => {
        const rejected = isKeyRejected(p);
        const code = httpCode(p.errors);
        return (
          <li
            key={p.provider}
            className={cn(
              "flex flex-wrap items-start justify-between gap-2 rounded-xl border px-3.5 py-2.5 text-sm shadow-sm transition-all duration-150 hover:-translate-y-px hover:shadow",
              rejected ? "border-destructive/50 bg-destructive/5" : "border-border/70 bg-card",
            )}
          >
            <div className="flex min-w-0 items-start gap-2.5">
              {p.available ? (
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-success/10">
                  <CheckCircle2 className="h-4 w-4 text-success" />
                </span>
              ) : rejected ? (
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-destructive/10">
                  <AlertTriangle className="h-4 w-4 text-destructive" />
                </span>
              ) : (
                <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-muted/60">
                  <Info className="h-4 w-4 text-muted-foreground" />
                </span>
              )}
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-1.5">
                  <span className="font-semibold text-foreground">{p.name}</span>
                  {p.available && (
                    <span className="rounded-full border border-success/40 bg-success/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-success">
                      Working
                    </span>
                  )}
                  {rejected && (
                    <span className="rounded-full border border-destructive/50 bg-destructive/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-destructive">
                      Key rejected{code ? ` (HTTP ${code})` : ""}
                    </span>
                  )}
                  {!p.available && !p.configured && (
                    <span className="rounded-full border border-border bg-muted/60 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-muted-foreground">
                      Requires API key
                    </span>
                  )}
                  {p.configured && !p.available && !rejected && (
                    <span className="rounded-full border border-warning/40 bg-warning/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-warning">
                      Not working
                    </span>
                  )}
                  {p.rate_limited && (
                    <span className="rounded-full border border-warning/40 bg-warning/10 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-warning">
                      Rate limited
                    </span>
                  )}
                </div>
                {rejected ? (
                  <p className="mt-1 text-xs text-destructive">
                    Key rejected by {p.name}{code ? ` (HTTP ${code})` : ""}.{" "}
                    <Link to="/settings" className="font-semibold underline underline-offset-2">
                      Check the key in Settings
                    </Link>
                  </p>
                ) : (
                  <>
                    {!p.available && p.reason && <p className="text-xs text-muted-foreground">{p.reason}</p>}
                    {p.errors.length > 0 && (
                      <p className={cn("text-xs", p.available ? "text-warning" : "text-muted-foreground")}>
                        {p.errors[0]}
                        {p.errors.length > 1 && ` (+${p.errors.length - 1} more)`}
                      </p>
                    )}
                  </>
                )}
              </div>
            </div>
            <div className="shrink-0 text-right text-xs text-muted-foreground">
              {p.available ? (
                <span className="inline-flex items-center gap-1.5 rounded-full bg-primary/10 px-2 py-0.5 font-semibold text-primary">
                  {formatNumber(p.calls)} call{p.calls === 1 ? "" : "s"} · {formatNumber(p.result_count)} result
                  {p.result_count === 1 ? "" : "s"}
                  {p.cache_hits > 0 && ` · ${formatNumber(p.cache_hits)} cached`}
                </span>
              ) : (
                <span className="text-muted-foreground/70">Not used</span>
              )}
            </div>
          </li>
        );
      })}
    </ul>
  );
}

export function providerHasIssue(p: ProviderStatus): boolean {
  return p.available && p.errors.length > 0;
}
