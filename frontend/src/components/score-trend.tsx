import { useMemo } from "react";
import { Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";

import { scansApi } from "@/api/scans";
import type { ScanListItem } from "@/api/types";
import { ExposureBandBadge } from "@/components/severity-badge";
import { formatDateTime, formatNumber } from "@/lib/format";

const HISTORY_LIMIT = 20;
const TREND_COUNT = 10;

/** Tiny SVG sparkline of exposure scores over time. No chart lib needed:
 * the path is plain polyline math over a 240x48 viewBox. */
function Sparkline({ points, currentId }: { points: ScanListItem[]; currentId: string }) {
  const W = 240;
  const H = 48;
  const pad = 6;
  const coords = useMemo(() => {
    const n = points.length;
    return points.map((p, i) => {
      const x = pad + (i / Math.max(1, n - 1)) * (W - pad * 2);
      const y = H - pad - (Math.min(100, Math.max(0, p.exposure_score ?? 0)) / 100) * (H - pad * 2);
      return { x, y, scan: p };
    });
  }, [points]);

  if (coords.length < 2) return null;
  const path = coords.map((c, i) => `${i === 0 ? "M" : "L"}${c.x.toFixed(1)},${c.y.toFixed(1)}`).join(" ");

  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="h-12 w-full max-w-60" role="img" aria-label="Exposure score trend">
      <path d={path} fill="none" stroke="var(--primary)" strokeWidth="2" strokeLinecap="round" />
      {coords.map((c) => (
        <circle
          key={c.scan.id}
          cx={c.x}
          cy={c.y}
          r={c.scan.id === currentId ? 3.5 : 2.5}
          fill={c.scan.id === currentId ? "var(--primary)" : "var(--muted-foreground)"}
          opacity={c.scan.id === currentId ? 1 : 0.6}
        />
      ))}
    </svg>
  );
}

/** Score history for one target: the last TREND_COUNT scans with an exposure
 * score, rendered as a sparkline plus a dated list. Uses the existing
 * `GET /api/scans?target=` filter, then exact-matches client-side because
 * that filter is a substring match. */
export function ScoreTrend({ targetValue, currentScanId }: { targetValue: string; currentScanId: string }) {
  const history = useQuery({
    queryKey: ["scans", "score-history", targetValue],
    queryFn: () => scansApi.list({ target: targetValue, limit: HISTORY_LIMIT }),
    select: (page) =>
      page.items
        .filter((s) => s.target_value === targetValue && s.exposure_score != null)
        .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())
        .slice(-TREND_COUNT),
  });

  const points = history.data ?? [];
  if (history.isLoading || history.isError) return null;
  if (points.length < 2) {
    return (
      <p className="text-sm text-muted-foreground">
        Not enough history yet. Run this target again and the score trend will appear here.
      </p>
    );
  }

  const first = points[0].exposure_score as number;
  const last = points[points.length - 1].exposure_score as number;
  const delta = last - first;
  const deltaLabel =
    delta === 0 ? "unchanged" : `${delta > 0 ? "+" : ""}${formatNumber(delta)} since ${formatDateTime(points[0].created_at)}`;

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <Sparkline points={points} currentId={currentScanId} />
          <p className="mt-1 text-xs text-muted-foreground">
            {points.length} {points.length === 1 ? "scan" : "scans"} · {deltaLabel}
          </p>
        </div>
      </div>
      <ul className="divide-y divide-border/60">
        {[...points].reverse().map((s) => (
          <li key={s.id} className="flex items-center gap-3 py-1.5 text-xs">
            <span className="font-mono tabular-nums text-foreground">{formatNumber(s.exposure_score ?? 0)}</span>
            {s.exposure_band && <ExposureBandBadge band={s.exposure_band} />}
            <span className="text-muted-foreground">{s.mode === "passive" ? "Passive" : "Web Surface"}</span>
            <span className="ml-auto text-muted-foreground">{formatDateTime(s.created_at)}</span>
            {s.id === currentScanId ? (
              <span className="font-semibold text-primary">this scan</span>
            ) : (
              <Link to="/scans/$scanId" params={{ scanId: s.id }} className="text-primary hover:underline">
                open
              </Link>
            )}
          </li>
        ))}
      </ul>
    </div>
  );
}
