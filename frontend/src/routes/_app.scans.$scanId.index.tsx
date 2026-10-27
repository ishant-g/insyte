import { createFileRoute } from "@tanstack/react-router";
import { AlertTriangle, Info } from "lucide-react";

import { useScanDetail } from "@/lib/scan-context";
import { formatNumber } from "@/lib/format";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { StatTile } from "@/components/stat-tile";
import { ModuleChecklist } from "@/components/module-checklist";
import { ProviderStatusList } from "@/components/provider-status-list";
import { SeverityDistributionChart } from "@/components/severity-distribution-chart";
import { ExposureBandBadge } from "@/components/severity-badge";
import { ScoreTrend } from "@/components/score-trend";
import {
  Globe2,
  Network,
  Waypoints,
  Cable,
  FileCode2,
  Fingerprint,
  ListTree,
  ShieldAlert,
  Boxes,
} from "lucide-react";

export const Route = createFileRoute("/_app/scans/$scanId/")({
  component: ScanDashboard,
});

function ScanDashboard() {
  const scan = useScanDetail();
  const data = scan.data!;
  const summary = data.summary ?? {};
  const running = data.status === "queued" || data.status === "running";

  return (
    <div className="flex flex-col gap-6">
      {data.status === "failed" && data.error && (
        <Alert variant="destructive">
          <AlertTriangle className="h-4 w-4" />
          <AlertTitle>Scan failed</AlertTitle>
          <AlertDescription>{data.error}</AlertDescription>
        </Alert>
      )}
      {data.status === "partial" && (
        <Alert>
          <Info className="h-4 w-4" />
          <AlertTitle>Partial results</AlertTitle>
          <AlertDescription>
            Some modules didn't complete: see the module status below for details. The results shown reflect what
            did complete.
          </AlertDescription>
        </Alert>
      )}

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Module status</CardTitle>
        </CardHeader>
        <CardContent>
          <ModuleChecklist modules={data.modules} />
        </CardContent>
      </Card>

      {running && (
        <p className="flex items-center gap-2 text-xs text-muted-foreground">
          <span className="relative flex h-2 w-2">
            <span className="insyte-live-dot absolute inline-flex h-full w-full rounded-full bg-primary/60" />
            <span className="relative inline-flex h-2 w-2 rounded-full bg-primary" />
          </span>
          Results below update automatically as modules complete. This page polls every 2 seconds while the scan is
          in progress.
        </p>
      )}

      <div className="insyte-stagger grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <StatTile label="Assets" value={summary.assets_total} icon={Boxes} />
        <StatTile label="Domains" value={summary.domains} icon={Globe2} />
        <StatTile label="Subdomains" value={summary.subdomains} icon={Globe2} />
        <StatTile label="IPs" value={summary.ips} icon={Network} />
        <StatTile label="URLs" value={summary.urls} icon={Waypoints} />
        <StatTile label="APIs" value={summary.apis} icon={Cable} />
        <StatTile label="JS files" value={summary.javascript_files} icon={FileCode2} />
        <StatTile label="Certificates" value={summary.certificates} icon={Fingerprint} />
        <StatTile label="Technologies" value={summary.technologies} icon={ListTree} />
        <StatTile label="Findings" value={summary.findings_total} icon={ShieldAlert} tone={summary.findings_total ? "high" : "default"} />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Exposure score</CardTitle>
          </CardHeader>
          <CardContent>
            {data.exposure_score != null ? (
              <div className="flex items-center gap-4">
                <div className="font-mono text-4xl font-bold tabular-nums text-foreground">
                  {Math.round(data.exposure_score)}
                  <span className="text-base font-normal text-muted-foreground">/100</span>
                </div>
                {data.exposure_band && <ExposureBandBadge band={data.exposure_band} />}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">Not yet computed.</p>
            )}
            <p className="mt-3 text-xs text-muted-foreground">
              This is Insyte's own exposure prioritisation score: it is <strong>not CVSS</strong>. It blends
              finding severity, confidence, and exposure reachability to help triage; it does not replace
              per-vulnerability CVSS scoring shown on individual CVEs.
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Findings by severity</CardTitle>
          </CardHeader>
          <CardContent>
            {summary.findings_by_severity && Object.keys(summary.findings_by_severity).length > 0 ? (
              <SeverityDistributionChart counts={summary.findings_by_severity} />
            ) : (
              <p className="text-sm text-muted-foreground">
                {formatNumber(summary.findings_total ?? 0)} findings recorded so far.
              </p>
            )}
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Score trend</CardTitle>
          <p className="text-xs text-muted-foreground">
            Exposure scores from the most recent scans of this target. Scores move as findings and
            confidence change between runs, so a small drift between identical scans is expected.
          </p>
        </CardHeader>
        <CardContent>
          <ScoreTrend targetValue={data.target_value} currentScanId={data.id} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Provider status</CardTitle>
        </CardHeader>
        <CardContent>
          <ProviderStatusList providers={data.provider_status ?? {}} />
        </CardContent>
      </Card>
    </div>
  );
}
