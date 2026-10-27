import { createFileRoute, Link } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Info } from "lucide-react";

import { catalogueApi } from "@/api/catalogue";
import { credentialsApi } from "@/api/credentials";
import { scansApi } from "@/api/scans";
import { CredentialCard } from "@/components/credential-card";
import { isKeyRejected } from "@/components/provider-status-list";
import { useAuth } from "@/lib/auth";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/page-header";
import { QuerySection } from "@/components/async-state";
import { formatBytes, formatDateTime, formatNumber } from "@/lib/format";

export const Route = createFileRoute("/_app/settings")({
  component: SettingsPage,
});

/** Warns when the most recent finished scan rejected a saved provider key,
 * so a bad key is visible exactly where it can be fixed. */
function RejectedKeyBanner() {
  const recent = useQuery({
    queryKey: ["scans", "recent-for-key-check"],
    queryFn: () => scansApi.list({ limit: 10 }),
  });
  const latestId = recent.data?.items.find((s) =>
    ["completed", "partial", "failed"].includes(s.status),
  )?.id;
  const latest = useQuery({
    queryKey: ["scan", latestId, "key-check"],
    queryFn: () => scansApi.get(latestId as string),
    enabled: !!latestId,
  });

  const rejected = latest.data
    ? Object.values(latest.data.provider_status ?? {}).filter(isKeyRejected)
    : [];
  if (rejected.length === 0) return null;

  return (
    <div className="flex items-start gap-2.5 rounded-xl border border-destructive/50 bg-destructive/5 px-3.5 py-3 text-sm">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-destructive" />
      <div className="min-w-0">
        <p className="font-semibold text-foreground">
          {rejected.length === 1 ? "A saved key was rejected" : "Saved keys were rejected"}
        </p>
        <p className="mt-0.5 text-xs text-muted-foreground">
          {rejected.map((p) => p.name).join(", ")} rejected the saved key in the scan of{" "}
          {latest.data ? (
            <Link
              to="/scans/$scanId"
              params={{ scanId: latest.data.id }}
              className="font-mono text-foreground underline underline-offset-2"
            >
              {latest.data.target_value}
            </Link>
          ) : (
            "your latest scan"
          )}{" "}
          ({latest.data ? formatDateTime(latest.data.created_at) : ""}). Re-check the key{rejected.length === 1 ? "" : "s"} below.
        </p>
      </div>
    </div>
  );
}

function SettingsPage() {
  const { user } = useAuth();
  const settings = useQuery({ queryKey: ["settings"], queryFn: catalogueApi.settings });
  const policy = useQuery({ queryKey: ["security-policy"], queryFn: catalogueApi.securityPolicy });
  const credentials = useQuery({ queryKey: ["credentials"], queryFn: credentialsApi.list });

  return (
    <div className="mx-auto flex max-w-3xl flex-col gap-6">
      <PageHeader
        title="Settings"
        description={`Signed in as ${user?.email ?? ""}. Add your provider API keys below. They are stored encrypted against your account and used automatically on every scan you run. Keyless providers work without any of this.`}
      />

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Provider API keys</CardTitle>
          <p className="text-xs text-muted-foreground">
            Keys are encrypted at rest and never shown again after saving: only a
            masked hint is displayed. Removing a key deletes it from your account;
            signing out simply hides these until you sign back in. A saved key is
            not proof it works: only a scan can confirm the vendor accepts it.
          </p>
        </CardHeader>
        <CardContent className="flex flex-col gap-4">
          <RejectedKeyBanner />
          <QuerySection
            isLoading={credentials.isLoading}
            isError={credentials.isError}
            error={credentials.error}
            onRetry={() => credentials.refetch()}
            data={credentials.data?.providers}
            isEmpty={(d) => d.length === 0}
            emptyTitle="No configurable providers"
          >
            {(providers) => (
              <div className="flex flex-col gap-3">
                {providers.map((p) => (
                  <CredentialCard key={p.provider_id} provider={p} />
                ))}
              </div>
            )}
          </QuerySection>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Application</CardTitle>
        </CardHeader>
        <CardContent>
          <QuerySection
            isLoading={settings.isLoading}
            isError={settings.isError}
            error={settings.error}
            onRetry={() => settings.refetch()}
            data={settings.data}
            isEmpty={() => false}
            emptyTitle=""
          >
            {(data) => (
              <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                <span className="text-muted-foreground">Name</span>
                <span className="text-foreground">{data.app_name}</span>
                <span className="text-muted-foreground">Version</span>
                <span className="font-mono text-foreground">{data.app_version}</span>
                <span className="text-muted-foreground">Environment</span>
                <span className="text-foreground">{data.environment}</span>
                <span className="text-muted-foreground">Tagline</span>
                <span className="text-foreground">{data.tagline}</span>
              </div>
            )}
          </QuerySection>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Scan limits</CardTitle>
        </CardHeader>
        <CardContent>
          <QuerySection
            isLoading={settings.isLoading}
            isError={settings.isError}
            error={settings.error}
            onRetry={() => settings.refetch()}
            data={settings.data}
            isEmpty={() => false}
            emptyTitle=""
          >
            {(data) => (
              <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                <span className="text-muted-foreground">Max URLs per scan</span>
                <span className="font-mono text-foreground">{formatNumber(data.max_urls_per_scan)}</span>
                <span className="text-muted-foreground">Max JS files per scan</span>
                <span className="font-mono text-foreground">{formatNumber(data.max_js_files_per_scan)}</span>
                <span className="text-muted-foreground">Max pages per scan</span>
                <span className="font-mono text-foreground">{formatNumber(data.max_pages_per_scan)}</span>
                <span className="text-muted-foreground">Max subdomains per scan</span>
                <span className="font-mono text-foreground">{formatNumber(data.max_subdomains_per_scan)}</span>
                <span className="text-muted-foreground">Scan time limit</span>
                <span className="font-mono text-foreground">{formatNumber(data.scan_time_limit)}s</span>
                <span className="text-muted-foreground">HTTP timeout</span>
                <span className="font-mono text-foreground">{formatNumber(data.http_total_timeout)}s</span>
                <span className="text-muted-foreground">HTTP max redirects</span>
                <span className="font-mono text-foreground">{formatNumber(data.http_max_redirects)}</span>
                <span className="text-muted-foreground">HTTP max response size</span>
                <span className="font-mono text-foreground">{formatBytes(data.http_max_response_bytes)}</span>
                <span className="text-muted-foreground">HTTP max concurrency</span>
                <span className="font-mono text-foreground">{formatNumber(data.http_max_concurrency)}</span>
                <span className="text-muted-foreground">Cache enabled</span>
                <span className="text-foreground">{data.cache_enabled ? "Yes" : "No"}</span>
                <span className="text-muted-foreground">Report retention</span>
                <span className="font-mono text-foreground">{formatNumber(data.report_retention_days)} days</span>
              </div>
            )}
          </QuerySection>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Providers</CardTitle>
        </CardHeader>
        <CardContent>
          <QuerySection
            isLoading={settings.isLoading}
            isError={settings.isError}
            error={settings.error}
            onRetry={() => settings.refetch()}
            data={settings.data?.providers}
            isEmpty={(d) => d.length === 0}
            emptyTitle="No providers registered"
          >
            {(providers) => (
              <ul className="divide-y divide-border">
                {providers.map((p) => (
                  <li key={p.id} className="flex items-center justify-between gap-2 py-2 text-sm">
                    <div className="flex items-center gap-2">
                      {p.configured ? (
                        <CheckCircle2 className="h-4 w-4 text-success" />
                      ) : (
                        <Info className="h-4 w-4 text-muted-foreground" />
                      )}
                      <span className="text-foreground">{p.name}</span>
                      {p.requires_api_key && (
                        <Badge variant="outline" className="text-[10px]">
                          API key
                        </Badge>
                      )}
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {p.configured ? "Configured" : p.requires_api_key ? "Not configured" : "No key required"}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </QuerySection>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Security policy</CardTitle>
        </CardHeader>
        <CardContent>
          <QuerySection
            isLoading={policy.isLoading}
            isError={policy.isError}
            error={policy.error}
            onRetry={() => policy.refetch()}
            data={policy.data}
            isEmpty={() => false}
            emptyTitle=""
          >
            {(data) => (
              <div className="flex flex-col gap-3 text-sm">
                <div className="grid grid-cols-2 gap-x-4 gap-y-2">
                  <span className="text-muted-foreground">Allowed schemes</span>
                  <span className="font-mono text-foreground">{data.allowed_schemes.join(", ")}</span>
                  <span className="text-muted-foreground">Allowed ports</span>
                  <span className="font-mono text-foreground">{data.allowed_ports.join(", ") || "-"}</span>
                  <span className="text-muted-foreground">Allowed methods</span>
                  <span className="font-mono text-foreground">{data.allowed_methods.join(", ")}</span>
                  <span className="text-muted-foreground">Max redirects</span>
                  <span className="font-mono text-foreground">{formatNumber(data.max_redirects)}</span>
                  <span className="text-muted-foreground">Redirects revalidated</span>
                  <span className="text-foreground">{data.redirects_revalidated ? "Yes" : "No"}</span>
                  <span className="text-muted-foreground">Max response size</span>
                  <span className="font-mono text-foreground">{formatBytes(data.max_response_bytes)}</span>
                  <span className="text-muted-foreground">DNS rebinding protection</span>
                  <span className="text-foreground">{data.dns_rebinding_protection}</span>
                  <span className="text-muted-foreground">Private targets allowed</span>
                  <span className="text-foreground">{data.private_targets_allowed ? "Yes" : "No"}</span>
                </div>
                <Separator />
                {data.blocked_hostnames.length > 0 && (
                  <div>
                    <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Blocked hostnames</p>
                    <p className="font-mono text-xs text-muted-foreground break-all">{data.blocked_hostnames.join(", ")}</p>
                  </div>
                )}
                {data.blocked_suffixes.length > 0 && (
                  <div>
                    <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Blocked suffixes</p>
                    <p className="font-mono text-xs text-muted-foreground break-all">{data.blocked_suffixes.join(", ")}</p>
                  </div>
                )}
                {data.blocked_ipv4_ranges.length > 0 && (
                  <div>
                    <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Blocked IPv4 ranges</p>
                    <p className="font-mono text-xs text-muted-foreground break-all">{data.blocked_ipv4_ranges.join(", ")}</p>
                  </div>
                )}
              </div>
            )}
          </QuerySection>
        </CardContent>
      </Card>
    </div>
  );
}
