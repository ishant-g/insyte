import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle } from "lucide-react";

import { scansApi } from "@/api/scans";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { PageHeader } from "@/components/page-header";
import { QuerySection } from "@/components/async-state";
import { ScanEmptyState } from "@/components/scan-empty-state";
import { formatDate, formatNumber, truncateMiddle } from "@/lib/format";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_app/scans/$scanId/certificates")({
  component: CertificatesPage,
});

function CertificatesPage() {
  const { scanId } = Route.useParams();
  const certs = useQuery({ queryKey: ["certificates", scanId], queryFn: () => scansApi.certificates(scanId) });

  return (
    <div className="flex flex-col gap-4">
      <PageHeader title="Certificates" description="TLS certificates observed for this target's hosts." />

      <QuerySection
        isLoading={certs.isLoading}
        isError={certs.isError}
        error={certs.error}
        onRetry={() => certs.refetch()}
        data={certs.data}
        isEmpty={(d) => d.length === 0}
        emptyTitle="No certificates observed"
        emptyState={
          <ScanEmptyState
            title="No certificates observed"
            moduleIds={["certificate_intelligence"]}
          />
        }
      >
        {(data) => (
          <div className="grid gap-3 md:grid-cols-2">
            {data.map((cert) => {
              const expiringSoon = cert.days_until_expiry != null && cert.days_until_expiry <= 30 && cert.days_until_expiry >= 0;
              return (
                <Card key={cert.id} className={cn(cert.is_expired && "border-destructive/40", expiringSoon && "border-warning/40")}>
                  <CardContent className="flex flex-col gap-2.5 p-4">
                    <div className="flex items-start justify-between gap-2">
                      <span className="truncate font-mono text-sm font-medium text-foreground">{cert.subject_cn ?? "(no subject CN)"}</span>
                      {cert.is_expired ? (
                        <Badge variant="destructive" className="shrink-0 gap-1">
                          <AlertTriangle className="h-3 w-3" />
                          Expired
                        </Badge>
                      ) : expiringSoon ? (
                        <Badge className="shrink-0 gap-1 border-warning/40 bg-warning/10 text-warning">
                          <AlertTriangle className="h-3 w-3" />
                          {cert.days_until_expiry}d left
                        </Badge>
                      ) : null}
                    </div>

                    <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-xs">
                      <span className="text-muted-foreground">Issuer</span>
                      <span className="truncate text-foreground">{cert.issuer_cn ?? cert.issuer_org ?? "-"}</span>
                      <span className="text-muted-foreground">Valid from</span>
                      <span className="text-foreground">{formatDate(cert.not_before)}</span>
                      <span className="text-muted-foreground">Valid until</span>
                      <span className="text-foreground">{formatDate(cert.not_after)}</span>
                      <span className="text-muted-foreground">Signature</span>
                      <span className="truncate text-foreground">{cert.signature_algorithm ?? "-"}</span>
                      <span className="text-muted-foreground">Public key</span>
                      <span className="truncate text-foreground">{cert.public_key_algorithm ?? "-"}</span>
                      <span className="text-muted-foreground">TLS version</span>
                      <span className="text-foreground">{cert.tls_version ?? "-"}</span>
                    </div>

                    {cert.sans.length > 0 && (
                      <div>
                        <p className="mb-1 text-xs text-muted-foreground">SANs ({formatNumber(cert.sans.length)})</p>
                        <div className="flex flex-wrap gap-1">
                          {cert.sans.slice(0, 12).map((san) => (
                            <Badge key={san} variant="outline" className="font-mono text-[10px]">
                              {truncateMiddle(san, 28)}
                            </Badge>
                          ))}
                          {cert.sans.length > 12 && (
                            <Badge variant="outline" className="text-[10px]">
                              +{cert.sans.length - 12} more
                            </Badge>
                          )}
                        </div>
                      </div>
                    )}

                    <p className="truncate font-mono text-[10px] text-muted-foreground" title={cert.fingerprint_sha256}>
                      {cert.fingerprint_sha256}
                    </p>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}
      </QuerySection>
    </div>
  );
}
