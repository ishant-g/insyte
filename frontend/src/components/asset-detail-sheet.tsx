import { useQuery } from "@tanstack/react-query";

import { scansApi } from "@/api/scans";
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from "@/components/ui/sheet";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { ErrorBlock, LoadingBlock } from "@/components/async-state";
import { ConfidenceBadge } from "@/components/severity-badge";
import { formatDate, titleCase } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { RelationshipRead } from "@/api/types";

function RelationshipList({ title, items }: { title: string; items: RelationshipRead[] }) {
  if (items.length === 0) return null;
  return (
    <div>
      <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">{title}</p>
      <ul className="flex flex-col gap-1">
        {items.map((r) => (
          <li key={r.id} className="flex items-center justify-between gap-2 rounded-md border border-border px-2 py-1 text-xs">
            <span className="text-foreground">{titleCase(r.relation)}</span>
            <ConfidenceBadge value={r.confidence} />
          </li>
        ))}
      </ul>
    </div>
  );
}

export function AssetDetailSheet({
  scanId,
  assetId,
  onClose,
}: {
  scanId: string;
  assetId: string | null;
  onClose: () => void;
}) {
  const asset = useQuery({
    queryKey: ["asset", scanId, assetId],
    queryFn: () => scansApi.asset(scanId, assetId!),
    enabled: !!assetId,
  });

  return (
    <Sheet open={!!assetId} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-full overflow-y-auto sm:max-w-md">
        {asset.isLoading ? (
          <div className="mt-6">
            <LoadingBlock rows={5} />
          </div>
        ) : asset.isError ? (
          <div className="mt-6">
            <ErrorBlock error={asset.error} onRetry={() => asset.refetch()} />
          </div>
        ) : asset.data ? (
          <>
            <SheetHeader>
              <div className="flex flex-wrap items-center gap-1.5">
                <Badge variant="outline">{titleCase(asset.data.asset_type)}</Badge>
                {asset.data.is_target && <Badge>Target</Badge>}
                <span className={cn("text-xs", asset.data.in_scope ? "text-foreground" : "text-muted-foreground")}>
                  {asset.data.in_scope ? "In scope" : "Out of scope"}
                </span>
              </div>
              <SheetTitle className="break-all font-mono text-sm">{asset.data.value}</SheetTitle>
              {asset.data.label && <SheetDescription>{asset.data.label}</SheetDescription>}
            </SheetHeader>

            <div className="mt-4 flex flex-col gap-4 text-sm">
              <div className="grid grid-cols-2 gap-2 text-xs">
                <span className="text-muted-foreground">Confidence</span>
                <ConfidenceBadge value={asset.data.confidence} />
                <span className="text-muted-foreground">Status</span>
                <span className="text-foreground">{asset.data.status}</span>
                <span className="text-muted-foreground">Sources</span>
                <span className="text-foreground">{asset.data.sources.join(", ") || "-"}</span>
                <span className="text-muted-foreground">Observations</span>
                <span className="text-foreground">{asset.data.observation_count}</span>
                <span className="text-muted-foreground">First seen</span>
                <span className="text-foreground">{formatDate(asset.data.first_seen)}</span>
                <span className="text-muted-foreground">Last seen</span>
                <span className="text-foreground">{formatDate(asset.data.last_seen)}</span>
              </div>

              {Object.keys(asset.data.attributes ?? {}).length > 0 && (
                <div>
                  <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Attributes</p>
                  <pre className="max-h-48 overflow-auto rounded-md border border-border bg-muted/30 p-2.5 text-[11px] text-muted-foreground">
                    {JSON.stringify(asset.data.attributes, null, 2)}
                  </pre>
                </div>
              )}

              <Separator />

              <RelationshipList title={`Outgoing (${asset.data.outgoing.length})`} items={asset.data.outgoing} />
              <RelationshipList title={`Incoming (${asset.data.incoming.length})`} items={asset.data.incoming} />

              {Object.keys(asset.data.evidence ?? {}).length > 0 && (
                <div>
                  <p className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Evidence</p>
                  <pre className="max-h-48 overflow-auto rounded-md border border-border bg-muted/30 p-2.5 text-[11px] text-muted-foreground">
                    {JSON.stringify(asset.data.evidence, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </>
        ) : null}
      </SheetContent>
    </Sheet>
  );
}
