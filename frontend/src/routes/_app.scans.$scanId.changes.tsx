import { useMemo, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { Minus, Plus, RefreshCw } from "lucide-react";

import { scansApi } from "@/api/scans";
import { useScanDetail } from "@/lib/scan-context";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { PageHeader } from "@/components/page-header";
import { ErrorBlock, LoadingBlock, EmptyBlock } from "@/components/async-state";
import { formatDateTime, titleCase } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { ChangeEntry } from "@/api/types";

export const Route = createFileRoute("/_app/scans/$scanId/changes")({
  component: ChangesPage,
});

function ChangeRow({ entry, tone }: { entry: ChangeEntry; tone: "added" | "removed" | "changed" }) {
  const icon = tone === "added" ? <Plus className="h-3.5 w-3.5 text-success" /> : tone === "removed" ? <Minus className="h-3.5 w-3.5 text-destructive" /> : <RefreshCw className="h-3.5 w-3.5 text-warning" />;
  return (
    <li className="flex items-start gap-2 border-b border-border px-3 py-2 text-sm last:border-b-0">
      {icon}
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <span className="break-all font-mono text-foreground">{entry.value}</span>
          <Badge variant="outline" className="text-[10px]">
            {titleCase(entry.asset_type)}
          </Badge>
        </div>
        {entry.detail && Object.keys(entry.detail).length > 0 && (
          <pre className="mt-1 max-w-full overflow-x-auto text-[11px] text-muted-foreground">
            {JSON.stringify(entry.detail)}
          </pre>
        )}
      </div>
    </li>
  );
}

function ChangesPage() {
  const { scanId } = Route.useParams();
  const scanQuery = useScanDetail();
  const scan = scanQuery.data;
  const [compareTo, setCompareTo] = useState<string>("");

  const otherScans = useQuery({
    queryKey: ["scans", "for-target", scan?.target_value],
    queryFn: () => scansApi.list({ target: scan!.target_value, limit: 50 }),
    enabled: !!scan,
  });

  const candidates = useMemo(
    () => (otherScans.data?.items ?? []).filter((s) => s.id !== scanId),
    [otherScans.data, scanId],
  );

  const diff = useQuery({
    queryKey: ["changes", scanId, compareTo],
    queryFn: () => scansApi.changes(scanId, compareTo),
    enabled: !!compareTo,
  });

  return (
    <div className="flex flex-col gap-4">
      <PageHeader title="Changes" description="Compare this scan's discovered assets against another scan of the same target." />

      {otherScans.isLoading ? (
        <LoadingBlock rows={2} />
      ) : candidates.length === 0 ? (
        <EmptyBlock
          title="No other scans of this target"
          description="Run another scan against the same target to compare results here."
        />
      ) : (
        <>
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Compare against</span>
            <Select value={compareTo} onValueChange={setCompareTo}>
              <SelectTrigger className="w-72">
                <SelectValue placeholder="Choose a scan…" />
              </SelectTrigger>
              <SelectContent>
                {candidates.map((s) => (
                  <SelectItem key={s.id} value={s.id}>
                    {formatDateTime(s.created_at)} · {titleCase(s.status)}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {!compareTo ? (
            <EmptyBlock title="Pick a scan to compare" description="Select another scan of this target above to see what changed." />
          ) : diff.isLoading ? (
            <LoadingBlock rows={4} />
          ) : diff.isError ? (
            <ErrorBlock error={diff.error} onRetry={() => diff.refetch()} />
          ) : diff.data ? (
            <div className="flex flex-col gap-4">
              <div className="flex gap-3">
                <div className="rounded-lg border border-success/30 bg-success/5 px-3 py-2 text-sm">
                  <span className="font-mono font-semibold text-success">{diff.data.summary.added}</span>{" "}
                  <span className="text-muted-foreground">added</span>
                </div>
                <div className="rounded-lg border border-destructive/30 bg-destructive/5 px-3 py-2 text-sm">
                  <span className="font-mono font-semibold text-destructive">{diff.data.summary.removed}</span>{" "}
                  <span className="text-muted-foreground">removed</span>
                </div>
                <div className="rounded-lg border border-warning/30 bg-warning/5 px-3 py-2 text-sm">
                  <span className="font-mono font-semibold text-warning">{diff.data.summary.changed}</span>{" "}
                  <span className="text-muted-foreground">changed</span>
                </div>
              </div>

              <div className="grid gap-4 lg:grid-cols-3">
                <ChangeGroup title="Added" entries={diff.data.added} tone="added" />
                <ChangeGroup title="Removed" entries={diff.data.removed} tone="removed" />
                <ChangeGroup title="Changed" entries={diff.data.changed} tone="changed" />
              </div>
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}

function ChangeGroup({ title, entries, tone }: { title: string; entries: ChangeEntry[]; tone: "added" | "removed" | "changed" }) {
  return (
    <div className={cn("rounded-lg border border-border")}>
      <div className="border-b border-border px-3 py-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
        {title} ({entries.length})
      </div>
      {entries.length === 0 ? (
        <p className="px-3 py-6 text-center text-xs text-muted-foreground">None</p>
      ) : (
        <ul className="max-h-96 overflow-y-auto">
          {entries.map((e, i) => (
            <ChangeRow key={i} entry={e} tone={tone} />
          ))}
        </ul>
      )}
    </div>
  );
}
