import { createFileRoute, Link, Outlet } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Ban } from "lucide-react";

import { scansApi } from "@/api/scans";
import { ApiError } from "@/lib/api-client";
import { ScanDetailProvider, isTerminalStatus } from "@/lib/scan-context";
import { Button } from "@/components/ui/button";
import { ScanStatusBadge, ScanProgressBar } from "@/components/scan-status-badge";
import { ExposureBandBadge } from "@/components/severity-badge";
import { ReportDownloadButtons } from "@/components/report-download-buttons";
import { ErrorBlock, LoadingBlock } from "@/components/async-state";
import { PassiveModeNotice } from "@/components/passive-mode-notice";

export const Route = createFileRoute("/_app/scans/$scanId")({
  component: ScanDetailLayout,
});

function ScanDetailLayout() {
  const { scanId } = Route.useParams();
  const queryClient = useQueryClient();

  const scan = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => scansApi.get(scanId),
    refetchInterval: (query) => (isTerminalStatus(query.state.data?.status) ? false : 2000),
  });

  const cancel = useMutation({
    mutationFn: () => scansApi.cancel(scanId),
    onSuccess: () => {
      toast.success("Scan cancelled.");
      queryClient.invalidateQueries({ queryKey: ["scan", scanId] });
    },
    onError: (error) => toast.error(error instanceof ApiError ? error.message : "Failed to cancel scan."),
  });

  if (scan.isLoading) {
    return <LoadingBlock rows={4} />;
  }

  if (scan.isError || !scan.data) {
    return (
      <ErrorBlock
        error={scan.error ?? new Error("Scan not found.")}
        onRetry={() => scan.refetch()}
      />
    );
  }

  const data = scan.data;
  const canDownload = data.status === "completed" || data.status === "partial";
  const canCancel = data.status === "queued" || data.status === "running";
  const isRunning = data.status === "running";

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-border/70 pb-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Link to="/scans/$scanId" params={{ scanId }} className="truncate font-mono text-lg font-semibold text-foreground transition-colors hover:text-primary">
              {data.target_value}
            </Link>
            <ScanStatusBadge status={data.status} progress={data.progress} />
            {data.exposure_band && <ExposureBandBadge band={data.exposure_band} />}
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            {data.mode === "passive" ? "Passive Intelligence" : "Web Surface Collection"} · {data.target_type} · started{" "}
            {data.started_at ? new Date(data.started_at).toLocaleString() : "not yet"}
          </p>
          {isRunning && (
            <div className="mt-3 max-w-md">
              <ScanProgressBar progress={data.progress} />
            </div>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          {canCancel && (
            <Button variant="outline" size="sm" onClick={() => cancel.mutate()} disabled={cancel.isPending}>
              <Ban className="h-3.5 w-3.5" />
              Cancel scan
            </Button>
          )}
          {canDownload && <ReportDownloadButtons scanId={scanId} />}
        </div>
      </div>

      <ScanDetailProvider value={scan}>
        {data.mode === "passive" && <PassiveModeNotice />}
        <Outlet />
      </ScanDetailProvider>
    </div>
  );
}
