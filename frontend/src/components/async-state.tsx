import { AlertTriangle, Inbox, LoaderCircle } from "lucide-react";

import { Button } from "@/components/ui/button";
import { ApiError } from "@/lib/api-client";
import { cn } from "@/lib/utils";

export function LoadingBlock({ rows = 6 }: { rows?: number }) {
  return (
    <div className="flex flex-col gap-2.5" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => (
        <div
          key={i}
          className="insyte-skeleton h-11 w-full rounded-xl"
          style={{ animationDelay: `${i * 90}ms`, opacity: 1 - i * 0.08 }}
        />
      ))}
    </div>
  );
}

export function InlineSpinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 text-sm text-muted-foreground">
      <LoaderCircle className="insyte-loader h-4 w-4 text-primary" />
      {label}
    </div>
  );
}

export function ErrorBlock({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const message = error instanceof ApiError ? error.message : error instanceof Error ? error.message : "Request failed.";
  const requestId = error instanceof ApiError ? error.requestId : undefined;
  return (
    <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-destructive/25 bg-destructive/[0.05] px-6 py-12 text-center shadow-sm">
      <span className="flex h-11 w-11 items-center justify-center rounded-full border border-destructive/30 bg-destructive/10">
        <AlertTriangle className="h-5 w-5 text-destructive" />
      </span>
      <div>
        <p className="text-sm font-semibold text-foreground">Couldn't load this data</p>
        <p className="mt-1 max-w-sm text-sm text-muted-foreground">{message}</p>
        {requestId && <p className="mt-1 font-mono text-xs text-muted-foreground">request id: {requestId}</p>}
      </div>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry} className="mt-1">
          Try again
        </Button>
      )}
    </div>
  );
}

export function EmptyBlock({
  title,
  description,
  icon: Icon = Inbox,
  action,
  className,
}: {
  title: string;
  description?: React.ReactNode;
  icon?: React.ComponentType<{ className?: string }>;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center gap-2 rounded-xl border border-dashed bg-card px-6 py-12 text-center shadow-sm",
        className,
      )}
    >
      <span className="flex h-11 w-11 items-center justify-center rounded-full border border-border bg-muted/60">
        <Icon className="h-5 w-5 text-muted-foreground" />
      </span>
      <p className="text-sm font-semibold text-foreground">{title}</p>
      {description && <p className="max-w-sm text-sm text-muted-foreground">{description}</p>}
      {action && <div className="mt-3 flex flex-wrap items-center justify-center gap-2">{action}</div>}
    </div>
  );
}

/** Uniform loading / error / empty / content switch for a TanStack Query
 * result rendered as a list-like section.
 *
 * Pass `emptyState` to render a richer empty view (e.g. ScanEmptyState with
 * module-aware explanations) instead of the plain EmptyBlock. */
export function QuerySection<T>({
  isLoading,
  isError,
  error,
  onRetry,
  data,
  isEmpty,
  emptyTitle,
  emptyDescription,
  emptyState,
  children,
}: {
  isLoading: boolean;
  isError: boolean;
  error?: unknown;
  onRetry?: () => void;
  data: T | undefined;
  isEmpty: (data: T) => boolean;
  emptyTitle: string;
  emptyDescription?: string;
  emptyState?: React.ReactNode;
  children: (data: T) => React.ReactNode;
}) {
  if (isLoading) return <LoadingBlock />;
  if (isError) return <ErrorBlock error={error} onRetry={onRetry} />;
  if (data === undefined || isEmpty(data)) {
    if (emptyState) return <>{emptyState}</>;
    return <EmptyBlock title={emptyTitle} description={emptyDescription} />;
  }
  return <>{children(data)}</>;
}
