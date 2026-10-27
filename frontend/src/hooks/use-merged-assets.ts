import { useQueries } from "@tanstack/react-query";

import { scansApi } from "@/api/scans";
import type { AssetRead } from "@/api/types";

const FETCH_LIMIT = 200;

/**
 * The assets endpoint filters by a single `asset_type` value, but several
 * pages (Domains & Subdomains, IPs / ASN) need several asset types shown
 * together as one list. This fans out one request per type in parallel and
 * merges the results client-side, since there is no server-side "type in
 * [...]" filter to rely on.
 *
 * Each branch is capped at FETCH_LIMIT - if a branch's true total exceeds
 * that, `truncated` reports it (rather than silently dropping rows) so the
 * page can show a note instead of pretending the list is complete.
 */
export function useMergedAssets(
  scanId: string,
  types: string[],
  opts: { search?: string; inScope?: boolean; minConfidence?: number; countOnly?: boolean } = {},
) {
  const limit = opts.countOnly ? 1 : FETCH_LIMIT;
  const results = useQueries({
    queries: types.map((type) => ({
      queryKey: ["assets", scanId, type, opts.search, opts.inScope, opts.minConfidence, limit],
      queryFn: () =>
        scansApi.assets(scanId, {
          asset_type: type,
          search: opts.search || undefined,
          in_scope: opts.inScope,
          min_confidence: opts.minConfidence,
          limit,
          offset: 0,
        }),
      enabled: !!scanId,
    })),
  });

  const isLoading = results.some((r) => r.isLoading);
  const isError = results.some((r) => r.isError);
  const error = results.find((r) => r.error)?.error;

  const items: AssetRead[] = [];
  let total = 0;
  let truncated = false;
  for (const r of results) {
    if (r.data) {
      items.push(...r.data.items);
      total += r.data.total;
      if (r.data.total > r.data.items.length) truncated = true;
    }
  }
  items.sort((a, b) => b.confidence - a.confidence);

  return {
    isLoading,
    isError,
    error,
    items,
    total,
    truncated,
    refetch: () => results.forEach((r) => r.refetch()),
  };
}
