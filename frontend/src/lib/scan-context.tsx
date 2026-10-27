import { createContext, useContext } from "react";
import type { UseQueryResult } from "@tanstack/react-query";

import type { ScanDetailRead } from "@/api/types";

export type ScanQuery = UseQueryResult<ScanDetailRead, unknown>;

const ScanDetailContext = createContext<ScanQuery | null>(null);

export const ScanDetailProvider = ScanDetailContext.Provider;

/** Sub-pages under /scans/$scanId/* read the already-fetched scan via this
 * hook instead of re-querying scansApi.get themselves. */
export function useScanDetail(): ScanQuery {
  const ctx = useContext(ScanDetailContext);
  if (!ctx) throw new Error("useScanDetail must be used within a scan detail route");
  return ctx;
}

export function isTerminalStatus(status: string | undefined): boolean {
  return status === "completed" || status === "failed" || status === "cancelled" || status === "partial";
}
