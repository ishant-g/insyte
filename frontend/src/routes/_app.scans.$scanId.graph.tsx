import { useEffect, useMemo, useRef, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import { forceCenter, forceCollide, forceLink, forceManyBody, forceSimulation, type SimulationLinkDatum, type SimulationNodeDatum } from "d3-force";

import { scansApi } from "@/api/scans";
import type { GraphEdge, GraphNode } from "@/api/types";
import { PageHeader } from "@/components/page-header";
import { ErrorBlock, LoadingBlock } from "@/components/async-state";
import { ScanEmptyState } from "@/components/scan-empty-state";
import { AssetDetailSheet } from "@/components/asset-detail-sheet";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useTheme } from "@/lib/theme";
import { formatNumber, titleCase } from "@/lib/format";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/_app/scans/$scanId/graph")({
  component: GraphPage,
});

const MAX_NODES = 300;

const CONFIDENCE_OPTIONS = [
  { value: "0", label: "All confidence" },
  { value: "70", label: "70+ confidence" },
  { value: "85", label: "85+ confidence" },
];

/** Asset-type -> CSS variable holding its node color (see styles.css).
 * Resolved against the live theme so the graph re-colors with light/dark. */
const TYPE_CSS_VARS: Record<string, string> = {
  domain: "--graph-domain",
  subdomain: "--graph-subdomain",
  ipv4: "--graph-ipv4",
  ipv6: "--graph-ipv6",
  asn: "--graph-asn",
  certificate: "--graph-certificate",
  url: "--graph-url",
  api: "--graph-api",
  javascript: "--graph-javascript",
  technology: "--graph-technology",
  cloud_resource: "--graph-cloud",
  email: "--graph-email",
  organization: "--graph-org",
  person: "--graph-org",
};
const FALLBACK_CSS_VAR = "--graph-fallback";

function resolveGraphPalette(): Record<string, string> {
  const palette: Record<string, string> = {};
  if (typeof document === "undefined") return palette;
  const computed = getComputedStyle(document.documentElement);
  for (const [type, cssVar] of Object.entries(TYPE_CSS_VARS)) {
    palette[type] = computed.getPropertyValue(cssVar).trim() || "#8a8a9a";
  }
  palette.__fallback = computed.getPropertyValue(FALLBACK_CSS_VAR).trim() || "#8a8a9a";
  return palette;
}

interface SimNode extends SimulationNodeDatum, GraphNode {}
interface SimLink extends SimulationLinkDatum<SimNode> {
  relation: string;
  confidence: number;
}

/** Pan/zoom transform that fits every node's position inside a
 * `width`×`height` viewport, with padding. Falls back to the identity
 * transform for an empty graph or a not-yet-measured (zero-size) container. */
function fitTransform(nodes: SimNode[], width: number, height: number) {
  const identity = { x: 0, y: 0, k: 1 };
  const positioned = nodes.filter((n) => n.x != null && n.y != null);
  if (positioned.length === 0 || width <= 0 || height <= 0) return identity;

  const xs = positioned.map((n) => n.x as number);
  const ys = positioned.map((n) => n.y as number);
  const minX = Math.min(...xs);
  const maxX = Math.max(...xs);
  const minY = Math.min(...ys);
  const maxY = Math.max(...ys);

  const padding = 40;
  const spanX = Math.max(1, maxX - minX);
  const spanY = Math.max(1, maxY - minY);
  const k = Math.min(2, (width - padding * 2) / spanX, (height - padding * 2) / spanY);
  const scale = Math.max(0.05, k);

  const centerX = (minX + maxX) / 2;
  const centerY = (minY + maxY) / 2;
  return {
    x: width / 2 - centerX * scale,
    y: height / 2 - centerY * scale,
    k: scale,
  };
}

function GraphPage() {
  const { scanId } = Route.useParams();
  // Out-of-scope nodes (typically co-hosted junk from shared IPs) are hidden
  // by default: the graph should answer "what is mine", not "who shares my IP".
  const [showOutOfScope, setShowOutOfScope] = useState(false);
  const [minConfidence, setMinConfidence] = useState("0");
  const graph = useQuery({
    queryKey: ["graph", scanId, MAX_NODES, showOutOfScope, minConfidence],
    queryFn: () =>
      scansApi.graph(scanId, MAX_NODES, {
        in_scope: showOutOfScope ? undefined : true,
        min_confidence: minConfidence === "0" ? undefined : Number(minConfidence),
      }),
  });

  const filters = (
    <div className="flex flex-wrap items-center gap-4 text-xs">
      <div className="flex items-center gap-2">
        <Switch id="graph-out-of-scope" checked={showOutOfScope} onCheckedChange={setShowOutOfScope} />
        <Label htmlFor="graph-out-of-scope" className="text-xs font-medium text-foreground">
          Show out-of-scope
        </Label>
        <span className="text-muted-foreground">co-hosted and unrelated hosts stay hidden unless enabled</span>
      </div>
      <div className="flex items-center gap-2">
        <Label htmlFor="graph-confidence" className="text-xs font-medium text-foreground">
          Confidence
        </Label>
        <Select value={minConfidence} onValueChange={setMinConfidence}>
          <SelectTrigger id="graph-confidence" className="h-8 w-40 text-xs">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {CONFIDENCE_OPTIONS.map((o) => (
              <SelectItem key={o.value} value={o.value}>
                {o.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
    </div>
  );

  return (
    <div className="flex h-[calc(100vh-9rem)] flex-col gap-4">
      <PageHeader
        title="Asset graph"
        description="Relationships between discovered assets, laid out with a force-directed simulation. Scroll to zoom, drag to pan."
      />

      {filters}

      {graph.isLoading ? (
        <LoadingBlock rows={8} />
      ) : graph.isError ? (
        <ErrorBlock error={graph.error} onRetry={() => graph.refetch()} />
      ) : !graph.data || graph.data.nodes.length === 0 ? (
        <ScanEmptyState
          title="No graph data available"
          description="No asset relationships were recorded for this scan, so there is nothing to lay out yet."
        />
      ) : (
        <GraphCanvas nodes={graph.data.nodes} edges={graph.data.edges} scanId={scanId} />
      )}
    </div>
  );
}

function GraphCanvas({ nodes, edges, scanId }: { nodes: GraphNode[]; edges: GraphEdge[]; scanId: string }) {
  const containerRef = useRef<HTMLDivElement>(null);
  const { mode } = useTheme();
  // Theme-reactive palette: re-resolved whenever light/dark flips so node
  // colors always match the active theme's vibrant set.
  const palette = useMemo(() => resolveGraphPalette(), [mode]);
  const colorFor = (type: string): string => palette[type] ?? palette.__fallback ?? "#8a8a9a";
  const [size, setSize] = useState({ width: 800, height: 600 });
  // Bumped after each simulation run purely to force a re-render - the
  // node/link positions live in mutable refs so React never sees them
  // change on its own.
  const [, forceRerender] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [transform, setTransform] = useState({ x: 0, y: 0, k: 1 });
  const panState = useRef<{ dragging: boolean; startX: number; startY: number; origin: { x: number; y: number } } | null>(null);

  const truncated = nodes.length >= MAX_NODES;

  const simNodesRef = useRef<SimNode[]>([]);
  const simLinksRef = useRef<SimLink[]>([]);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const observer = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (entry) setSize({ width: entry.contentRect.width, height: entry.contentRect.height });
    });
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    const nodeIds = new Set(nodes.map((n) => n.id));
    const simNodes: SimNode[] = nodes.map((n) => ({ ...n }));
    const simLinks: SimLink[] = edges
      .filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target))
      .map((e) => ({ source: e.source, target: e.target, relation: e.relation, confidence: e.confidence }));

    simNodesRef.current = simNodes;
    simLinksRef.current = simLinks;

    const simulation = forceSimulation(simNodes)
      .force("charge", forceManyBody().strength(-90))
      .force("link", forceLink<SimNode, SimLink>(simLinks).id((d) => d.id).distance(60).strength(0.4))
      .force("center", forceCenter(size.width / 2, size.height / 2))
      .force("collide", forceCollide(14))
      .stop();

    const iterations = Math.min(300, Math.max(80, Math.floor(6000 / Math.max(1, simNodes.length))));
    for (let i = 0; i < iterations; i++) simulation.tick();

    forceRerender((t) => t + 1);
    // The force layout's natural extent is frequently much larger than the
    // panel (repulsion between ~90 nodes easily spans 1000+ px), so a
    // fixed scale=1 view would show a near-empty corner of the graph -
    // fit the computed bounding box into the panel instead of asking the
    // user to discover they need to zoom out first.
    setTransform(fitTransform(simNodes, size.width, size.height));
    return () => {
      simulation.stop();
    };
  }, [nodes, edges, size.width, size.height]);

  const selectedNode = useMemo(() => nodes.find((n) => n.id === selectedId) ?? null, [nodes, selectedId]);

  function clampScale(k: number) {
    return Math.min(4, Math.max(0.2, k));
  }

  function onWheel(e: React.WheelEvent<SVGSVGElement>) {
    e.preventDefault();
    const factor = e.deltaY > 0 ? 0.9 : 1.1;
    setTransform((prev) => ({ ...prev, k: clampScale(prev.k * factor) }));
  }

  function onPointerDown(e: React.PointerEvent<SVGSVGElement>) {
    panState.current = {
      dragging: true,
      startX: e.clientX,
      startY: e.clientY,
      origin: { x: transform.x, y: transform.y },
    };
    (e.target as Element).setPointerCapture(e.pointerId);
  }

  function onPointerMove(e: React.PointerEvent<SVGSVGElement>) {
    const state = panState.current;
    if (!state?.dragging) return;
    setTransform((prev) => ({
      ...prev,
      x: state.origin.x + (e.clientX - state.startX),
      y: state.origin.y + (e.clientY - state.startY),
    }));
  }

  function onPointerUp() {
    if (panState.current) panState.current.dragging = false;
  }

  const simNodes = simNodesRef.current;
  const simLinks = simLinksRef.current;
  const nodesById = useMemo(() => new Map(simNodes.map((n) => [n.id, n])), [simNodes]);
  const typeCounts = useMemo(() => {
    const map = new Map<string, number>();
    for (const n of nodes) map.set(n.asset_type, (map.get(n.asset_type) ?? 0) + 1);
    return Array.from(map.entries()).sort((a, b) => b[1] - a[1]);
  }, [nodes]);

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-2">
      <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
        <span>{formatNumber(nodes.length)} nodes · {formatNumber(edges.length)} edges rendered</span>
        {truncated && (
          <span className="text-warning">
            Capped at {MAX_NODES} highest-confidence matching nodes. Raise the confidence filter or enable
            out-of-scope to change what is included.
          </span>
        )}
      </div>

      <div className="flex flex-1 min-h-0 gap-3">
        <div ref={containerRef} className="relative min-h-0 flex-1 overflow-hidden rounded-xl border border-border/70 bg-card shadow-sm">
          <svg
            width="100%"
            height="100%"
            className="graph-canvas cursor-grab active:cursor-grabbing touch-none"
            onWheel={onWheel}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerLeave={onPointerUp}
          >
            <g transform={`translate(${transform.x}, ${transform.y}) scale(${transform.k})`}>
              <g stroke="var(--border)" strokeOpacity={0.6}>
                {simLinks.map((l, i) => {
                  const source = typeof l.source === "object" ? l.source : nodesById.get(l.source as unknown as string);
                  const target = typeof l.target === "object" ? l.target : nodesById.get(l.target as unknown as string);
                  if (!source || !target || source.x == null || target.x == null) return null;
                  return (
                    <line
                      key={i}
                      x1={source.x}
                      y1={source.y}
                      x2={target.x}
                      y2={target.y}
                      strokeWidth={Math.max(0.5, (l.confidence / 100) * 2)}
                    />
                  );
                })}
              </g>
              <g>
                {simNodes.map((n) => {
                  if (n.x == null || n.y == null) return null;
                  // n.confidence is 0-100 (matches the API), so this maps
                  // onto a 4-12px node radius rather than using the raw
                  // percentage as a pixel count directly.
                  const radius = n.is_target ? 10 : 4 + (n.confidence / 100) * 8;
                  return (
                    <g
                      key={n.id}
                      transform={`translate(${n.x}, ${n.y})`}
                      className="cursor-pointer"
                      onClick={() => setSelectedId(n.id)}
                      opacity={n.in_scope ? 1 : 0.4}
                    >
                      <circle
                        r={radius}
                        fill={colorFor(n.asset_type)}
                        stroke={n.is_target ? "var(--foreground)" : selectedId === n.id ? "var(--primary)" : "transparent"}
                        strokeWidth={n.is_target || selectedId === n.id ? 2 : 0}
                      />
                      {(n.is_target || radius > 7) && (
                        <text
                          x={radius + 4}
                          y={3}
                          fontSize={10}
                          fill="var(--foreground)"
                          className="pointer-events-none select-none"
                        >
                          {n.value.length > 24 ? `${n.value.slice(0, 24)}…` : n.value}
                        </text>
                      )}
                    </g>
                  );
                })}
              </g>
            </g>
          </svg>

          <div className="absolute bottom-2 right-2 flex gap-1">
            <button
              type="button"
              className="rounded-md border border-border bg-card px-2 py-1 text-xs text-foreground hover:bg-muted/50"
              onClick={() => setTransform(fitTransform(simNodesRef.current, size.width, size.height))}
            >
              Reset view
            </button>
          </div>
        </div>

        <div className="hidden w-48 shrink-0 flex-col gap-1 overflow-y-auto rounded-xl border border-border/70 bg-card p-3 shadow-sm lg:flex">
          <p className="mb-1 text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">Asset types</p>
          {typeCounts.map(([type, count]) => (
            <div key={type} className="flex items-center gap-2 rounded-md px-1.5 py-1 text-xs transition-colors hover:bg-muted/50">
              <span className={cn("h-2.5 w-2.5 shrink-0 rounded-full shadow-sm")} style={{ backgroundColor: colorFor(type) }} />
              <span className="truncate font-medium text-foreground">{titleCase(type)}</span>
              <span className="ml-auto tabular-nums text-muted-foreground">{count}</span>
            </div>
          ))}
        </div>
      </div>

      <AssetDetailSheet
        scanId={scanId}
        assetId={selectedNode?.id ?? null}
        onClose={() => setSelectedId(null)}
      />
    </div>
  );
}
