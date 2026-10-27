import { Link, useLocation, useParams } from "@tanstack/react-router";
import { useQuery } from "@tanstack/react-query";
import {
  Cable,
  FileCode2,
  FileText,
  Fingerprint,
  Globe2,
  History,
  IdCard,
  LayoutDashboard,
  ListTree,
  Network,
  Radar,
  ScanSearch,
  Settings,
  ShieldAlert,
  ShieldQuestion,
  Target,
  Waypoints,
  Workflow,
} from "lucide-react";

import { scansApi } from "@/api/scans";
import { cn } from "@/lib/utils";
import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
} from "@/components/ui/sidebar";
import { Separator } from "@/components/ui/separator";
import { ThemeControls, UserMenu } from "@/components/header-controls";

function Wordmark() {
  return (
    <div className="group flex items-center gap-2.5 px-2 py-1.5">
      <span className="relative flex h-8 w-8 shrink-0 items-center justify-center overflow-hidden rounded-xl bg-gradient-to-br from-primary via-[#7c5cf0] to-chart-2 shadow-[0_4px_14px_-4px_var(--primary)] transition-transform duration-200 group-hover:scale-105">
        <svg viewBox="0 0 24 24" className="h-4.5 w-4.5" aria-hidden="true" fill="none" stroke="white" strokeWidth="2.2" strokeLinecap="round">
          <circle cx="10.5" cy="10.5" r="5.5" />
          <line x1="14.8" y1="14.8" x2="20" y2="20" />
        </svg>
      </span>
      <span className="flex flex-col leading-none">
        <span className="bg-gradient-to-r from-primary to-chart-2 bg-clip-text font-mono text-sm font-bold tracking-[0.22em] text-transparent">
          INSYTE
        </span>
        <span className="mt-1 text-[10px] font-medium tracking-wide text-muted-foreground">Exposure Intelligence</span>
      </span>
    </div>
  );
}

const topNav = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/targets", label: "Targets", icon: Target },
  { to: "/scans", label: "Scans", icon: ScanSearch },
];

/** Nav items only ever populated by modules that crawl beyond a single GET
 * per resource (linked pages, their JS/CSS) - see the mode_support on
 * `modules/web/url_collection.py`, `api_discovery.py` and
 * `javascript.py`. Hidden for a Passive-mode scan so the sidebar never
 * promises a page that will only ever say "No results". */
const WEB_SURFACE_ONLY_PATHS = new Set(["urls", "apis", "javascript"]);

function scanNav(scanId: string, mode: string | undefined) {
  const attackSurfaceAll = [
    { navId: "domains", to: `/scans/${scanId}/domains`, label: "Domains & Subdomains", icon: Globe2 },
    { navId: "network", to: `/scans/${scanId}/network`, label: "IPs / ASN", icon: Network },
    { navId: "urls", to: `/scans/${scanId}/urls`, label: "URLs", icon: Waypoints },
    { navId: "apis", to: `/scans/${scanId}/apis`, label: "APIs", icon: Cable },
    { navId: "javascript", to: `/scans/${scanId}/javascript`, label: "JavaScript", icon: FileCode2 },
    { navId: "certificates", to: `/scans/${scanId}/certificates`, label: "Certificates", icon: Fingerprint },
    { navId: "technologies", to: `/scans/${scanId}/technologies`, label: "Technologies", icon: ListTree },
  ];
  const isPassive = mode === "passive";
  return {
    attackSurface: (isPassive
      ? attackSurfaceAll.filter((item) => !WEB_SURFACE_ONLY_PATHS.has(item.navId))
      : attackSurfaceAll
    ).map(({ navId: _navId, ...item }) => item),
    intelligence: [
      { to: `/scans/${scanId}/identity`, label: "Identity", icon: IdCard },
      { to: `/scans/${scanId}/documents`, label: "Documents", icon: FileText },
      { to: `/scans/${scanId}/historical`, label: "Historical", icon: History },
      { to: `/scans/${scanId}/exposure`, label: "Indexed Exposure", icon: ShieldQuestion },
      { to: `/scans/${scanId}/findings`, label: "Findings", icon: ShieldAlert },
      { to: `/scans/${scanId}/changes`, label: "Changes", icon: Workflow },
    ],
    graph: [{ to: `/scans/${scanId}/graph`, label: "Asset Graph", icon: Radar }],
  };
}

function NavLink({ to, label, icon: Icon }: { to: string; label: string; icon: React.ComponentType<{ className?: string }> }) {
  const location = useLocation();
  const isActive = to === "/" ? location.pathname === "/" : location.pathname.startsWith(to);
  return (
    <SidebarMenuItem>
      <SidebarMenuButton asChild isActive={isActive} className="rounded-lg transition-all duration-200">
        <Link to={to}>
          <Icon className={cn("h-4 w-4 shrink-0 transition-transform duration-200", isActive && "scale-110")} />
          <span className="truncate">{label}</span>
        </Link>
      </SidebarMenuButton>
    </SidebarMenuItem>
  );
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const params = useParams({ strict: false }) as { scanId?: string };
  const scanId = params.scanId;
  const location = useLocation();
  const locationKey = location.pathname;
  // Same ["scan", scanId] query key the scan detail route uses (see
  // lib/scan-context.tsx) - React Query dedupes this against that fetch
  // rather than issuing a second request.
  const scan = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => scansApi.get(scanId as string),
    enabled: Boolean(scanId),
    staleTime: 5000,
  });
  const groups = scanId ? scanNav(scanId, scan.data?.mode) : null;

  return (
    <SidebarProvider>
      <Sidebar>
        <SidebarHeader>
          <Link to="/">
            <Wordmark />
          </Link>
        </SidebarHeader>
        <SidebarContent>
          <SidebarGroup>
            <SidebarGroupContent>
              <SidebarMenu>
                {topNav.map((item) => (
                  <NavLink key={item.to} {...item} />
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>

          {groups && (
            <>
              <Separator className="mx-2 w-auto" />
              <SidebarGroup>
                <SidebarGroupLabel>Attack Surface</SidebarGroupLabel>
                <SidebarGroupContent>
                  <SidebarMenu>
                    {groups.attackSurface.map((item) => (
                      <NavLink key={item.to} {...item} />
                    ))}
                  </SidebarMenu>
                </SidebarGroupContent>
              </SidebarGroup>
              <SidebarGroup>
                <SidebarGroupLabel>Intelligence</SidebarGroupLabel>
                <SidebarGroupContent>
                  <SidebarMenu>
                    {groups.intelligence.map((item) => (
                      <NavLink key={item.to} {...item} />
                    ))}
                  </SidebarMenu>
                </SidebarGroupContent>
              </SidebarGroup>
              <SidebarGroup>
                <SidebarGroupContent>
                  <SidebarMenu>
                    {groups.graph.map((item) => (
                      <NavLink key={item.to} {...item} />
                    ))}
                  </SidebarMenu>
                </SidebarGroupContent>
              </SidebarGroup>
            </>
          )}
        </SidebarContent>
        <div className="mt-auto p-2">
          <Separator className="mb-2" />
          <SidebarMenu>
            <NavLink to="/settings" label="Settings" icon={Settings} />
          </SidebarMenu>
          <p className="mt-2 px-2 text-[10px] font-medium tracking-wide text-muted-foreground/60 transition-colors hover:text-muted-foreground">
            Crafted by @r0t-ig
          </p>
        </div>
      </Sidebar>
      <SidebarInset>
        <header className={cn("sticky top-0 z-10 flex h-13 items-center gap-2 border-b border-border/70 bg-background/80 px-4 py-2 backdrop-blur-xl")}>
          <SidebarTrigger className="rounded-lg transition-colors hover:bg-accent" />
          <Separator orientation="vertical" className="h-4" />
          <span className="hidden text-xs font-medium tracking-wide text-muted-foreground sm:inline">
            Passive Exposure Intelligence
          </span>
          <div className="ml-auto flex items-center gap-1">
            <ThemeControls />
            <Separator orientation="vertical" className="h-4" />
            <UserMenu />
          </div>
        </header>
        <div className="flex-1 p-4 md:p-6 lg:p-8">
          <div key={locationKey} className="insyte-page-enter mx-auto flex max-w-7xl flex-col">
            {children}
          </div>
        </div>
      </SidebarInset>
    </SidebarProvider>
  );
}
