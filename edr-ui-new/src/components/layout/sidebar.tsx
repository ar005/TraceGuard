"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/utils";
import {
  Activity,
  AlertTriangle,
  ArrowUpFromLine,
  BarChart3,
  BookOpen,
  Box,
  Bug,
  CalendarClock,
  Cloud,
  Crosshair,
  Database,
  FileText,
  FolderOpen,
  FolderCog,
  Ghost,
  GitBranch,
  GitFork,
  Globe,
  LayoutDashboard,
  LayoutGrid,
  Layers,
  Mail,
  Network,
  PlaySquare,
  ScanSearch,
  Search,
  Server,
  Settings,
  Share2,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Siren,
  TrendingUp,
  Terminal,
  Usb,
  UserCheck,
  Users,
  Wifi,
  ClipboardCheck,
  Rss,
} from "lucide-react";

interface NavItem {
  label: string;
  href: string;
  icon: React.ComponentType<{ size?: number; className?: string }>;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const NAV_SECTIONS: NavSection[] = [
  {
    title: "Core",
    items: [
      { label: "Dashboard", href: "/", icon: LayoutDashboard },
      { label: "Alerts", href: "/alerts", icon: AlertTriangle },
      { label: "Incidents", href: "/incidents", icon: Layers },
      { label: "Cases", href: "/cases", icon: FolderOpen },
      { label: "Agents", href: "/agents", icon: Server },
    ],
  },
  {
    title: "Investigate",
    items: [
      { label: "Events", href: "/events", icon: Activity },
      { label: "Commands", href: "/commands", icon: Terminal },
      { label: "Browser", href: "/browser", icon: Globe },
      { label: "USB Devices", href: "/usb", icon: Usb },
      { label: "Email Threats", href: "/email-threats", icon: Mail },
      { label: "Hunt", href: "/hunt", icon: Crosshair },
      { label: "Search", href: "/search", icon: Search },
    ],
  },
  {
    title: "Detect",
    items: [
      { label: "Rules", href: "/rules", icon: Shield },
      { label: "YARA Rules", href: "/yara", icon: ScanSearch },
      { label: "Suppressions", href: "/suppressions", icon: ShieldOff },
      { label: "IOCs", href: "/iocs", icon: Database },
      { label: "IOC Feeds", href: "/ioc-feeds", icon: Rss },
      { label: "DNS Intelligence", href: "/dns", icon: Wifi },
      { label: "Vulnerabilities", href: "/vulnerabilities", icon: Bug },
      { label: "MITRE Heatmap", href: "/mitre-heatmap", icon: LayoutGrid },
    ],
  },
  {
    title: "XDR",
    items: [
      { label: "Sources", href: "/sources", icon: Network },
      { label: "Network Events", href: "/network-events", icon: Globe },
      { label: "Cloud Events", href: "/cloud-events", icon: Cloud },
      { label: "Identity Events", href: "/identity-events", icon: Users },
      { label: "User Risk", href: "/user-risk", icon: UserCheck },
      { label: "Host Risk", href: "/host-risk", icon: TrendingUp },
      { label: "Threat Score", href: "/threat-score", icon: ShieldAlert },
      { label: "UEBA Timeline", href: "/ueba", icon: GitBranch },
      { label: "Lateral Graph", href: "/lateral-graph", icon: GitFork },
      { label: "Attack Surface", href: "/attack-surface", icon: ScanSearch },
      { label: "Asset Inventory", href: "/asset-inventory", icon: Server },
      { label: "Containers", href: "/containers", icon: Box },
      { label: "Data Exfiltration", href: "/data-exfil", icon: ArrowUpFromLine },
    ],
  },
  {
    title: "Operate",
    items: [
      { label: "Live Response", href: "/live-response", icon: Terminal },
      { label: "Playbooks", href: "/playbooks", icon: PlaySquare },
      { label: "Playbook Runs", href: "/playbooks/runs", icon: Activity },
      { label: "Auto-Remediation", href: "/auto-remediation", icon: Siren },
      { label: "Compliance", href: "/compliance", icon: ClipboardCheck },
      { label: "Canary Tokens", href: "/canary", icon: Ghost },
      { label: "Scheduled Tasks", href: "/scheduled-tasks", icon: CalendarClock },
      { label: "Auto-Case Policies", href: "/autocase", icon: FolderCog },
      { label: "Response Actions", href: "/response-actions", icon: ShieldCheck },
      { label: "Export / SIEM", href: "/export", icon: Share2 },
      { label: "Reports", href: "/reports", icon: FileText },
      { label: "Metrics", href: "/metrics", icon: BarChart3 },
      { label: "Settings", href: "/settings", icon: Settings },
    ],
  },
];

export function Sidebar() {
  const [collapsed, setCollapsed] = useState(() => {
    if (typeof window !== "undefined") {
      // Default collapsed on phones (< 640px)
      if (window.innerWidth < 640) return true;
      return localStorage.getItem("sidebar-collapsed") === "true";
    }
    return false;
  });
  const pathname = usePathname();

  useEffect(() => {
    localStorage.setItem("sidebar-collapsed", String(collapsed));
  }, [collapsed]);

  // Auto-collapse on phone when navigating
  useEffect(() => {
    if (typeof window !== "undefined" && window.innerWidth < 640) {
      setCollapsed(true);
    }
  }, [pathname]);

  const isActive = (href: string) => {
    if (href === "/") return pathname === "/";
    return pathname.startsWith(href);
  };

  return (
    <aside
      className={cn(
        "relative flex flex-col h-full border-r border-[hsl(var(--border))] bg-[hsl(var(--card))] shrink-0",
        "transition-[width] duration-200 ease-in-out",
        collapsed ? "w-[56px]" : "w-[240px]"
      )}
    >
      {/* Brand — icon doubles as collapse toggle */}
      <div className="flex items-center h-12 px-3 border-b border-[hsl(var(--border))] shrink-0">
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="shrink-0 p-1 -ml-1 rounded hover:bg-[hsl(var(--accent))] transition-colors"
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          <BookOpen size={20} className="text-[hsl(var(--primary))]" />
        </button>
        <span
          className={cn(
            "ml-2 text-sm font-semibold tracking-wide font-heading text-[hsl(var(--primary))] whitespace-nowrap",
            "transition-[opacity,transform] duration-200",
            collapsed ? "opacity-0 scale-95 w-0 ml-0" : "opacity-100 scale-100"
          )}
        >
          TRACEGUARD
        </span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto overflow-x-hidden py-2 px-1.5">
        {NAV_SECTIONS.map((section, sIdx) => (
          <div key={section.title} className="mb-2">
            {/* Section title — visible only when expanded */}
            <div
              className={cn(
                "px-2 mb-1 text-[10px] font-medium uppercase tracking-widest text-[hsl(var(--muted-foreground))]",
                "transition-opacity duration-200 overflow-hidden whitespace-nowrap",
                collapsed ? "opacity-0 h-0 mb-0" : "opacity-100 h-auto"
              )}
            >
              {section.title}
            </div>

            {/* Collapsed separator between sections */}
            {collapsed && sIdx > 0 && (
              <div className="mx-2 my-1 border-t border-[hsl(var(--border)/.5)]" />
            )}

            {section.items.map((item) => {
              const Icon = item.icon;
              const active = isActive(item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  title={item.label}
                  className={cn(
                    "group relative flex items-center rounded-md text-[13px] font-medium transition-colors",
                    collapsed ? "justify-center px-0 py-2 mx-0.5" : "gap-2.5 px-2 py-1.5",
                    active
                      ? "bg-[hsl(var(--primary)/.1)] text-[hsl(var(--primary))]"
                      : "text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--accent))] hover:text-[hsl(var(--foreground))]"
                  )}
                >
                  {/* Active indicator bar */}
                  {active && (
                    <div className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-4 rounded-r-full bg-[hsl(var(--primary))]" />
                  )}

                  <Icon size={16} className="shrink-0" />

                  <span
                    className={cn(
                      "truncate whitespace-nowrap transition-[opacity,width] duration-200",
                      collapsed ? "opacity-0 w-0 overflow-hidden" : "opacity-100 w-auto"
                    )}
                  >
                    {item.label}
                  </span>

                  {/* Tooltip on hover when collapsed */}
                  {collapsed && (
                    <div className="absolute left-full ml-2 px-2 py-1 rounded bg-[hsl(var(--popover))] border border-[hsl(var(--border))] text-xs text-[hsl(var(--foreground))] whitespace-nowrap opacity-0 pointer-events-none group-hover:opacity-100 transition-opacity z-50 shadow-md">
                      {item.label}
                    </div>
                  )}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>

    </aside>
  );
}
