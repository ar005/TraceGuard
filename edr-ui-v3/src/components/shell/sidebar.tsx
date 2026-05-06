"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { useAuth } from "@/lib/auth";
import { useNotifications } from "@/hooks/use-notifications";
import type { Notification } from "@/hooks/use-notifications";
import {
  LayoutDashboard,
  MonitorCheck,
  ShieldAlert,
  Layers,
  Activity,
  Search,
  Terminal,
  SlidersHorizontal,
  Globe,
  Usb,
  FlaskConical,
  FileX2,
  Bug,
  BarChart2,
  Network,
  Cloud,
  Users,
  UserCheck,
  Server,
  PlaySquare,
  ShieldCheck,
  Share2,
  FolderOpen,
  Container,
  LogOut,
  Bell,
  X,
  AlertTriangle,
  WifiOff,
  Mail,
  ScanSearch,
  GitBranch,
} from "lucide-react";

interface NavItem {
  href: string;
  icon: React.ElementType;
  label: string;
  matchPrefix?: string;
}

interface NavGroup {
  label: string;
  items: NavItem[];
}

const NAV: NavGroup[] = [
  {
    label: "Core",
    items: [
      { href: "/dashboard",  icon: LayoutDashboard, label: "Dashboard" },
      { href: "/agents",     icon: MonitorCheck,    label: "Agents",    matchPrefix: "/agents" },
      { href: "/alerts",     icon: ShieldAlert,     label: "Alerts" },
      { href: "/incidents",  icon: Layers,          label: "Incidents" },
      { href: "/cases",      icon: FolderOpen,      label: "Cases",     matchPrefix: "/cases" },
    ],
  },
  {
    label: "Investigate",
    items: [
      { href: "/events",        icon: Activity,   label: "Events" },
      { href: "/chains",        icon: GitBranch,  label: "Chains" },
      { href: "/commands",      icon: Terminal,  label: "Commands" },
      { href: "/browser",       icon: Globe,     label: "Browser" },
      { href: "/usb",           icon: Usb,       label: "USB Devices" },
      { href: "/email-threats", icon: Mail,      label: "Email Threats" },
      { href: "/search",        icon: Search,    label: "Hunt" },
    ],
  },
  {
    label: "Detect",
    items: [
      { href: "/rules",           icon: FlaskConical,   label: "Rules" },
      { href: "/yara",            icon: ScanSearch,     label: "YARA Rules" },
      { href: "/suppressions",    icon: FileX2,         label: "Suppressions" },
      { href: "/iocs",            icon: Bug,            label: "IOCs" },
      { href: "/vulnerabilities", icon: ShieldAlert,    label: "Vulns" },
    ],
  },
  {
    label: "XDR",
    items: [
      { href: "/sources",          icon: Network,       label: "Sources",         matchPrefix: "/sources" },
      { href: "/network-events",   icon: Globe,         label: "Network Events" },
      { href: "/cloud-events",     icon: Cloud,         label: "Cloud Events" },
      { href: "/identity-events",  icon: Users,         label: "Identity Events" },
      { href: "/user-risk",        icon: UserCheck,     label: "User Risk" },
      { href: "/asset-inventory",  icon: Server,        label: "Asset Inventory" },
      { href: "/containers",       icon: Container,     label: "Containers",      matchPrefix: "/containers" },
    ],
  },
  {
    label: "Operate",
    items: [
      { href: "/live-response", icon: Terminal,          label: "Live Response" },
      { href: "/playbooks",         icon: PlaySquare,   label: "Playbooks",         matchPrefix: "/playbooks" },
      { href: "/response-actions",  icon: ShieldCheck,  label: "Response Actions",  matchPrefix: "/response-actions" },
      { href: "/export",        icon: Share2,            label: "Export / SIEM" },
      { href: "/metrics",       icon: BarChart2,         label: "Metrics" },
      { href: "/settings",      icon: SlidersHorizontal, label: "Settings" },
    ],
  },
];

const STORAGE_KEY = "tg-sidebar-expanded";

const SEV_COLORS = ["var(--fg-3)", "oklch(0.65 0.15 200)", "oklch(0.70 0.16 80)", "oklch(0.65 0.18 35)", "var(--sev-critical)"];

function ShieldLogo({ size = 20 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 22 22" fill="none" aria-hidden="true">
      <path
        d="M11 2L3 6v5c0 4.4 3.4 8.5 8 9.5C16.6 19.5 20 15.4 20 11V6L11 2z"
        fill="none"
        stroke="var(--primary)"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path
        d="M8 11l2 2 4-4"
        stroke="var(--primary)"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/* ── Notification Dropdown ───────────────────────────────────────── */

function NotificationItem({ n }: { n: Notification }) {
  const Icon = n.type === "agent_offline" ? WifiOff : AlertTriangle;
  const color = n.type === "agent_offline"
    ? "var(--fg-3)"
    : SEV_COLORS[n.severity ?? 0] ?? "var(--fg-3)";

  return (
    <div
      className="flex items-start gap-2 px-3 py-2 transition-fast hover:bg-[var(--surface-1)]"
      style={{ opacity: n.read ? 0.6 : 1 }}
    >
      <Icon size={13} style={{ color, flexShrink: 0, marginTop: 2 }} />
      <div className="min-w-0 flex-1">
        <p className="truncate" style={{ fontSize: "var(--text-xs)", color: "var(--fg)", fontWeight: n.read ? 400 : 600 }}>
          {n.title}
        </p>
        {n.subtitle && (
          <p className="truncate" style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)" }}>
            {n.subtitle}
          </p>
        )}
      </div>
      {!n.read && (
        <span
          className="shrink-0 rounded-full"
          style={{ width: 6, height: 6, background: "var(--primary)", marginTop: 4 }}
        />
      )}
    </div>
  );
}

function BellButton({ expanded, unread, onClick }: { expanded: boolean; unread: number; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      title={expanded ? undefined : `Notifications${unread > 0 ? ` (${unread})` : ""}`}
      aria-label="Notifications"
      className="relative flex items-center transition-fast rounded-md"
      style={{
        height: "34px",
        margin: "0 auto",
        width: expanded ? "calc(100% - 0px)" : "40px",
        padding: expanded ? "0 10px" : "0",
        gap: expanded ? "10px" : "0",
        justifyContent: expanded ? "flex-start" : "center",
        background: "none",
        border: "none",
        cursor: "pointer",
        color: "var(--fg-3)",
        borderRadius: "6px",
        whiteSpace: "nowrap",
        overflow: "visible",
      }}
    >
      <span className="relative" style={{ flexShrink: 0 }}>
        <Bell size={15} />
        {unread > 0 && (
          <span
            className="absolute flex items-center justify-center rounded-full font-display font-bold"
            style={{
              top: -5, right: -5,
              width: 14, height: 14,
              background: "var(--sev-critical)",
              color: "#fff",
              fontSize: 9,
              fontFamily: "var(--font-archivo)",
              lineHeight: 1,
            }}
          >
            {unread > 9 ? "9+" : unread}
          </span>
        )}
      </span>
      {expanded && (
        <span style={{ fontSize: "var(--text-sm)" }}>
          Notifications{unread > 0 ? ` (${unread})` : ""}
        </span>
      )}
    </button>
  );
}

/* ── Sidebar ─────────────────────────────────────────────────────── */

export function Sidebar() {
  const pathname = usePathname();
  const { logout, user } = useAuth();
  const [expanded, setExpanded] = useState(false);
  const [bellOpen, setBellOpen] = useState(false);
  const bellRef = useRef<HTMLDivElement>(null);

  const { notifications, unread, markAllRead, clear } = useNotifications();

  useEffect(() => {
    try { setExpanded(localStorage.getItem(STORAGE_KEY) === "1"); } catch {/* ignore */}
  }, []);

  // Close bell dropdown on outside click
  useEffect(() => {
    if (!bellOpen) return;
    const handler = (e: MouseEvent) => {
      if (bellRef.current && !bellRef.current.contains(e.target as Node)) {
        setBellOpen(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [bellOpen]);

  const toggle = () => {
    setExpanded(v => {
      const next = !v;
      try { localStorage.setItem(STORAGE_KEY, next ? "1" : "0"); } catch {/* ignore */}
      return next;
    });
  };

  const isActive = (item: NavItem) => {
    if (item.matchPrefix) return pathname.startsWith(item.matchPrefix);
    return pathname === item.href || pathname.startsWith(item.href + "/");
  };

  const w = expanded ? "220px" : "56px";

  return (
    <nav
      className="flex flex-col h-screen shrink-0"
      style={{
        width: w,
        minWidth: w,
        background: "var(--rail-bg)",
        borderRight: "1px solid var(--rail-border)",
        transition: "width 0.18s ease, min-width 0.18s ease",
        overflow: "hidden",
      }}
      aria-label="Main navigation"
    >
      {/* Logo — click to toggle */}
      <button
        onClick={toggle}
        aria-label={expanded ? "Collapse sidebar" : "Expand sidebar"}
        className="flex items-center shrink-0 w-full transition-fast hover:bg-[var(--surface-1)]"
        style={{
          height: "52px",
          borderBottom: "1px solid var(--rail-border)",
          background: "none",
          cursor: "pointer",
          padding: expanded ? "0 14px" : "0",
          justifyContent: expanded ? "flex-start" : "center",
          gap: "10px",
          overflow: "hidden",
        }}
      >
        <ShieldLogo size={20} />
        {expanded && (
          <span
            style={{
              fontFamily: "var(--font-archivo)",
              fontWeight: 700,
              fontSize: "var(--text-sm)",
              color: "var(--fg)",
              whiteSpace: "nowrap",
              letterSpacing: "-0.01em",
            }}
          >
            TraceGuard
          </span>
        )}
      </button>

      {/* Nav groups */}
      <div
        className="flex-1 flex flex-col gap-4 overflow-y-auto overflow-x-hidden"
        style={{ padding: "12px 0" }}
      >
        {NAV.map((group) => (
          <div key={group.label}>
            {expanded && (
              <span
                className="section-label block truncate"
                style={{ padding: "0 12px", marginBottom: "4px" }}
              >
                {group.label}
              </span>
            )}
            <ul className="flex flex-col gap-0.5" role="list">
              {group.items.map((item) => {
                const active = isActive(item);
                const Icon = item.icon;
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      title={expanded ? undefined : item.label}
                      aria-label={item.label}
                      aria-current={active ? "page" : undefined}
                      className="flex items-center transition-fast rounded-md"
                      style={{
                        height: "34px",
                        margin: "0 6px",
                        padding: expanded ? "0 10px" : "0",
                        gap: expanded ? "10px" : "0",
                        justifyContent: expanded ? "flex-start" : "center",
                        color: active ? "var(--rail-active-fg)" : "var(--rail-fg)",
                        background: active ? "var(--rail-active-bg)" : "transparent",
                        textDecoration: "none",
                        whiteSpace: "nowrap",
                        overflow: "hidden",
                      }}
                    >
                      <Icon size={15} strokeWidth={active ? 2.2 : 1.8} style={{ flexShrink: 0 }} />
                      {expanded && (
                        <span style={{ fontSize: "var(--text-sm)", fontWeight: active ? 600 : 400 }}>
                          {item.label}
                        </span>
                      )}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>

      {/* Bottom — notifications + user + logout */}
      <div
        style={{
          borderTop: "1px solid var(--rail-border)",
          padding: expanded ? "10px 8px" : "10px 0",
          display: "flex",
          flexDirection: "column",
          gap: "4px",
          position: "relative",
          overflow: "visible",
        }}
      >
        {/* Bell button */}
        <div ref={bellRef} style={{ position: "relative" }}>
          <BellButton
            expanded={expanded}
            unread={unread}
            onClick={() => {
              setBellOpen(v => !v);
              if (!bellOpen) markAllRead();
            }}
          />

          {/* Notification dropdown — pops out to the right of sidebar */}
          {bellOpen && (
            <div
              className="absolute z-50 rounded-xl border shadow-2xl"
              style={{
                left: expanded ? "0" : "52px",
                bottom: 0,
                width: "300px",
                background: "var(--surface-0)",
                borderColor: "var(--border)",
                maxHeight: "380px",
                display: "flex",
                flexDirection: "column",
                overflow: "hidden",
              }}
            >
              {/* Header */}
              <div
                className="flex items-center justify-between px-3 py-2 shrink-0"
                style={{ borderBottom: "1px solid var(--border)" }}
              >
                <span style={{ fontSize: "var(--text-xs)", fontWeight: 700, color: "var(--fg)", fontFamily: "var(--font-archivo)" }}>
                  Notifications
                </span>
                <div className="flex items-center gap-2">
                  {notifications.length > 0 && (
                    <button
                      onClick={clear}
                      className="transition-fast hover:text-[var(--fg)]"
                      style={{ fontSize: "var(--text-xs)", color: "var(--fg-3)" }}
                    >
                      Clear
                    </button>
                  )}
                  <button
                    onClick={() => setBellOpen(false)}
                    className="transition-fast hover:text-[var(--fg)]"
                    style={{ color: "var(--fg-3)" }}
                  >
                    <X size={13} />
                  </button>
                </div>
              </div>

              {/* List */}
              <div className="overflow-y-auto flex-1">
                {notifications.length === 0 ? (
                  <div
                    className="flex flex-col items-center justify-center gap-2 py-10"
                    style={{ color: "var(--fg-4)" }}
                  >
                    <Bell size={22} />
                    <p style={{ fontSize: "var(--text-xs)" }}>No notifications</p>
                  </div>
                ) : (
                  notifications.map((n) => <NotificationItem key={n.id} n={n} />)
                )}
              </div>
            </div>
          )}
        </div>

        {expanded && user && (
          <div
            style={{
              padding: "0 6px",
              marginBottom: "2px",
              overflow: "hidden",
            }}
          >
            <p
              className="truncate"
              style={{ fontSize: "var(--text-xs)", color: "var(--fg-2)", fontWeight: 600 }}
            >
              {user.username ?? user.email ?? "User"}
            </p>
            <p
              className="truncate"
              style={{ fontSize: "var(--text-xs)", color: "var(--fg-4)", textTransform: "capitalize" }}
            >
              {user.role ?? "analyst"}
            </p>
          </div>
        )}

        <button
          onClick={() => void logout()}
          title={expanded ? undefined : "Log out"}
          aria-label="Log out"
          className="flex items-center transition-fast rounded-md"
          style={{
            height: "34px",
            margin: "0 auto",
            width: expanded ? "calc(100% - 0px)" : "40px",
            padding: expanded ? "0 10px" : "0",
            gap: expanded ? "10px" : "0",
            justifyContent: expanded ? "flex-start" : "center",
            background: "none",
            border: "none",
            cursor: "pointer",
            color: "var(--fg-3)",
            borderRadius: "6px",
            whiteSpace: "nowrap",
            overflow: "hidden",
          }}
        >
          <LogOut size={15} style={{ flexShrink: 0 }} />
          {expanded && (
            <span style={{ fontSize: "var(--text-sm)" }}>Log out</span>
          )}
        </button>
      </div>
    </nav>
  );
}
