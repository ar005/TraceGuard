"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
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
  LogOut,
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
      { href: "/agents",     icon: MonitorCheck,    label: "Agents",   matchPrefix: "/agents" },
      { href: "/alerts",     icon: ShieldAlert,     label: "Alerts" },
      { href: "/incidents",  icon: Layers,          label: "Incidents" },
    ],
  },
  {
    label: "Investigate",
    items: [
      { href: "/events",   icon: Activity, label: "Events" },
      { href: "/commands", icon: Terminal,  label: "Commands" },
      { href: "/browser",  icon: Globe,    label: "Browser" },
      { href: "/usb",      icon: Usb,      label: "USB Devices" },
      { href: "/search",   icon: Search,   label: "Hunt" },
    ],
  },
  {
    label: "Detect",
    items: [
      { href: "/rules",           icon: FlaskConical,   label: "Rules" },
      { href: "/suppressions",    icon: FileX2,         label: "Suppressions" },
      { href: "/iocs",            icon: Bug,            label: "IOCs" },
      { href: "/vulnerabilities", icon: ShieldAlert,    label: "Vulns" },
    ],
  },
  {
    label: "Operate",
    items: [
      { href: "/live-response", icon: Terminal,          label: "Live Response" },
      { href: "/metrics",       icon: BarChart2,         label: "Metrics" },
      { href: "/settings",      icon: SlidersHorizontal, label: "Settings" },
    ],
  },
];

const STORAGE_KEY = "tg-sidebar-expanded";

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

export function Sidebar() {
  const pathname = usePathname();
  const { logout, user } = useAuth();
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    try { setExpanded(localStorage.getItem(STORAGE_KEY) === "1"); } catch {/* ignore */}
  }, []);

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

      {/* Bottom — user + logout */}
      <div
        style={{
          borderTop: "1px solid var(--rail-border)",
          padding: expanded ? "10px 8px" : "10px 0",
          display: "flex",
          flexDirection: "column",
          gap: "4px",
        }}
      >
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
