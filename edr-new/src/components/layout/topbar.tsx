"use client";

import { useRouter } from "next/navigation";
import { useTheme } from "next-themes";
import { useAuth } from "@/lib/auth";
import {
  ChevronDown,
  LogOut,
  Moon,
  Search,
  Sun,
  User,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";

export function Topbar() {
  const { theme, setTheme } = useTheme();
  const { user, logout } = useAuth();
  const router = useRouter();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  // Close dropdown on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDropdownOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClick);
    return () => document.removeEventListener("mousedown", handleClick);
  }, []);

  return (
    <header
      className="flex items-center h-12 px-4 border-b shrink-0"
      style={{
        background: "var(--topbar-bg)",
        borderColor: "var(--topbar-border)",
      }}
    >
      {/* Search */}
      <button
        onClick={() => router.push("/search")}
        className="flex items-center gap-2 px-3 py-1.5 rounded text-xs border transition-colors hover:bg-[var(--surface-2)]"
        style={{
          borderColor: "var(--border)",
          color: "var(--muted)",
        }}
      >
        <Search size={13} />
        <span>Search events, hosts, IOCs...</span>
        <kbd
          className="ml-4 hidden sm:inline-block px-1.5 py-0.5 rounded text-[10px] font-mono border"
          style={{
            borderColor: "var(--border)",
            color: "var(--muted-fg)",
          }}
        >
          /
        </kbd>
      </button>

      <div className="flex-1" />

      {/* Theme toggle */}
      <button
        onClick={() => setTheme(theme === "dark" ? "light" : "dark")}
        className="p-1.5 rounded transition-colors hover:bg-[var(--surface-2)]"
        style={{ color: "var(--muted)" }}
        aria-label="Toggle theme"
      >
        {theme === "dark" ? <Sun size={15} /> : <Moon size={15} />}
      </button>

      {/* User dropdown */}
      <div ref={dropdownRef} className="relative ml-2">
        <button
          onClick={() => setDropdownOpen(!dropdownOpen)}
          className="flex items-center gap-1.5 px-2 py-1 rounded text-xs font-medium transition-colors hover:bg-[var(--surface-2)]"
          style={{ color: "var(--fg)" }}
        >
          <User size={14} style={{ color: "var(--muted)" }} />
          <span className="hidden sm:inline">{user?.username ?? "User"}</span>
          <ChevronDown size={12} style={{ color: "var(--muted)" }} />
        </button>

        {dropdownOpen && (
          <div
            className="absolute right-0 top-full mt-1 w-44 rounded border py-1 shadow-lg z-50 animate-fade-in"
            style={{
              background: "var(--surface-1)",
              borderColor: "var(--border)",
            }}
          >
            <div
              className="px-3 py-1.5 text-[11px] border-b"
              style={{
                color: "var(--muted)",
                borderColor: "var(--border-subtle)",
              }}
            >
              {user?.email || user?.username || "—"}
            </div>
            <button
              onClick={() => {
                setDropdownOpen(false);
                logout();
              }}
              className="flex items-center gap-2 w-full px-3 py-1.5 text-xs text-left transition-colors hover:bg-[var(--surface-2)]"
              style={{ color: "var(--fg)" }}
            >
              <LogOut size={13} />
              Sign out
            </button>
          </div>
        )}
      </div>
    </header>
  );
}
