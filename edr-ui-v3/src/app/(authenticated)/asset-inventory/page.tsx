"use client";

import { useState, useEffect, useCallback } from "react";
import { api } from "@/lib/api-client";

interface AssetRecord {
  id: string;
  asset_type: string;
  hostname: string;
  ip_addresses: string[];
  os: string;
  os_version: string;
  cloud_provider: string;
  cloud_region: string;
  cloud_account: string;
  cloud_resource_id: string;
  agent_id: string;
  tags: string[];
  risk_score: number;
  criticality: number;
  owner_uid: string;
  first_seen_at: string;
  last_seen_at: string;
  source_id: string;
}

const ASSET_TYPE_COLORS: Record<string, string> = {
  endpoint:  "#3b82f6",
  vm:        "#8b5cf6",
  container: "#06b6d4",
  network:   "#f59e0b",
  cloud:     "#10b981",
};

const CRITICALITY_LABELS: Record<number, { label: string; color: string }> = {
  1: { label: "LOW",      color: "#6b7280" },
  2: { label: "MEDIUM",   color: "#3b82f6" },
  3: { label: "HIGH",     color: "#f59e0b" },
  4: { label: "CRITICAL", color: "#ef4444" },
};

export default function AssetInventoryPage() {
  const [assets, setAssets] = useState<AssetRecord[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [offset, setOffset] = useState(0);
  const [typeFilter, setTypeFilter] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const limit = 100;

  const load = useCallback(async (off: number) => {
    setLoading(true);
    setError("");
    try {
      const params = new URLSearchParams({ limit: String(limit), offset: String(off) });
      if (typeFilter) params.set("type", typeFilter);
      const data = await api.get<{ assets?: AssetRecord[]; total?: number }>(`/api/v1/assets?${params}`);
      if (off === 0) setAssets(data.assets ?? []);
      else setAssets(prev => [...prev, ...(data.assets ?? [])]);
      setTotal(data.total ?? 0);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load assets");
    } finally {
      setLoading(false);
    }
  }, [api, typeFilter]);

  useEffect(() => { setOffset(0); load(0); }, [load]);

  const toggle = (id: string) => setExpanded(prev => prev === id ? null : id);

  return (
    <div style={{ padding: 24, maxWidth: 1400 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, marginBottom: 4 }}>Asset Inventory</h1>
          <p style={{ color: "#6b7280", fontSize: 14 }}>
            {total} assets — endpoints, VMs, cloud resources, network devices
          </p>
        </div>
      </div>

      {/* Type filter */}
      <div style={{ display: "flex", gap: 10, marginBottom: 16 }}>
        {["", "endpoint", "vm", "container", "network", "cloud"].map(t => (
          <button key={t} onClick={() => setTypeFilter(t)} style={{
            padding: "4px 12px", borderRadius: 6, border: "1px solid",
            borderColor: typeFilter === t ? "#3b82f6" : "#374151",
            background: typeFilter === t ? "#1d4ed822" : "transparent",
            color: typeFilter === t ? "#3b82f6" : "#9ca3af",
            cursor: "pointer", fontSize: 13,
          }}>{t || "All"}</button>
        ))}
      </div>

      {error && <div style={{ color: "#ef4444", marginBottom: 12 }}>{error}</div>}

      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
        <thead>
          <tr style={{ borderBottom: "1px solid #374151", color: "#9ca3af" }}>
            {["Hostname / ID", "Type", "OS", "IPs", "Criticality", "Owner", "Last Seen", ""].map(h => (
              <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontWeight: 600 }}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {assets.map(a => {
            const crit = CRITICALITY_LABELS[a.criticality] ?? CRITICALITY_LABELS[1];
            const typeColor = ASSET_TYPE_COLORS[a.asset_type] ?? "#6b7280";
            return (
              <>
                <tr key={a.id} onClick={() => toggle(a.id)} style={{
                  borderBottom: "1px solid #1f2937", cursor: "pointer",
                  background: expanded === a.id ? "#1f2937" : "transparent",
                }}>
                  <td style={{ padding: "8px 12px" }}>
                    <div style={{ fontWeight: 600, color: "#f3f4f6" }}>{a.hostname || a.cloud_resource_id || a.id}</div>
                    {a.cloud_resource_id && a.hostname && (
                      <div style={{ fontSize: 11, color: "#6b7280" }}>{a.cloud_resource_id}</div>
                    )}
                  </td>
                  <td style={{ padding: "8px 12px" }}>
                    <span style={{
                      padding: "2px 8px", borderRadius: 4, fontSize: 11, fontWeight: 600,
                      background: typeColor + "22", color: typeColor,
                    }}>{a.asset_type}</span>
                  </td>
                  <td style={{ padding: "8px 12px", color: "#9ca3af" }}>
                    {a.os ? `${a.os} ${a.os_version}`.trim() : a.cloud_provider ? `${a.cloud_provider}/${a.cloud_region}` : "—"}
                  </td>
                  <td style={{ padding: "8px 12px", color: "#6b7280", fontFamily: "monospace", fontSize: 11 }}>
                    {(a.ip_addresses ?? []).slice(0, 2).join(", ") || "—"}
                  </td>
                  <td style={{ padding: "8px 12px" }}>
                    <span style={{ color: crit.color, fontWeight: 700, fontSize: 11 }}>{crit.label}</span>
                  </td>
                  <td style={{ padding: "8px 12px", color: "#9ca3af" }}>{a.owner_uid || "—"}</td>
                  <td style={{ padding: "8px 12px", color: "#6b7280", fontSize: 12 }}>
                    {new Date(a.last_seen_at).toLocaleString()}
                  </td>
                  <td style={{ padding: "8px 12px", color: "#6b7280" }}>{expanded === a.id ? "▲" : "▼"}</td>
                </tr>
                {expanded === a.id && (
                  <tr key={a.id + "-d"} style={{ background: "#111827" }}>
                    <td colSpan={8} style={{ padding: 16 }}>
                      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(220px, 1fr))", gap: 16, fontSize: 12 }}>
                        <div>
                          <div style={{ color: "#6b7280", marginBottom: 4 }}>CLOUD DETAILS</div>
                          <div style={{ color: "#d1d5db" }}>Provider: {a.cloud_provider || "—"}</div>
                          <div style={{ color: "#d1d5db" }}>Region: {a.cloud_region || "—"}</div>
                          <div style={{ color: "#d1d5db" }}>Account: {a.cloud_account || "—"}</div>
                        </div>
                        <div>
                          <div style={{ color: "#6b7280", marginBottom: 4 }}>NETWORK</div>
                          {(a.ip_addresses ?? []).map(ip => (
                            <div key={ip} style={{ color: "#d1d5db", fontFamily: "monospace" }}>{ip}</div>
                          ))}
                        </div>
                        <div>
                          <div style={{ color: "#6b7280", marginBottom: 4 }}>TAGS</div>
                          {(a.tags ?? []).map(tag => (
                            <span key={tag} style={{
                              display: "inline-block", margin: "2px 3px",
                              padding: "1px 6px", borderRadius: 3, background: "#1f2937",
                              color: "#9ca3af", fontSize: 11,
                            }}>{tag}</span>
                          ))}
                          {(a.tags ?? []).length === 0 && <span style={{ color: "#6b7280" }}>—</span>}
                        </div>
                        <div>
                          <div style={{ color: "#6b7280", marginBottom: 4 }}>TRACKING</div>
                          <div style={{ color: "#d1d5db" }}>First seen: {new Date(a.first_seen_at).toLocaleString()}</div>
                          <div style={{ color: "#d1d5db" }}>Agent ID: {a.agent_id || "—"}</div>
                          <div style={{ color: "#d1d5db" }}>Source: {a.source_id || "—"}</div>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </>
            );
          })}
          {!loading && assets.length === 0 && (
            <tr>
              <td colSpan={8} style={{ padding: 40, textAlign: "center", color: "#6b7280" }}>
                No assets found — assets are auto-discovered from endpoint agents and XDR cloud connectors
              </td>
            </tr>
          )}
        </tbody>
      </table>

      {assets.length > 0 && assets.length % limit === 0 && (
        <div style={{ marginTop: 16, textAlign: "center" }}>
          <button onClick={() => { const next = offset + limit; setOffset(next); load(next); }}
            disabled={loading}
            style={{ padding: "8px 20px", borderRadius: 6, border: "1px solid #374151", background: "#1f2937", color: "#d1d5db", cursor: "pointer" }}>
            {loading ? "Loading…" : "Load more"}
          </button>
        </div>
      )}
    </div>
  );
}
