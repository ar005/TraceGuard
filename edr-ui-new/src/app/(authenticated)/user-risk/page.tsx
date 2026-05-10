"use client";

import { useState, useEffect } from "react";
import { api } from "@/lib/api-client";

interface IdentityRecord {
  id: string;
  canonical_uid: string;
  display_name: string;
  email: string;
  department: string;
  risk_score: number;
  risk_factors: string[];
  is_privileged: boolean;
  last_login_at: string | null;
  last_seen_src: string;
  updated_at: string;
}

function RiskBadge({ score }: { score: number }) {
  const color = score >= 70 ? "#ef4444" : score >= 40 ? "#f59e0b" : score >= 20 ? "#3b82f6" : "#6b7280";
  const label = score >= 70 ? "CRITICAL" : score >= 40 ? "HIGH" : score >= 20 ? "MEDIUM" : "LOW";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ width: 60, height: 6, background: "#374151", borderRadius: 3, overflow: "hidden" }}>
        <div style={{ width: `${score}%`, height: "100%", background: color }} />
      </div>
      <span style={{ fontSize: 12, fontWeight: 700, color }}>{score}</span>
      <span style={{ fontSize: 10, color, fontWeight: 600 }}>{label}</span>
    </div>
  );
}

export default function UserRiskPage() {
  const [identities, setIdentities] = useState<IdentityRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [showAll, setShowAll] = useState(false);

  useEffect(() => {
    setLoading(true);
    const endpoint = showAll ? "/api/v1/identity?limit=200" : "/api/v1/identity/top-risk?n=50";
    api.get<{ identities?: IdentityRecord[] }>(endpoint)
      .then(d => setIdentities(d?.identities ?? []))
      .catch(e => setError(e.message))
      .finally(() => setLoading(false));
  }, [api, showAll]);

  const toggle = (id: string) => setExpanded(prev => prev === id ? null : id);

  return (
    <div style={{ padding: 24, maxWidth: 1200 }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", marginBottom: 20 }}>
        <div>
          <h1 style={{ fontSize: 22, fontWeight: 700, marginBottom: 4 }}>User Risk</h1>
          <p style={{ color: "#6b7280", fontSize: 14 }}>
            Identity risk scores from cross-source correlation (impossible travel, burst login, privilege escalation)
          </p>
        </div>
        <button onClick={() => setShowAll(p => !p)} style={{
          padding: "6px 14px", borderRadius: 6, border: "1px solid #374151",
          background: "#1f2937", color: "#d1d5db", cursor: "pointer", fontSize: 13,
        }}>{showAll ? "Show Top 50" : "Show All"}</button>
      </div>

      {error && <div style={{ color: "#ef4444", marginBottom: 12 }}>{error}</div>}
      {loading && <div style={{ color: "#6b7280" }}>Loading…</div>}

      {!loading && (
        <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13 }}>
          <thead>
            <tr style={{ borderBottom: "1px solid #374151", color: "#9ca3af" }}>
              {["User", "Department", "Risk Score", "Privileged", "Last Login", "Last IP", ""].map(h => (
                <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {identities.map(id => (
              <>
                <tr key={id.id} onClick={() => toggle(id.id)} style={{
                  borderBottom: "1px solid #1f2937", cursor: "pointer",
                  background: expanded === id.id ? "#1f2937" : "transparent",
                }}>
                  <td style={{ padding: "8px 12px" }}>
                    <div style={{ fontWeight: 600, color: "#f3f4f6" }}>{id.display_name || id.canonical_uid}</div>
                    <div style={{ fontSize: 11, color: "#6b7280" }}>{id.email || id.canonical_uid}</div>
                  </td>
                  <td style={{ padding: "8px 12px", color: "#9ca3af" }}>{id.department || "—"}</td>
                  <td style={{ padding: "8px 12px" }}><RiskBadge score={id.risk_score} /></td>
                  <td style={{ padding: "8px 12px" }}>
                    {id.is_privileged
                      ? <span style={{ color: "#f59e0b", fontWeight: 600 }}>PRIVILEGED</span>
                      : <span style={{ color: "#374151" }}>—</span>}
                  </td>
                  <td style={{ padding: "8px 12px", color: "#9ca3af", fontSize: 12 }}>
                    {id.last_login_at ? new Date(id.last_login_at).toLocaleString() : "—"}
                  </td>
                  <td style={{ padding: "8px 12px", color: "#6b7280", fontFamily: "monospace", fontSize: 11 }}>
                    {id.last_seen_src || "—"}
                  </td>
                  <td style={{ padding: "8px 12px", color: "#6b7280" }}>{expanded === id.id ? "▲" : "▼"}</td>
                </tr>
                {expanded === id.id && (
                  <tr key={id.id + "-d"} style={{ background: "#111827" }}>
                    <td colSpan={7} style={{ padding: "12px 16px" }}>
                      <div style={{ display: "flex", gap: 24 }}>
                        <div>
                          <div style={{ color: "#6b7280", fontSize: 11, marginBottom: 6 }}>RISK FACTORS</div>
                          {(Array.isArray(id.risk_factors) ? id.risk_factors : []).length > 0
                            ? (Array.isArray(id.risk_factors) ? id.risk_factors : []).map((f: string) => (
                              <span key={f} style={{
                                display: "inline-block", margin: "2px 4px",
                                padding: "2px 8px", borderRadius: 4,
                                background: "#dc262622", color: "#ef4444",
                                fontSize: 11, fontWeight: 600,
                              }}>{f}</span>
                            ))
                            : <span style={{ color: "#6b7280", fontSize: 12 }}>No risk factors</span>}
                        </div>
                        <div>
                          <div style={{ color: "#6b7280", fontSize: 11, marginBottom: 6 }}>CANONICAL UID</div>
                          <code style={{ color: "#d1d5db", fontSize: 12 }}>{id.canonical_uid}</code>
                        </div>
                        <div>
                          <div style={{ color: "#6b7280", fontSize: 11, marginBottom: 6 }}>LAST UPDATED</div>
                          <span style={{ color: "#9ca3af", fontSize: 12 }}>{new Date(id.updated_at).toLocaleString()}</span>
                        </div>
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
            {identities.length === 0 && (
              <tr>
                <td colSpan={7} style={{ padding: 40, textAlign: "center", color: "#6b7280" }}>
                  No identity records yet — risk scores populate as XDR events arrive
                </td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </div>
  );
}
