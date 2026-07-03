"use client";

import { useCallback, useEffect, useState } from "react";
import { useAuth } from "@/lib/auth";
import { api } from "@/lib/api-client";
import {
  AlertTriangle,
  Check,
  ChevronDown,
  ChevronUp,
  Copy,
  KeyRound,
  Loader2,
  Plus,
  Shield,
  Trash2,
  ToggleLeft,
  ToggleRight,
} from "lucide-react";
import { cn } from "@/lib/utils";

// ─── Types ────────────────────────────────────────────────────────────────────

interface SSOConfig {
  id: string;
  tenant_id: string;
  provider_name: string;
  provider_type: "saml" | "oidc";
  enabled: boolean;
  auto_provision: boolean;
  default_role: string;
  domains: string[];
  saml_sp_cert_pem?: string;
  oidc_issuer_url?: string;
  oidc_client_id?: string;
  created_at: string;
  updated_at: string;
}

interface CreateBody {
  provider_name: string;
  provider_type: "saml" | "oidc";
  domains: string[];
  enabled: boolean;
  auto_provision: boolean;
  default_role: string;
  // SAML
  saml_idp_metadata_xml: string;
  saml_attribute_email: string;
  saml_attribute_name: string;
  saml_attribute_role: string;
  // OIDC
  oidc_issuer_url: string;
  oidc_client_id: string;
  oidc_client_secret: string;
  oidc_claim_email: string;
  oidc_claim_name: string;
  oidc_claim_role: string;
}

const EMPTY_FORM: CreateBody = {
  provider_name: "",
  provider_type: "saml",
  domains: [],
  enabled: true,
  auto_provision: true,
  default_role: "analyst",
  saml_idp_metadata_xml: "",
  saml_attribute_email: "email",
  saml_attribute_name: "name",
  saml_attribute_role: "",
  oidc_issuer_url: "",
  oidc_client_id: "",
  oidc_client_secret: "",
  oidc_claim_email: "email",
  oidc_claim_name: "preferred_username",
  oidc_claim_role: "",
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function Badge({ children, variant = "default" }: { children: React.ReactNode; variant?: "default" | "success" | "muted" }) {
  const colors: Record<string, string> = {
    default: "oklch(0.5 0.15 250 / 0.15)",
    success: "oklch(0.5 0.15 145 / 0.15)",
    muted: "oklch(0.5 0 0 / 0.12)",
  };
  const text: Record<string, string> = {
    default: "var(--primary)",
    success: "oklch(0.55 0.15 145)",
    muted: "var(--muted)",
  };
  return (
    <span className="px-1.5 py-0.5 rounded text-[11px] font-medium"
      style={{ background: colors[variant], color: text[variant] }}>
      {children}
    </span>
  );
}

function Field({ label, children, hint }: { label: string; children: React.ReactNode; hint?: string }) {
  return (
    <div className="space-y-1">
      <label className="block text-[11px] font-medium uppercase tracking-wider" style={{ color: "var(--muted)" }}>
        {label}
      </label>
      {children}
      {hint && <p className="text-[11px]" style={{ color: "var(--muted)" }}>{hint}</p>}
    </div>
  );
}

function Input({ ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={cn(
        "w-full px-3 py-2 rounded border text-sm outline-none transition-colors focus-ring",
        props.className
      )}
      style={{ background: "var(--surface-1)", borderColor: "var(--border)", color: "var(--fg)", ...props.style }}
    />
  );
}

function Textarea({ ...props }: React.TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...props}
      className={cn("w-full px-3 py-2 rounded border text-sm outline-none transition-colors focus-ring font-mono resize-y", props.className)}
      style={{ background: "var(--surface-1)", borderColor: "var(--border)", color: "var(--fg)", ...props.style }}
    />
  );
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      className="inline-flex items-center gap-1 px-2 py-1 rounded text-xs border transition-colors hover:bg-[var(--surface-1)]"
      style={{ borderColor: "var(--border)", color: "var(--muted)" }}
    >
      {copied ? <Check size={12} /> : <Copy size={12} />}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function SSOSettingsPage() {
  const { user } = useAuth();
  const [configs, setConfigs] = useState<SSOConfig[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState("");
  const [createResult, setCreateResult] = useState<{ saml_sp_cert_pem?: string; saml_metadata_url?: string; oidc_redirect_uri?: string } | null>(null);
  const [form, setForm] = useState<CreateBody>(EMPTY_FORM);
  const [domainsInput, setDomainsInput] = useState("");

  const isAdmin = user?.role === "admin";

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const data = await api.get<SSOConfig[]>("/api/v1/admin/sso/configs");
      setConfigs(data ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load SSO configurations");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (!isAdmin) {
    return (
      <div className="p-8 text-center" style={{ color: "var(--muted)" }}>
        <Shield size={32} className="mx-auto mb-3 opacity-40" />
        <p className="text-sm">Admin access required to manage SSO configurations.</p>
      </div>
    );
  }

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setCreateError("");
    setCreating(true);
    try {
      const domains = domainsInput.split(/[\s,]+/).map(d => d.trim().toLowerCase()).filter(Boolean);
      const body = { ...form, domains };
      const res = await api.post<{ id: string; saml_sp_cert_pem?: string; saml_metadata_url?: string; oidc_redirect_uri?: string }>(
        "/api/v1/admin/sso/configs", body
      );
      setCreateResult(res);
      await load();
    } catch (e) {
      setCreateError(e instanceof Error ? e.message : "Failed to create SSO config");
    } finally {
      setCreating(false);
    }
  }

  async function handleToggle(cfg: SSOConfig) {
    try {
      await api.put(`/api/v1/admin/sso/configs/${cfg.id}`, { enabled: !cfg.enabled });
      await load();
    } catch {
      // silently surface via reload
    }
  }

  async function handleDelete(id: string) {
    try {
      await api.del(`/api/v1/admin/sso/configs/${id}`);
      setDeleteConfirm(null);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Delete failed");
    }
  }

  function updateForm(patch: Partial<CreateBody>) {
    setForm(prev => ({ ...prev, ...patch }));
  }

  return (
    <div className="max-w-3xl mx-auto space-y-6 p-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-semibold" style={{ fontFamily: "var(--font-space-grotesk)", color: "var(--fg)" }}>
            SSO / SAML Configuration
          </h1>
          <p className="text-xs mt-0.5" style={{ color: "var(--muted)" }}>
            Connect an identity provider so users can sign in with their corporate credentials.
          </p>
        </div>
        {!showCreate && !createResult && (
          <button
            onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded text-sm font-medium transition-colors"
            style={{ background: "var(--primary)", color: "var(--primary-fg)" }}
          >
            <Plus size={14} /> Add provider
          </button>
        )}
      </div>

      {error && (
        <div className="flex items-center gap-2 px-3 py-2 rounded text-sm" style={{ background: "oklch(0.55 0.22 25 / 0.1)", color: "var(--destructive)" }}>
          <AlertTriangle size={14} /> {error}
        </div>
      )}

      {/* Post-create result box */}
      {createResult && (
        <div className="rounded-lg border p-4 space-y-3" style={{ background: "oklch(0.5 0.15 145 / 0.08)", borderColor: "oklch(0.5 0.15 145 / 0.3)" }}>
          <div className="flex items-center gap-2 text-sm font-medium" style={{ color: "oklch(0.55 0.15 145)" }}>
            <Check size={16} /> Provider created successfully
          </div>
          {createResult.saml_metadata_url && (
            <div className="space-y-1">
              <p className="text-xs font-medium" style={{ color: "var(--muted)" }}>SP Metadata URL (give this to your IdP)</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-xs px-2 py-1 rounded font-mono truncate" style={{ background: "var(--surface-1)", color: "var(--fg)" }}>
                  {createResult.saml_metadata_url}
                </code>
                <CopyButton text={createResult.saml_metadata_url} />
              </div>
            </div>
          )}
          {createResult.saml_sp_cert_pem && (
            <div className="space-y-1">
              <p className="text-xs font-medium" style={{ color: "var(--muted)" }}>SP Certificate (upload to your IdP)</p>
              <div className="flex items-start gap-2">
                <Textarea value={createResult.saml_sp_cert_pem} readOnly rows={6} className="flex-1 text-xs" />
                <CopyButton text={createResult.saml_sp_cert_pem} />
              </div>
            </div>
          )}
          {createResult.oidc_redirect_uri && (
            <div className="space-y-1">
              <p className="text-xs font-medium" style={{ color: "var(--muted)" }}>OIDC Redirect URI (register in your IdP)</p>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-xs px-2 py-1 rounded font-mono truncate" style={{ background: "var(--surface-1)", color: "var(--fg)" }}>
                  {createResult.oidc_redirect_uri}
                </code>
                <CopyButton text={createResult.oidc_redirect_uri} />
              </div>
            </div>
          )}
          <button onClick={() => { setCreateResult(null); setShowCreate(false); setForm(EMPTY_FORM); setDomainsInput(""); }}
            className="text-xs hover:underline" style={{ color: "var(--muted)" }}>
            Dismiss
          </button>
        </div>
      )}

      {/* Create form */}
      {showCreate && !createResult && (
        <div className="rounded-lg border p-5 space-y-5" style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}>
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold" style={{ color: "var(--fg)" }}>New SSO Provider</h2>
            <button onClick={() => { setShowCreate(false); setCreateError(""); setForm(EMPTY_FORM); setDomainsInput(""); }}
              className="text-xs hover:underline" style={{ color: "var(--muted)" }}>Cancel</button>
          </div>

          <form onSubmit={handleCreate} className="space-y-4">
            {/* Provider type toggle */}
            <div className="flex gap-2">
              {(["saml", "oidc"] as const).map(t => (
                <button key={t} type="button" onClick={() => updateForm({ provider_type: t })}
                  className="px-4 py-1.5 rounded border text-sm font-medium transition-colors"
                  style={{
                    background: form.provider_type === t ? "var(--primary)" : "var(--surface-1)",
                    color: form.provider_type === t ? "var(--primary-fg)" : "var(--fg)",
                    borderColor: form.provider_type === t ? "var(--primary)" : "var(--border)",
                  }}>
                  {t.toUpperCase()}
                </button>
              ))}
            </div>

            <div className="grid grid-cols-2 gap-4">
              <Field label="Provider Name" hint="Displayed on the login button">
                <Input required value={form.provider_name} onChange={e => updateForm({ provider_name: e.target.value })} placeholder="Okta, Azure AD, Google…" />
              </Field>
              <Field label="Default Role" hint="Role assigned to new SSO users">
                <select value={form.default_role} onChange={e => updateForm({ default_role: e.target.value })}
                  className="w-full px-3 py-2 rounded border text-sm outline-none"
                  style={{ background: "var(--surface-1)", borderColor: "var(--border)", color: "var(--fg)" }}>
                  <option value="analyst">analyst</option>
                  <option value="admin">admin</option>
                </select>
              </Field>
            </div>

            <Field label="Email Domains" hint="Comma-separated domains that trigger SSO (e.g. corp.example.com, example.org)">
              <Input value={domainsInput} onChange={e => setDomainsInput(e.target.value)} placeholder="corp.example.com, example.org" />
            </Field>

            <div className="flex gap-6">
              <label className="flex items-center gap-2 text-sm cursor-pointer select-none">
                <input type="checkbox" checked={form.auto_provision} onChange={e => updateForm({ auto_provision: e.target.checked })} className="rounded" />
                <span style={{ color: "var(--fg)" }}>Auto-provision new users</span>
              </label>
              <label className="flex items-center gap-2 text-sm cursor-pointer select-none">
                <input type="checkbox" checked={form.enabled} onChange={e => updateForm({ enabled: e.target.checked })} className="rounded" />
                <span style={{ color: "var(--fg)" }}>Enabled</span>
              </label>
            </div>

            {/* SAML fields */}
            {form.provider_type === "saml" && (
              <div className="space-y-4 pt-2 border-t" style={{ borderColor: "var(--border)" }}>
                <p className="text-xs font-medium uppercase tracking-wider" style={{ color: "var(--muted)" }}>SAML Settings</p>
                <Field label="IdP Metadata XML" hint="Download from your IdP and paste here">
                  <Textarea required value={form.saml_idp_metadata_xml}
                    onChange={e => updateForm({ saml_idp_metadata_xml: e.target.value })}
                    rows={6} placeholder="<?xml version=&quot;1.0&quot;?>&#10;<EntityDescriptor …" />
                </Field>
                <div className="grid grid-cols-3 gap-3">
                  <Field label="Email attribute">
                    <Input value={form.saml_attribute_email} onChange={e => updateForm({ saml_attribute_email: e.target.value })} placeholder="email" />
                  </Field>
                  <Field label="Name attribute">
                    <Input value={form.saml_attribute_name} onChange={e => updateForm({ saml_attribute_name: e.target.value })} placeholder="name" />
                  </Field>
                  <Field label="Role attribute" hint="Optional — maps to TraceGuard role">
                    <Input value={form.saml_attribute_role} onChange={e => updateForm({ saml_attribute_role: e.target.value })} placeholder="(optional)" />
                  </Field>
                </div>
              </div>
            )}

            {/* OIDC fields */}
            {form.provider_type === "oidc" && (
              <div className="space-y-4 pt-2 border-t" style={{ borderColor: "var(--border)" }}>
                <p className="text-xs font-medium uppercase tracking-wider" style={{ color: "var(--muted)" }}>OIDC Settings</p>
                <Field label="Issuer URL" hint="Discovery endpoint, e.g. https://accounts.google.com">
                  <Input required value={form.oidc_issuer_url} onChange={e => updateForm({ oidc_issuer_url: e.target.value })} placeholder="https://your-idp.example.com" />
                </Field>
                <div className="grid grid-cols-2 gap-3">
                  <Field label="Client ID">
                    <Input required value={form.oidc_client_id} onChange={e => updateForm({ oidc_client_id: e.target.value })} />
                  </Field>
                  <Field label="Client Secret">
                    <Input required type="password" value={form.oidc_client_secret} onChange={e => updateForm({ oidc_client_secret: e.target.value })} />
                  </Field>
                </div>
                <div className="grid grid-cols-3 gap-3">
                  <Field label="Email claim">
                    <Input value={form.oidc_claim_email} onChange={e => updateForm({ oidc_claim_email: e.target.value })} placeholder="email" />
                  </Field>
                  <Field label="Name claim">
                    <Input value={form.oidc_claim_name} onChange={e => updateForm({ oidc_claim_name: e.target.value })} placeholder="preferred_username" />
                  </Field>
                  <Field label="Role claim" hint="Optional">
                    <Input value={form.oidc_claim_role} onChange={e => updateForm({ oidc_claim_role: e.target.value })} placeholder="(optional)" />
                  </Field>
                </div>
              </div>
            )}

            {createError && (
              <div className="flex items-center gap-2 px-3 py-2 rounded text-xs" style={{ background: "oklch(0.55 0.22 25 / 0.1)", color: "var(--destructive)" }}>
                <AlertTriangle size={12} /> {createError}
              </div>
            )}

            <div className="flex justify-end">
              <button type="submit" disabled={creating}
                className="flex items-center gap-2 px-4 py-2 rounded text-sm font-medium disabled:opacity-60"
                style={{ background: "var(--primary)", color: "var(--primary-fg)" }}>
                {creating && <Loader2 size={14} className="animate-spin" />}
                {creating ? "Creating…" : "Create provider"}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Config list */}
      {loading ? (
        <div className="flex items-center justify-center py-12" style={{ color: "var(--muted)" }}>
          <Loader2 size={20} className="animate-spin mr-2" /> Loading…
        </div>
      ) : configs.length === 0 && !showCreate ? (
        <div className="text-center py-12 rounded-lg border border-dashed" style={{ borderColor: "var(--border)", color: "var(--muted)" }}>
          <KeyRound size={28} className="mx-auto mb-3 opacity-40" />
          <p className="text-sm">No SSO providers configured.</p>
          <p className="text-xs mt-1">Add a SAML 2.0 or OIDC provider to enable corporate SSO login.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {configs.map(cfg => (
            <div key={cfg.id} className="rounded-lg border" style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}>
              {/* Row header */}
              <div className="flex items-center gap-3 px-4 py-3">
                <div className="flex-1 flex items-center gap-2 min-w-0">
                  <Shield size={16} style={{ color: "var(--primary)", flexShrink: 0 }} />
                  <span className="font-medium text-sm truncate" style={{ color: "var(--fg)" }}>{cfg.provider_name}</span>
                  <Badge variant={cfg.provider_type === "saml" ? "default" : "success"}>{cfg.provider_type.toUpperCase()}</Badge>
                  {cfg.enabled
                    ? <Badge variant="success">Active</Badge>
                    : <Badge variant="muted">Disabled</Badge>
                  }
                  {cfg.domains?.length > 0 && (
                    <span className="text-xs truncate hidden sm:inline" style={{ color: "var(--muted)" }}>
                      {cfg.domains.join(", ")}
                    </span>
                  )}
                </div>

                <div className="flex items-center gap-1 shrink-0">
                  {/* Toggle enable/disable */}
                  <button onClick={() => handleToggle(cfg)} title={cfg.enabled ? "Disable" : "Enable"}
                    className="p-1.5 rounded hover:bg-[var(--surface-1)] transition-colors" style={{ color: cfg.enabled ? "oklch(0.55 0.15 145)" : "var(--muted)" }}>
                    {cfg.enabled ? <ToggleRight size={18} /> : <ToggleLeft size={18} />}
                  </button>

                  {/* Delete */}
                  {deleteConfirm === cfg.id ? (
                    <div className="flex items-center gap-1">
                      <span className="text-xs" style={{ color: "var(--destructive)" }}>Delete?</span>
                      <button onClick={() => handleDelete(cfg.id)}
                        className="px-2 py-0.5 rounded text-xs font-medium" style={{ background: "var(--destructive)", color: "#fff" }}>Yes</button>
                      <button onClick={() => setDeleteConfirm(null)}
                        className="px-2 py-0.5 rounded text-xs border" style={{ borderColor: "var(--border)", color: "var(--muted)" }}>No</button>
                    </div>
                  ) : (
                    <button onClick={() => setDeleteConfirm(cfg.id)}
                      className="p-1.5 rounded hover:bg-[var(--surface-1)] transition-colors" style={{ color: "var(--muted)" }}>
                      <Trash2 size={15} />
                    </button>
                  )}

                  {/* Expand */}
                  <button onClick={() => setExpanded(expanded === cfg.id ? null : cfg.id)}
                    className="p-1.5 rounded hover:bg-[var(--surface-1)] transition-colors" style={{ color: "var(--muted)" }}>
                    {expanded === cfg.id ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
                  </button>
                </div>
              </div>

              {/* Expanded details */}
              {expanded === cfg.id && (
                <div className="px-4 pb-4 pt-1 border-t space-y-3 text-xs" style={{ borderColor: "var(--border)" }}>
                  <div className="grid grid-cols-2 gap-x-8 gap-y-2">
                    <div>
                      <span style={{ color: "var(--muted)" }}>Auto-provision: </span>
                      <span style={{ color: "var(--fg)" }}>{cfg.auto_provision ? "Yes" : "No"}</span>
                    </div>
                    <div>
                      <span style={{ color: "var(--muted)" }}>Default role: </span>
                      <span style={{ color: "var(--fg)" }}>{cfg.default_role}</span>
                    </div>
                    <div>
                      <span style={{ color: "var(--muted)" }}>Domains: </span>
                      <span style={{ color: "var(--fg)" }}>{cfg.domains?.join(", ") || "—"}</span>
                    </div>
                    <div>
                      <span style={{ color: "var(--muted)" }}>Config ID: </span>
                      <code className="font-mono" style={{ color: "var(--fg)" }}>{cfg.id}</code>
                    </div>
                  </div>

                  {cfg.provider_type === "saml" && (
                    <div className="space-y-2 pt-2">
                      <div className="flex items-center gap-2">
                        <span style={{ color: "var(--muted)" }}>SP Metadata URL:</span>
                        <code className="font-mono text-[11px]" style={{ color: "var(--fg)" }}>
                          {`${window.location.protocol}//${window.location.host}`}/api/v1/sso/saml/metadata?tenant_id={cfg.tenant_id}
                        </code>
                        <CopyButton text={`${window.location.protocol}//${window.location.host}/api/v1/sso/saml/metadata?tenant_id=${cfg.tenant_id}`} />
                      </div>
                      {cfg.saml_sp_cert_pem && (
                        <div className="space-y-1">
                          <div className="flex items-center justify-between">
                            <span style={{ color: "var(--muted)" }}>SP Certificate:</span>
                            <CopyButton text={cfg.saml_sp_cert_pem} />
                          </div>
                          <Textarea value={cfg.saml_sp_cert_pem} readOnly rows={4} className="text-[11px]" />
                        </div>
                      )}
                    </div>
                  )}

                  {cfg.provider_type === "oidc" && (
                    <div className="space-y-1 pt-2">
                      <div>
                        <span style={{ color: "var(--muted)" }}>Issuer: </span>
                        <span style={{ color: "var(--fg)" }}>{cfg.oidc_issuer_url}</span>
                      </div>
                      <div>
                        <span style={{ color: "var(--muted)" }}>Client ID: </span>
                        <code className="font-mono" style={{ color: "var(--fg)" }}>{cfg.oidc_client_id}</code>
                      </div>
                      <div className="flex items-center gap-2">
                        <span style={{ color: "var(--muted)" }}>Redirect URI:</span>
                        <code className="font-mono text-[11px]" style={{ color: "var(--fg)" }}>
                          {`${window.location.protocol}//${window.location.host}`}/api/v1/sso/oidc/callback
                        </code>
                        <CopyButton text={`${window.location.protocol}//${window.location.host}/api/v1/sso/oidc/callback`} />
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Help box */}
      <div className="rounded-lg border p-4 text-xs space-y-1.5" style={{ background: "var(--surface-0)", borderColor: "var(--border)" }}>
        <p className="font-medium" style={{ color: "var(--fg)" }}>Setup guide</p>
        <ol className="list-decimal list-inside space-y-1" style={{ color: "var(--muted)" }}>
          <li>Create the provider above, choosing SAML or OIDC.</li>
          <li>Copy the SP Metadata URL or Redirect URI and register it in your IdP (Okta, Azure AD, Google Workspace, etc.).</li>
          <li>For SAML: download the IdP metadata XML from your IdP and paste it here.</li>
          <li>Set the email domains so users are routed to SSO automatically on the login page.</li>
          <li>Test by signing in with a corporate email address.</li>
        </ol>
      </div>
    </div>
  );
}
