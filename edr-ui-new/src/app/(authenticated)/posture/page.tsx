"use client";

import { useApi } from "@/hooks/use-api";
import { api } from "@/lib/api-client";
import { ShieldCheck, AlertTriangle, AlertOctagon, Info } from "lucide-react";

interface PostureComponent {
  name: string;
  score: number;
  weight: number;
  detail: string;
}

interface PostureFinding {
  severity: "critical" | "high" | "medium";
  title: string;
  detail: string;
}

interface PostureScore {
  overall: number;
  grade: string;
  components: PostureComponent[];
  findings: PostureFinding[];
  computed_at: string;
}

function gradeColor(grade: string) {
  switch (grade) {
    case "A": return { ring: "stroke-emerald-400", text: "text-emerald-400", bg: "bg-emerald-500/10" };
    case "B": return { ring: "stroke-cyan-400",    text: "text-cyan-400",    bg: "bg-cyan-500/10" };
    case "C": return { ring: "stroke-amber-400",   text: "text-amber-400",   bg: "bg-amber-500/10" };
    case "D": return { ring: "stroke-orange-400",  text: "text-orange-400",  bg: "bg-orange-500/10" };
    default:  return { ring: "stroke-red-400",     text: "text-red-400",     bg: "bg-red-500/10" };
  }
}

function scoreColor(score: number) {
  if (score >= 80) return "bg-emerald-500";
  if (score >= 65) return "bg-cyan-500";
  if (score >= 50) return "bg-amber-500";
  if (score >= 35) return "bg-orange-500";
  return "bg-red-500";
}

function FindingIcon({ severity }: { severity: string }) {
  if (severity === "critical") return <AlertOctagon size={14} className="text-red-400 shrink-0 mt-0.5" />;
  if (severity === "high")     return <AlertTriangle size={14} className="text-orange-400 shrink-0 mt-0.5" />;
  return <Info size={14} className="text-amber-400 shrink-0 mt-0.5" />;
}

function ScoreGauge({ score, grade }: { score: number; grade: string }) {
  const c = gradeColor(grade);
  const r = 52;
  const circ = 2 * Math.PI * r;
  // Only use the top 75% of the circle (270°) so it looks like a speedometer arc
  const arcLen = circ * 0.75;
  const fillLen = arcLen * (score / 100);
  const gap = circ - arcLen;

  return (
    <div className="relative flex items-center justify-center w-36 h-36">
      <svg width="144" height="144" viewBox="0 0 144 144" className="-rotate-[135deg]">
        {/* Track */}
        <circle cx="72" cy="72" r={r} fill="none" stroke="rgba(255,255,255,0.06)"
          strokeWidth="10" strokeDasharray={`${arcLen} ${circ - arcLen}`} strokeLinecap="round" />
        {/* Fill */}
        <circle cx="72" cy="72" r={r} fill="none"
          className={c.ring}
          strokeWidth="10"
          strokeDasharray={`${fillLen} ${circ - fillLen + gap}`}
          strokeLinecap="round" />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={`text-3xl font-bold tabular-nums ${c.text}`}>{score}</span>
        <span className={`text-xs font-semibold px-2 py-0.5 rounded-full ${c.bg} ${c.text} mt-1`}>{grade}</span>
      </div>
    </div>
  );
}

export default function PosturePage() {
  const { data, loading, error, refetch } = useApi<PostureScore>(
    () => api.get<PostureScore>("/api/v1/xdr/posture")
  );

  const computedAt = data?.computed_at
    ? new Date(data.computed_at).toLocaleString()
    : null;

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      {/* Header */}
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-lg font-semibold flex items-center gap-2">
            <ShieldCheck size={18} /> Security Posture Score
          </h1>
          <p className="text-xs text-neutral-400 mt-0.5">
            Aggregated org-wide security health across hosts, identities, vulnerabilities, and anomalies.
          </p>
        </div>
        <button
          onClick={() => refetch()}
          className="text-xs px-3 py-1.5 rounded border border-neutral-700 hover:bg-neutral-800 text-neutral-400"
        >
          Refresh
        </button>
      </div>

      {loading && (
        <div className="text-sm text-neutral-400">Computing posture…</div>
      )}
      {error && (
        <div className="text-sm text-red-400 bg-red-500/10 rounded-lg px-4 py-3">{error}</div>
      )}

      {data && (
        <>
          {/* Score + grade */}
          <div className="flex flex-col sm:flex-row gap-6 bg-neutral-900 border border-neutral-800 rounded-xl p-6">
            <div className="flex flex-col items-center gap-2">
              <ScoreGauge score={data.overall} grade={data.grade} />
              <span className="text-[10px] text-neutral-500">
                Computed {computedAt}
              </span>
            </div>

            <div className="flex-1 space-y-1.5">
              <p className="text-xs font-semibold text-neutral-400 uppercase tracking-wider mb-3">
                Score breakdown
              </p>
              {data.components.map((c) => (
                <div key={c.name} className="space-y-0.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-neutral-300">{c.name}</span>
                    <span className="font-mono text-neutral-400">{c.score}/100
                      <span className="text-neutral-600 ml-1">×{c.weight}%</span>
                    </span>
                  </div>
                  <div className="h-1.5 rounded-full bg-neutral-800 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all ${scoreColor(c.score)}`}
                      style={{ width: `${c.score}%` }}
                    />
                  </div>
                  <p className="text-[10px] text-neutral-600">{c.detail}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Findings */}
          {data.findings.length > 0 ? (
            <div className="space-y-3">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-neutral-400">
                Key findings ({data.findings.length})
              </h2>
              <div className="space-y-2">
                {data.findings.map((f, i) => (
                  <div
                    key={i}
                    className={`flex gap-3 p-3 rounded-lg border ${
                      f.severity === "critical"
                        ? "bg-red-500/5 border-red-500/20"
                        : f.severity === "high"
                        ? "bg-orange-500/5 border-orange-500/20"
                        : "bg-amber-500/5 border-amber-500/20"
                    }`}
                  >
                    <FindingIcon severity={f.severity} />
                    <div>
                      <p className="text-xs font-medium text-neutral-200">{f.title}</p>
                      <p className="text-xs text-neutral-500 mt-0.5">{f.detail}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : (
            <div className="flex items-center gap-3 p-4 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
              <ShieldCheck size={16} className="text-emerald-400 shrink-0" />
              <p className="text-xs text-emerald-300">No critical findings — posture is healthy.</p>
            </div>
          )}
        </>
      )}
    </div>
  );
}
