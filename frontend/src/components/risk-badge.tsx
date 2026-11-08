import type { RiskLevel, Severity } from "@/lib/types";

const riskLabels: Record<RiskLevel, string> = {
  low_risk: "Low risk",
  suspicious: "Suspicious",
  high_risk: "High risk",
  confirmed_malicious: "Confirmed malicious",
};

const severityStyles: Record<Severity, string> = {
  info: "border-slate-500/30 bg-slate-500/10 text-slate-300",
  low: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  medium: "border-amber-500/30 bg-amber-500/10 text-amber-300",
  high: "border-orange-500/30 bg-orange-500/10 text-orange-300",
  critical: "border-rose-500/30 bg-rose-500/10 text-rose-300",
};

export function RiskBadge({ level }: { level: RiskLevel }) {
  const colors: Record<RiskLevel, string> = {
    low_risk: "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
    suspicious: "border-amber-500/30 bg-amber-500/10 text-amber-300",
    high_risk: "border-orange-500/30 bg-orange-500/10 text-orange-300",
    confirmed_malicious: "border-rose-500/30 bg-rose-500/10 text-rose-300",
  };
  return <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-semibold ${colors[level]}`}><span className="h-1.5 w-1.5 rounded-full bg-current" />{riskLabels[level]}</span>;
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`inline-flex rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${severityStyles[severity]}`}>{severity}</span>;
}
