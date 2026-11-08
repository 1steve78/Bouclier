"use client";

import Link from "next/link";
import { ArrowRight, ArrowUpRight, Clock3, Globe2, Plus, ShieldAlert, ShieldCheck, Sparkles } from "lucide-react";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { PageHeading } from "@/components/page-heading";
import { RiskBadge, SeverityBadge } from "@/components/risk-badge";
import { threatRecords } from "@/lib/mock-data";

const distribution = [{ name: "Low", value: 42, color: "#51c99a" }, { name: "Suspicious", value: 27, color: "#e5bd66" }, { name: "High", value: 21, color: "#ef925b" }, { name: "Confirmed", value: 10, color: "#d96f7c" }];
const recent = [
  { domain: "accounts-micros0ft.example", date: "Today, 08:30", risk: "high_risk" as const, score: 82 },
  { domain: "cdn-assets.example", date: "Yesterday, 16:42", risk: "low_risk" as const, score: 12 },
  { domain: "secure-wallet-check.example", date: "Nov 06, 11:09", risk: "suspicious" as const, score: 57 },
];

export default function DashboardPage() {
  return <div>
    <PageHeading eyebrow="Workspace overview" title="Good morning." description="Your digital trust workspace at a glance. All figures below are illustrative sample data." action={<Link href="/investigate" className="btn-primary text-xs"><Plus size={15}/> New investigation</Link>}/>
    <div className="mb-5 rounded-lg border border-amber-400/20 bg-amber-400/[.045] px-4 py-3 text-[11px] leading-5 text-amber-100/80"><span className="font-semibold text-amber-100">Demonstration data.</span> No live scans, threat feeds, or blockchain checks have been performed.</div>
    <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
      {[["Investigations", "128", "+12 this week", Globe2], ["High-risk signals", "18", "Sample reports", ShieldAlert], ["Reports verified", "42", "Demo commitments", ShieldCheck], ["Avg. analysis time", "2.4s", "Illustrative only", Clock3]].map(([label, value, note, Icon]) => {
        const Symbol = Icon as typeof Globe2;
        return <div key={label as string} className="panel p-4"><div className="flex items-center justify-between"><span className="text-[11px] text-slate-500">{label as string}</span><Symbol size={15} className="text-slate-500"/></div><div className="mt-4 text-2xl font-semibold tracking-tight text-slate-100">{value as string}</div><div className="mt-1 text-[10px] text-slate-600">{note as string}</div></div>;
      })}
    </div>
    <div className="mt-5 grid gap-4 xl:grid-cols-[1.45fr_.8fr]">
      <section className="panel p-5"><div className="flex items-center justify-between"><div><div className="section-title">Recent investigations</div><div className="mt-1 text-[10px] text-slate-500">Example reports from this demo workspace</div></div><Link href="/investigate" className="text-[10px] text-cyan-200 hover:text-cyan-100">View all <ArrowRight className="ml-1 inline" size={12}/></Link></div>
        <div className="mt-4 overflow-x-auto"><table className="w-full min-w-[510px] text-left"><thead><tr className="border-b border-[#202d38] text-[9px] uppercase tracking-wider text-slate-600"><th className="pb-3 font-medium">Target</th><th className="pb-3 font-medium">Date</th><th className="pb-3 font-medium">Assessment</th><th className="pb-3 text-right font-medium">Score</th></tr></thead><tbody>{recent.map((item) => <tr key={item.domain} className="border-b border-[#1b2630] last:border-0"><td className="py-3 font-mono text-[10px] text-slate-300">{item.domain}</td><td className="py-3 text-[10px] text-slate-500">{item.date}</td><td className="py-3"><RiskBadge level={item.risk}/></td><td className="py-3 text-right font-mono text-[11px] text-slate-300">{item.score}</td></tr>)}</tbody></table></div>
      </section>
      <section className="panel p-5"><div className="section-title">Risk distribution</div><div className="mt-1 text-[10px] text-slate-500">Illustrative sample · 30 days</div><div className="mt-2 flex items-center gap-2">
        <div className="h-[150px] w-[56%]"><ResponsiveContainer width="100%" height="100%"><PieChart><Pie data={distribution} innerRadius={45} outerRadius={65} paddingAngle={3} dataKey="value" stroke="none">{distribution.map((item) => <Cell key={item.name} fill={item.color}/>)}</Pie><Tooltip contentStyle={{ background: "#111a23", border: "1px solid #2a3844", borderRadius: 8, fontSize: 11 }} itemStyle={{ color: "#e8edf2" }}/></PieChart></ResponsiveContainer></div>
        <div className="flex-1 space-y-2">{distribution.map((item) => <div key={item.name} className="flex items-center justify-between text-[10px]"><span className="flex items-center gap-2 text-slate-400"><i className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: item.color }}/>{item.name}</span><span className="font-mono text-slate-300">{item.value}%</span></div>)}</div>
      </div></section>
    </div>
    <div className="mt-4 grid gap-4 lg:grid-cols-2">
      <section className="panel p-5"><div className="flex items-center justify-between"><div><div className="section-title">Recent threat activity</div><div className="mt-1 text-[10px] text-slate-500">Sample records · not a live feed</div></div><Link href="/threat-intelligence" className="text-[10px] text-slate-400 hover:text-white">Open intelligence <ArrowUpRight className="ml-1 inline" size={12}/></Link></div>
        <div className="mt-4 space-y-3">{threatRecords.slice(0, 3).map((record) => <div key={record.id} className="flex items-center justify-between gap-3 border-b border-[#1b2630] pb-3 last:border-0 last:pb-0"><div className="min-w-0"><div className="truncate font-mono text-[10px] text-slate-300">{record.indicator}</div><div className="mt-1 text-[10px] text-slate-600">{record.category} · {record.reported}</div></div><SeverityBadge severity={record.severity}/></div>)}</div>
      </section>
      <section className="panel p-5"><div className="flex items-center gap-2"><Sparkles size={15} className="text-cyan-200"/><div className="section-title">Intelligence summary</div></div><p className="mt-3 text-xs leading-6 text-slate-400">This workspace is running in demonstration mode. Explore the UI with sample reports, but treat all scores, findings, and threat records as illustrative content—not operational intelligence.</p><div className="mt-4 flex flex-wrap gap-2"><Link href="/message-analysis" className="btn-secondary text-[10px]">Analyze a message <ArrowRight size={12}/></Link><Link href="/verify" className="btn-secondary text-[10px]">Verify a report <ArrowRight size={12}/></Link></div></section>
    </div>
  </div>;
}
