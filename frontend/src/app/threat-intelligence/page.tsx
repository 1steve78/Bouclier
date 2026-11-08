"use client";

import { useEffect, useMemo, useState } from "react";
import { ArrowUpRight, Database, Search, ShieldAlert } from "lucide-react";
import { PageHeading } from "@/components/page-heading";
import { SeverityBadge } from "@/components/risk-badge";
import { getThreatIntelligence } from "@/lib/api/services";
import { threatRecords } from "@/lib/mock-data";
import type { ThreatRecord } from "@/lib/types";

export default function ThreatIntelligencePage() {
  const [records, setRecords] = useState<ThreatRecord[]>([]);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState("All categories");
  const [loadError, setLoadError] = useState("");
  useEffect(() => { getThreatIntelligence().then(setRecords).catch((error: unknown) => setLoadError(error instanceof Error ? error.message : "Could not load sample records.")); }, []);
  const categories = ["All categories", ...Array.from(new Set(threatRecords.map((record) => record.category)))];
  const filtered = useMemo(() => records.filter((record) =>
    (category === "All categories" || record.category === category) &&
    `${record.indicator} ${record.category} ${record.source}`.toLowerCase().includes(query.toLowerCase()),
  ), [records, category, query]);
  return <div>
    <PageHeading eyebrow="Community and feed signals" title="Threat intelligence" description="Search sample indicators and reports. All records on this page are demonstration data, not a live threat feed." action={<div className="flex items-center gap-2 rounded-md border border-[#2b3946] px-3 py-2 text-[10px] text-slate-400"><Database size={13}/> Sample dataset</div>}/>
    <div className="mb-5 grid gap-3 sm:grid-cols-3">{[["Reported indicators", "2,481"], ["Campaign clusters", "64"], ["Awaiting review", "19"]].map(([label, value]) => <div key={label} className="panel p-4"><div className="text-[10px] text-slate-500">{label}</div><div className="mt-2 text-xl font-semibold text-slate-200">{value}<span className="ml-2 text-[9px] font-normal text-slate-600">demo</span></div></div>)}</div>
    <div className="panel p-4">
      <div className="flex flex-col gap-2 sm:flex-row"><div className="relative flex-1"><Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600"/><input value={query} onChange={(event) => setQuery(event.target.value)} aria-label="Search threat intelligence" className="field py-2.5 pl-9 pr-3 text-[11px]" placeholder="Search domains, categories, or sources"/></div><label className="sr-only" htmlFor="category">Filter category</label><select id="category" value={category} onChange={(event) => setCategory(event.target.value)} className="field w-full px-3 py-2.5 text-[11px] sm:w-56">{categories.map((item) => <option key={item}>{item}</option>)}</select></div>
      <div className="mt-4 overflow-x-auto"><table className="w-full min-w-[700px] text-left"><thead><tr className="border-b border-[#25323d] text-[9px] uppercase tracking-wider text-slate-600"><th className="px-3 py-3 font-medium">Indicator</th><th className="px-3 py-3 font-medium">Category</th><th className="px-3 py-3 font-medium">Reported</th><th className="px-3 py-3 font-medium">Source</th><th className="px-3 py-3 font-medium">Severity</th><th className="px-3 py-3 font-medium">Status</th></tr></thead>
        <tbody>{filtered.map((record) => <tr key={record.id} className="border-b border-[#1b2630] last:border-0"><td className="px-3 py-3.5"><div className="font-mono text-[10px] text-slate-300">{record.indicator}</div><div className="mt-1 text-[9px] text-slate-600">{record.id}</div></td><td className="px-3 py-3.5 text-[10px] text-slate-400">{record.category}</td><td className="px-3 py-3.5 text-[10px] text-slate-500">{record.reported}</td><td className="px-3 py-3.5 text-[10px] text-slate-500">{record.source}</td><td className="px-3 py-3.5"><SeverityBadge severity={record.severity}/></td><td className="px-3 py-3.5"><span className="flex items-center gap-1.5 whitespace-nowrap text-[9px] text-slate-400"><span className={`h-1.5 w-1.5 rounded-full ${record.status.startsWith("Confirmed") ? "bg-orange-300" : "bg-cyan-300"}`}/>{record.status}</span></td></tr>)}</tbody></table>
        {!filtered.length && <div className="flex flex-col items-center py-12 text-center"><ShieldAlert size={19} className="text-slate-600"/><div className="mt-3 text-xs text-slate-400">No matching sample records</div><div className="mt-1 text-[10px] text-slate-600">Try another search or category.</div></div>}
        {loadError && <p role="alert" className="py-3 text-[10px] text-rose-300">{loadError}</p>}
      </div>
    </div>
    <div className="mt-4 flex items-start justify-between gap-3 rounded-lg border border-[#23313d] bg-[#0d151c] p-4"><div><div className="text-[11px] font-semibold text-slate-300">How to interpret these reports</div><p className="mt-1 max-w-3xl text-[10px] leading-5 text-slate-600">Community reports and threat-feed records can be incomplete, stale, or incorrect. Check source, time, and corroborating evidence before taking action. Items marked “Confirmed · demo” are examples only.</p></div><ArrowUpRight size={14} className="mt-0.5 shrink-0 text-slate-600"/></div>
  </div>;
}
