"use client";

import { useState } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { ArrowRight, Check, CircleHelp, Globe2, LoaderCircle, LockKeyhole, Shield, ShieldAlert } from "lucide-react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { PageHeading } from "@/components/page-heading";
import { RiskBadge, SeverityBadge } from "@/components/risk-badge";
import { assessWebsiteSecurity } from "@/lib/api/services";
import type { InvestigationResult } from "@/lib/types";
import { isHttpUrlOrDomain } from "@/lib/url";

const schema = z.object({
  url: z.string().trim().min(1, "Enter a website URL.")
    .max(2048, "URL must be under 2,048 characters.")
    .refine(isHttpUrlOrDomain, "Enter a valid HTTP(S) URL or domain."),
});
type FormValues = z.infer<typeof schema>;
const checks = [
  ["TLS configuration", "Certificate chain and protocol observations", "probe"],
  ["HTTP security headers", "Common response-header presence", "probe"],
  ["HTTPS and redirects", "Secure transport and redirect behavior", "probe"],
  ["Mixed content", "Resources requested over insecure transport", "probe"],
  ["Public indicators", "Passive, observable security signals", "rule"],
];

export default function SecurityAssessmentPage() {
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [serviceError, setServiceError] = useState("");
  const { register, handleSubmit, formState: { errors } } = useForm<FormValues>({ resolver: zodResolver(schema) });
  const submit = handleSubmit(async ({ url }) => {
    setLoading(true); setServiceError("");
    try { setResult(await assessWebsiteSecurity(url)); }
    catch (error) { setServiceError(error instanceof Error ? error.message : "Assessment failed."); }
    finally { setLoading(false); }
  });
  return <div>
    <PageHeading eyebrow="Passive technical checks" title="Security assessment" description="Review publicly observable TLS and HTTP configuration signals. This is not penetration testing."/>
    <div className="mb-5 grid gap-3 sm:grid-cols-3">{checks.slice(0, 3).map(([title, detail], i) => <div key={title} className="panel-soft p-4"><div className="flex items-center justify-between"><span className="text-[11px] font-semibold text-slate-300">{title}</span>{i === 0 ? <LockKeyhole size={14} className="text-cyan-200"/> : i === 1 ? <Shield size={14} className="text-cyan-200"/> : <Globe2 size={14} className="text-cyan-200"/>}</div><div className="mt-2 text-[10px] leading-4 text-slate-600">{detail}</div></div>)}</div>
    <div className="grid gap-4 lg:grid-cols-[.8fr_1.2fr]">
      <form onSubmit={submit} className="panel p-5"><label htmlFor="security-url" className="text-xs font-semibold text-slate-200">Website URL</label><div className="mt-3 flex flex-col gap-2"><input id="security-url" {...register("url")} className="field px-3 py-3 text-xs" placeholder="https://example.com" autoComplete="url"/>{errors.url && <span role="alert" className="text-[10px] text-rose-300">{errors.url.message}</span>}<button disabled={loading} className="btn-primary mt-1 text-xs">{loading ? <><LoaderCircle size={14} className="animate-spin"/> Checking</> : <>Run passive checks <ArrowRight size={14}/></>}</button></div><p className="mt-4 flex gap-2 text-[10px] leading-5 text-slate-600"><CircleHelp size={13} className="mt-0.5 shrink-0"/>No exploit attempts, authentication bypasses, or intrusive testing are performed.</p>{serviceError && <p role="alert" className="mt-3 text-[10px] text-rose-300">{serviceError}</p>}</form>
      <div className="panel p-5">
        {!result && !loading && <div className="flex h-full min-h-44 flex-col items-center justify-center text-center"><ShieldAlert size={19} className="text-slate-600"/><div className="mt-3 text-xs text-slate-400">Assessment results will appear here</div><div className="mt-1 text-[10px] text-slate-600">Run the sample check to view the result layout</div></div>}
        {loading && <div className="flex min-h-44 items-center justify-center"><div className="text-center"><LoaderCircle size={20} className="mx-auto animate-spin text-cyan-200"/><div className="mt-3 text-xs text-slate-300">Running demonstration checks…</div></div></div>}
        {result && !loading && <div><div className="flex flex-wrap items-start justify-between gap-3"><div><div className="eyebrow">Assessment summary · demo</div><div className="mt-2 break-all font-mono text-xs text-slate-200">{result.submittedUrl}</div></div><RiskBadge level={result.risk.level}/></div><div className="mt-4 rounded-md border border-amber-300/15 bg-amber-300/[.04] p-3 text-[10px] leading-5 text-amber-100/80">Illustrative output only. No live request, TLS check, or header inspection was performed.</div><div className="mt-5 space-y-4">{checks.map(([title, detail, source], index) => <div key={title} className="flex items-start justify-between gap-3 border-b border-[#202d38] pb-3 last:border-0"><div><div className="text-[11px] text-slate-300">{title}</div><div className="mt-1 text-[9px] text-slate-600">{detail} · {source}</div></div>{index === 0 ? <span className="flex items-center gap-1 text-[9px] text-emerald-300"><Check size={11}/> Sample only</span> : <SeverityBadge severity={index === 1 ? "medium" : "info"}/>}</div>)}</div><div className="mt-3 border-t border-[#202d38] pt-3 text-[10px] leading-5 text-slate-500">{result.findings[0]?.explanation}</div></div>}
      </div>
    </div>
  </div>;
}
