"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { AnimatePresence, motion } from "framer-motion";
import { AlertTriangle, ArrowDownToLine, ArrowRight, Check, Clipboard, Globe2, LoaderCircle, LockKeyhole, Network, Shield, ShieldCheck } from "lucide-react";
import { useEffect, useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { PageHeading } from "@/components/page-heading";
import { RiskBadge, SeverityBadge } from "@/components/risk-badge";
import { investigateURL } from "@/lib/api/services";
import { demoInvestigation } from "@/lib/mock-data";
import type { InvestigationResult } from "@/lib/types";
import { isHttpUrlOrDomain } from "@/lib/url";

const schema = z.object({
  input: z.string().trim().min(1, "Enter a URL or domain.")
    .max(2048, "URL must be under 2,048 characters.")
    .refine(isHttpUrlOrDomain, "Enter a valid HTTP(S) URL or domain."),
});
type FormValues = z.infer<typeof schema>;

export default function InvestigatePage() {
  const [result, setResult] = useState<InvestigationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [notice, setNotice] = useState("");
  const { register, handleSubmit, setValue, formState: { errors } } = useForm<FormValues>({ resolver: zodResolver(schema), defaultValues: { input: "" } });
  useEffect(() => {
    const url = new URLSearchParams(window.location.search).get("url");
    if (url) setValue("input", url);
  }, [setValue]);
  const submit = handleSubmit(async (values) => {
    setLoading(true); setNotice("");
    try { setResult(await investigateURL({ input: values.input })); }
    catch (error) { setNotice(error instanceof Error ? error.message : "Investigation failed."); }
    finally { setLoading(false); }
  });
  const exportReport = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url; link.download = `${result.id}.json`; link.click(); URL.revokeObjectURL(url);
  };
  const copy = async (value: string) => {
    try { await navigator.clipboard.writeText(value); setNotice("Copied to clipboard."); }
    catch { setNotice("Clipboard access is unavailable in this browser."); }
  };
  return <div>
    <PageHeading eyebrow="URL intelligence" title="Investigate a URL" description="Review observable signals, technical evidence, and unavailable checks in one report."/>
    <form onSubmit={submit} className="panel p-4 sm:p-5">
      <label htmlFor="url-input" className="mb-2 block text-xs font-semibold text-slate-200">URL or domain</label>
      <div className="flex flex-col gap-2 sm:flex-row"><input id="url-input" {...register("input")} className="field min-w-0 flex-1 px-3.5 py-3 text-xs" placeholder="https://example.com/path" autoComplete="url" aria-invalid={Boolean(errors.input)}/><button type="submit" disabled={loading} className="btn-primary min-w-[150px] text-xs">{loading ? <><LoaderCircle size={15} className="animate-spin"/> Inspecting</> : <>Investigate <ArrowRight size={14}/></>}</button></div>
      {errors.input && <p className="mt-2 text-[11px] text-rose-300" role="alert">{errors.input.message}</p>}
      <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-[10px] text-slate-600"><span className="flex items-center gap-1.5"><LockKeyhole size={12}/> Submitted URLs are treated as untrusted text and are not opened by this interface.</span><button type="button" onClick={() => { setValue("input", demoInvestigation.submittedUrl); setResult(demoInvestigation); }} className="text-cyan-200 hover:text-cyan-100">Load sample report</button></div>
    </form>
    {notice && <div role="status" className="mt-3 rounded-md border border-cyan-300/15 bg-cyan-300/[.05] px-3 py-2 text-[11px] text-cyan-100">{notice}</div>}
    {loading && <div className="mt-5 grid gap-3 md:grid-cols-3"><div className="panel h-36 animate-pulse bg-[#111923]"/><div className="panel h-36 animate-pulse bg-[#111923]"/><div className="panel h-36 animate-pulse bg-[#111923]"/></div>}
    <AnimatePresence>{result && !loading && <motion.section initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mt-5 space-y-4">
      <div className="rounded-lg border border-amber-300/20 bg-amber-300/[.04] px-4 py-3 text-[11px] leading-5 text-amber-100/80"><strong className="text-amber-100">Demonstration report.</strong> Results shown here are sample data and are not independently verified. Do not rely on this report to establish that a site is safe.</div>
      <div className="grid gap-4 lg:grid-cols-[.8fr_1.7fr]">
        <div className="panel p-5"><div className="flex items-start justify-between"><div><div className="eyebrow">Overall risk assessment</div><div className="mt-4"><RiskBadge level={result.risk.level}/></div></div><button onClick={exportReport} className="btn-secondary px-2.5 py-2 text-[10px]" aria-label="Download report"><ArrowDownToLine size={14}/></button></div>
          <div className="mt-5 flex items-center gap-4"><div className="text-5xl font-semibold tracking-[-.06em] text-slate-100">{result.risk.score}<span className="ml-1 text-base font-normal text-slate-600">/100</span></div><div className="flex-1"><div className="h-1.5 overflow-hidden rounded-full bg-[#26323d]"><div className="h-full rounded-full bg-orange-300" style={{ width: `${result.risk.score}%` }}/></div><div className="mt-2 text-[9px] text-slate-600">Illustrative risk score</div></div></div>
          <p className="mt-4 text-[11px] leading-5 text-slate-400">{result.risk.explanation}</p><button onClick={() => copy(result.id)} className="mt-5 flex items-center gap-2 font-mono text-[10px] text-slate-500 hover:text-cyan-100"><Clipboard size={12}/> {result.id} · copy ID</button>
        </div>
        <div className="panel p-5"><div className="flex items-center justify-between gap-2"><div><div className="eyebrow">Domain intelligence</div><div className="mt-2 break-all font-mono text-sm text-slate-100">{result.domain.domain}</div></div><Globe2 size={19} className="shrink-0 text-cyan-200"/></div>
          <div className="mt-5 grid gap-x-5 gap-y-4 sm:grid-cols-2">{[["Registered domain", result.domain.registeredDomain], ["Subdomain", result.domain.subdomain], ["TLD", result.domain.tld], ["IP address", result.domain.ipAddress], ["Registration", result.domain.registration], ["Reputation", result.domain.reputation]].map(([label, value]) => <div key={label}><div className="text-[9px] uppercase tracking-wider text-slate-600">{label}</div><div className="mt-1 break-all text-[11px] text-slate-300">{value}</div></div>)}</div>
        </div>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel p-5"><div className="flex items-center gap-2"><Shield size={15} className="text-cyan-200"/><div className="section-title">TLS certificate analysis</div></div><div className="mt-4 flex items-center gap-2 text-[11px]"><span className={result.tls.valid ? "text-emerald-300" : "text-rose-300"}>{result.tls.https && result.tls.valid ? "HTTPS available · certificate valid in sample" : "Not verified"}</span></div><div className="mt-4 space-y-3 text-[10px]"><div className="flex justify-between gap-3"><span className="text-slate-600">Issuer</span><span className="text-right text-slate-300">{result.tls.issuer}</span></div><div className="flex justify-between gap-3"><span className="text-slate-600">Expires</span><span className="text-slate-300">{result.tls.expiresAt}</span></div><div><div className="text-slate-600">Subject alternative names</div><div className="mt-1 font-mono text-slate-300">{result.tls.subjectAlternativeNames.join(", ")}</div></div></div><p className="mt-4 border-t border-[#202d38] pt-3 text-[10px] leading-4 text-slate-600">A valid certificate encrypts a connection; it does not establish that a website or its operator is trustworthy.</p></div>
        <div className="panel p-5"><div className="flex items-center gap-2"><Network size={15} className="text-cyan-200"/><div className="section-title">Redirect chain</div></div><div className="mt-4 space-y-3">{result.redirects.map((redirect, i) => <div key={`${redirect.url}-${i}`} className="flex gap-3"><div className="flex flex-col items-center"><span className="flex h-5 w-5 items-center justify-center rounded-full border border-[#344653] text-[9px] text-slate-400">{i + 1}</span>{i < result.redirects.length - 1 && <span className="my-1 h-full w-px bg-[#344653]"/>}</div><div className="min-w-0 pb-2"><div className="break-all font-mono text-[10px] text-slate-300">{redirect.url}</div><div className="mt-1 text-[9px] text-slate-600">HTTP {redirect.statusCode} · {redirect.locationHost}</div></div></div>)}</div></div>
      </div>
      <div className="panel p-5"><div className="flex items-center justify-between gap-3"><div><div className="section-title">Evidence and findings</div><div className="mt-1 text-[10px] text-slate-500">{result.findings.length} sample observations</div></div><span className="text-[10px] text-slate-600">{result.checksCompleted} checks shown · {result.checksUnavailable} unavailable</span></div><div className="mt-4 space-y-3">{result.findings.map((finding) => <article key={finding.id} className="rounded-lg border border-[#202d38] bg-[#0a1118] p-4"><div className="flex flex-wrap items-center justify-between gap-2"><h3 className="text-xs font-semibold text-slate-200">{finding.title}</h3><SeverityBadge severity={finding.severity}/></div><div className="mt-3 grid gap-3 text-[10px] sm:grid-cols-2"><div><div className="eyebrow !text-[9px]">Evidence · {finding.source}</div><p className="mt-1 leading-5 text-slate-400">{finding.evidence}</p></div><div><div className="eyebrow !text-[9px]">Why it matters</div><p className="mt-1 leading-5 text-slate-400">{finding.explanation} {finding.impact}</p></div><div className="sm:col-span-2"><div className="eyebrow !text-[9px]">Recommended action</div><p className="mt-1 leading-5 text-slate-400">{finding.recommendation}</p></div></div></article>)}</div></div>
      <div className="grid gap-4 lg:grid-cols-2">
        <div className="panel p-5"><div className="flex items-center gap-2"><ShieldCheck size={15} className="text-cyan-200"/><div className="section-title">Threat intelligence</div></div><div className="mt-4 space-y-3">{result.intelligence.map((item) => <div key={item.source} className="flex items-center justify-between border-b border-[#1c2731] pb-3 last:border-0 last:pb-0"><div><div className="text-[11px] text-slate-300">{item.source}</div><div className="mt-1 text-[9px] text-slate-600">{item.detail}</div></div><span className="rounded-full border border-slate-600/30 px-2 py-1 text-[9px] uppercase text-slate-500">{item.status}</span></div>)}</div></div>
        <div className="panel p-5"><div className="flex items-center gap-2"><AlertTriangle size={15} className="text-violet-300"/><div className="section-title">AI explanation</div></div><div className="mt-2 text-[9px] uppercase tracking-wider text-violet-200/70">Generated interpretation · not verified evidence</div><p className="mt-4 text-[11px] leading-6 text-slate-400">{result.aiExplanation}</p><div className="mt-4 flex items-center gap-1.5 text-[9px] text-slate-600"><Check size={12}/> Analysis metadata: {new Date(result.scannedAt).toLocaleString()} · {result.durationMs} ms (sample)</div></div>
      </div>
    </motion.section>}</AnimatePresence>
    {!result && !loading && <div className="panel mt-5 flex min-h-56 flex-col items-center justify-center px-5 text-center"><div className="flex h-10 w-10 items-center justify-center rounded-full border border-[#2a3945] bg-[#131d26] text-slate-400"><Globe2 size={18}/></div><div className="mt-4 text-sm font-medium text-slate-300">Your investigation report will appear here</div><p className="mt-2 max-w-sm text-[11px] leading-5 text-slate-600">Submit any URL or load the sample report to explore report structure. Sample outputs are not live assessments.</p></div>}
  </div>;
}
