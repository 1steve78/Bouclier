"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { AlertTriangle, ArrowRight, Check, Clipboard, LoaderCircle, Mail, MessageSquareText, ShieldAlert, Sparkles } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { PageHeading } from "@/components/page-heading";
import { RiskBadge, SeverityBadge } from "@/components/risk-badge";
import { analyzeMessage } from "@/lib/api/services";
import type { MessageAnalysisResult } from "@/lib/types";

const schema = z.object({ message: z.string().trim().min(12, "Add at least 12 characters for analysis.").max(10000, "Message must be under 10,000 characters.") });
type FormValues = z.infer<typeof schema>;
const examples = [
  "URGENT: Your account will be suspended today. Verify your details at https://account-check.example now.",
  "Hi, the meeting notes are ready. I have attached the agenda for tomorrow.",
];

export default function MessageAnalysisPage() {
  const [result, setResult] = useState<MessageAnalysisResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const { register, handleSubmit, setValue, watch, formState: { errors } } = useForm<FormValues>({ resolver: zodResolver(schema), defaultValues: { message: "" } });
  const value = watch("message");
  const submit = handleSubmit(async ({ message }) => {
    setLoading(true); setErrorMessage("");
    try { setResult(await analyzeMessage({ message })); }
    catch (error) { setErrorMessage(error instanceof Error ? error.message : "Analysis failed."); }
    finally { setLoading(false); }
  });
  const copy = async (item: string) => {
    try { await navigator.clipboard.writeText(item); setErrorMessage("Copied to clipboard."); }
    catch { setErrorMessage("Clipboard access is unavailable in this browser."); }
  };
  return <div>
    <PageHeading eyebrow="Social engineering signals" title="Analyze a message" description="Review language patterns and extracted indicators. Automated language signals do not prove that a message is fraudulent."/>
    <div className="grid gap-4 xl:grid-cols-[1.08fr_.92fr]">
      <form onSubmit={submit} className="panel p-5">
        <div className="flex items-center justify-between"><label htmlFor="message" className="text-xs font-semibold text-slate-200">Suspicious message</label><span className="text-[10px] text-slate-600">{value?.length ?? 0}/10,000</span></div>
        <textarea id="message" {...register("message")} rows={11} placeholder="Paste an email, text message, or social post here…" className="field mt-3 resize-y px-3.5 py-3 text-xs leading-6" aria-invalid={Boolean(errors.message)}/>
        {errors.message && <p role="alert" className="mt-2 text-[10px] text-rose-300">{errors.message.message}</p>}
        <div className="mt-3 flex flex-wrap items-center gap-2"><span className="mr-1 text-[10px] text-slate-600">Try a sample:</span>{examples.map((example, i) => <button key={example} type="button" onClick={() => setValue("message", example)} className="rounded border border-[#26343f] px-2 py-1 text-[9px] text-slate-400 hover:text-white">Example {i + 1}</button>)}</div>
        <button type="submit" disabled={loading} className="btn-primary mt-5 w-full text-xs">{loading ? <><LoaderCircle size={15} className="animate-spin"/> Analyzing</> : <>Analyze message <ArrowRight size={14}/></>}</button>
        <p className="mt-3 flex items-start gap-2 text-[10px] leading-5 text-slate-600"><ShieldAlert size={13} className="mt-0.5 shrink-0"/> Never submit passwords, one-time codes, payment details, private keys, or recovery phrases.</p>
        {errorMessage && <p role="status" className="mt-3 text-[10px] text-cyan-100">{errorMessage}</p>}
      </form>
      {loading ? <div className="panel flex min-h-80 items-center justify-center"><div className="text-center"><LoaderCircle className="mx-auto animate-spin text-cyan-200" size={22}/><div className="mt-3 text-xs text-slate-300">Reviewing message signals</div><div className="mt-1 text-[10px] text-slate-600">Demonstration analysis</div></div></div> :
      result ? <section className="space-y-4">
        <div className="rounded-lg border border-amber-300/20 bg-amber-300/[.04] px-4 py-3 text-[10px] leading-5 text-amber-100/80"><strong className="text-amber-100">Demonstration output.</strong> Heuristics are illustrative, not verified evidence about a sender.</div>
        <div className="panel p-5"><div className="eyebrow">Overall assessment</div><div className="mt-3 flex items-center justify-between"><RiskBadge level={result.risk.level}/><span className="font-mono text-lg text-slate-200">{result.risk.score}<span className="text-[10px] text-slate-600"> / 100</span></span></div><p className="mt-3 text-[10px] leading-5 text-slate-500">{result.risk.explanation}</p></div>
        <div className="panel p-5"><div className="flex items-center gap-2"><Sparkles size={14} className="text-violet-300"/><div className="section-title">Language indicators</div></div><div className="mt-1 text-[9px] uppercase tracking-wider text-violet-200/70">AI-style observations · independently unverified</div><div className="mt-4 space-y-3">{result.indicators.map((item) => <div key={item.title} className="border-b border-[#202d38] pb-3 last:border-0 last:pb-0"><div className="flex items-center justify-between gap-2"><div className="text-[11px] text-slate-300">{item.title}</div><SeverityBadge severity={item.severity}/></div><p className="mt-1 text-[10px] leading-5 text-slate-500">{item.detail}</p></div>)}</div></div>
        <div className="panel p-5"><div className="flex items-center gap-2"><Mail size={14} className="text-cyan-200"/><div className="section-title">Extracted indicators</div></div><div className="mt-4 space-y-3">{[["URLs", result.urls], ["Email addresses", result.emails], ["Phone numbers", result.phones]].map(([label, items]) => <div key={label as string} className="flex items-start justify-between gap-3 border-b border-[#1c2731] pb-2 last:border-0 last:pb-0"><div className="min-w-[94px] text-[10px] text-slate-600">{label as string}</div><div className="flex flex-1 flex-wrap justify-end gap-1">{(items as string[]).length ? (items as string[]).map((item) => <button key={item} title="Copy indicator" onClick={() => void copy(item)} className="break-all rounded bg-[#17212b] px-2 py-1 font-mono text-[9px] text-slate-300 hover:text-cyan-100">{item}<Clipboard className="ml-1 inline" size={10}/></button>) : <span className="text-[10px] text-slate-700">None extracted</span>}</div></div>)}</div></div>
        <div className="panel p-5"><div className="flex items-center gap-2"><AlertTriangle size={14} className="text-amber-200"/><div className="section-title">Safety guidance</div></div><p className="mt-2 text-[10px] leading-5 text-slate-500">{result.explanation}</p><ul className="mt-3 space-y-2">{result.safetyMeasures.map((measure) => <li key={measure} className="flex gap-2 text-[10px] leading-5 text-slate-400"><Check size={12} className="mt-0.5 shrink-0 text-emerald-300"/>{measure}</li>)}</ul></div>
      </section> :
      <div className="panel flex min-h-80 flex-col items-center justify-center px-6 text-center"><div className="flex h-10 w-10 items-center justify-center rounded-full border border-[#2a3945] text-slate-500"><MessageSquareText size={17}/></div><div className="mt-4 text-xs font-medium text-slate-300">Analysis will appear here</div><p className="mt-2 max-w-xs text-[10px] leading-5 text-slate-600">Your message is only interpreted by this demo. Avoid sharing sensitive or identifying content.</p></div>}
    </div>
  </div>;
}
