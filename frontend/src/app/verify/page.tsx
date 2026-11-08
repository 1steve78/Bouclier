"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { AlertCircle, ArrowRight, BadgeCheck, Clipboard, Fingerprint, LoaderCircle } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { PageHeading } from "@/components/page-heading";
import { verifyThreatReport } from "@/lib/api/services";
import type { BlockchainVerificationResult } from "@/lib/types";

const schema = z.object({ identifier: z.string().trim().min(8, "Enter a report ID, SHA-256 hash, or transaction hash.").max(256, "Identifier must be under 256 characters.") });
type FormValues = z.infer<typeof schema>;

export default function VerifyPage() {
  const [result, setResult] = useState<BlockchainVerificationResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");
  const { register, handleSubmit, setValue, formState: { errors } } = useForm<FormValues>({ resolver: zodResolver(schema), defaultValues: { identifier: "" } });
  const submit = handleSubmit(async ({ identifier }) => {
    setLoading(true); setErrorMessage("");
    try { setResult(await verifyThreatReport(identifier)); }
    catch (error) { setErrorMessage(error instanceof Error ? error.message : "Verification request failed."); }
    finally { setLoading(false); }
  });
  return <div>
    <PageHeading eyebrow="Integrity and provenance" title="Verify a report" description="Check a report identifier or cryptographic commitment. Verification is unavailable until a backend and chain integration are configured."/>
    <div className="grid gap-4 lg:grid-cols-[.9fr_1.1fr]">
      <form onSubmit={submit} className="panel p-5"><label htmlFor="identifier" className="text-xs font-semibold text-slate-200">Report ID, SHA-256 hash, or transaction hash</label><input id="identifier" {...register("identifier")} className="field mt-3 px-3 py-3 font-mono text-[11px]" placeholder="Enter an identifier to check" aria-invalid={Boolean(errors.identifier)}/>{errors.identifier && <div role="alert" className="mt-2 text-[10px] text-rose-300">{errors.identifier.message}</div>}<button disabled={loading} className="btn-primary mt-3 w-full text-xs">{loading ? <><LoaderCircle size={14} className="animate-spin"/> Checking</> : <>Check report <ArrowRight size={14}/></>}</button><p className="mt-4 text-[10px] leading-5 text-slate-600">This UI does not connect to a wallet or require private keys, seed phrases, or signatures.</p>{errorMessage && <p role="alert" className="mt-3 text-[10px] text-rose-300">{errorMessage}</p>}</form>
      <div className="panel p-5">
        {!result && !loading && <div className="flex min-h-64 flex-col items-center justify-center text-center"><div className="flex h-11 w-11 items-center justify-center rounded-full border border-[#2c3b47] text-cyan-200"><Fingerprint size={19}/></div><div className="mt-4 text-sm font-medium text-slate-300">Verification result</div><p className="mt-2 max-w-sm text-[10px] leading-5 text-slate-600">A report can be hashed and its digest compared with an independently published commitment. No successful verification is simulated here.</p><button onClick={() => setValue("identifier", "demo-report-8F2A91")} className="mt-4 text-[10px] text-cyan-200 hover:text-cyan-100">Use demonstration identifier</button></div>}
        {loading && <div className="flex min-h-64 items-center justify-center"><div className="text-center"><LoaderCircle size={21} className="mx-auto animate-spin text-cyan-200"/><div className="mt-3 text-xs text-slate-300">Checking report availability</div></div></div>}
        {result && !loading && <div><div className="flex items-center gap-3"><span className="flex h-9 w-9 items-center justify-center rounded-full border border-slate-500/30 bg-slate-500/10 text-slate-300"><AlertCircle size={17}/></span><div><div className="text-sm font-semibold text-slate-200">Verification unavailable</div><div className="mt-1 text-[10px] text-slate-500">No live lookup was performed</div></div></div><div className="mt-4 rounded-md border border-amber-300/15 bg-amber-300/[.04] px-3 py-2.5 text-[10px] leading-5 text-amber-100/75"><strong className="text-amber-100">Demo mode.</strong> This result is not a successful verification and makes no claim about report integrity.</div><div className="mt-5 space-y-4">{[["Lookup input", result.reportId], ["Report hash", result.reportHash], ["Transaction hash", result.transactionHash], ["Smart contract", result.contractAddress], ["Network", result.network], ["Block number", "Not available"], ["Timestamp", "Not available"]].map(([label, value]) => <div key={label} className="flex flex-col justify-between gap-1 border-b border-[#202d38] pb-3 sm:flex-row sm:items-center"><span className="text-[10px] text-slate-600">{label}</span><span className="break-all font-mono text-[10px] text-slate-400">{value}{value === result.reportId && <button aria-label="Copy identifier" onClick={() => navigator.clipboard?.writeText(value)} className="ml-2 text-slate-500 hover:text-cyan-100"><Clipboard size={11}/></button>}</span></div>)}</div></div>}
      </div>
    </div>
    <section className="panel mt-4 p-5"><div className="flex items-center gap-2"><BadgeCheck size={15} className="text-cyan-200"/><div className="section-title">How report integrity works</div></div><div className="mt-4 grid gap-4 sm:grid-cols-3">{[["Create a digest", "A cryptographic hash acts as a compact fingerprint of report contents."], ["Publish a commitment", "A supported system can record the digest with a timestamp and transaction."], ["Recompute and compare", "A verifier recalculates the digest and compares it with the published commitment."]].map(([title, copy], i) => <div key={title} className="rounded-md border border-[#202d38] bg-[#0a1118] p-3"><div className="font-mono text-[10px] text-cyan-200">0{i + 1}</div><div className="mt-2 text-[11px] font-semibold text-slate-300">{title}</div><p className="mt-1 text-[10px] leading-5 text-slate-600">{copy}</p></div>)}</div><p className="mt-4 text-[10px] leading-5 text-slate-600">A matching hash can show that the compared content has not changed since commitment. It does not prove that the original analysis was accurate or the report source was trustworthy.</p></section>
  </div>;
}
