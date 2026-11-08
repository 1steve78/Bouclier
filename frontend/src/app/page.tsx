import Link from "next/link";
import { ArrowDown, ArrowRight, BadgeCheck, Fingerprint, Globe2, ScanSearch, Shield, ShieldCheck, Sparkles } from "lucide-react";

const capabilities = [
  { icon: ScanSearch, title: "URL intelligence", copy: "Unpack domains, redirects, and suspicious URL patterns with evidence you can inspect." },
  { icon: Sparkles, title: "Message analysis", copy: "Surface social-engineering signals and separate language observations from verified facts." },
  { icon: ShieldCheck, title: "Security assessment", copy: "Review TLS and public security configuration without implying a penetration test." },
  { icon: Globe2, title: "Threat intelligence", copy: "Bring reports and known indicators together with clear source and verification context." },
  { icon: Fingerprint, title: "Verifiable reports", copy: "Explore how cryptographic commitments can make report integrity independently checkable." },
];

export default function HomePage() {
  return <div className="min-h-screen overflow-hidden">
    <header className="mx-auto flex h-[74px] max-w-7xl items-center justify-between px-5 sm:px-8">
      <Link href="/" className="flex items-center gap-3"><span className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-300/20 bg-cyan-300/[.08] text-cyan-200"><Shield size={18}/></span><span className="text-sm font-bold tracking-[.15em]">BOUCLIER</span></Link>
      <nav className="hidden items-center gap-8 text-xs text-slate-400 md:flex"><a href="#platform" className="hover:text-white">Platform</a><a href="#how-it-works" className="hover:text-white">How it works</a><Link href="/verify" className="hover:text-white">Verification</Link></nav>
      <Link href="/dashboard" className="btn-secondary px-3 py-2 text-[11px]">Open workspace <ArrowRight size={13}/></Link>
    </header>
    <main>
      <section className="grid-line relative px-5 pb-24 pt-16 sm:px-8 sm:pt-24 lg:pb-32 lg:pt-28">
        <div className="absolute left-1/2 top-0 h-[460px] w-[760px] -translate-x-1/2 rounded-full bg-cyan-300/[.045] blur-[120px]"/>
        <div className="relative mx-auto max-w-5xl text-center">
          <span className="inline-flex items-center gap-2 rounded-full border border-[#293a46] bg-[#0d151c]/80 px-3 py-1.5 text-[10px] font-semibold tracking-[.11em] text-cyan-100"><span className="h-1.5 w-1.5 rounded-full bg-emerald-300"/> DIGITAL TRUST INTELLIGENCE</span>
          <h1 className="mx-auto mt-7 max-w-4xl text-4xl font-semibold leading-[1.08] tracking-[-.055em] text-white sm:text-6xl lg:text-[72px]">See the threat before<br className="hidden sm:block"/> it reaches you.</h1>
          <p className="mx-auto mt-6 max-w-xl text-sm leading-7 text-slate-400 sm:text-base">Investigate suspicious digital signals. Understand the evidence. Verify what you can trust.</p>
          <form action="/investigate" className="mx-auto mt-9 flex max-w-2xl flex-col gap-2 rounded-xl border border-[#293743] bg-[#0d151d]/90 p-2 shadow-[0_20px_80px_rgba(0,0,0,.32)] sm:flex-row">
            <label htmlFor="hero-url" className="sr-only">URL to investigate</label>
            <input id="hero-url" name="url" type="text" placeholder="Paste a URL or domain to investigate" className="field min-w-0 flex-1 border-0 bg-transparent px-4 py-3 text-sm shadow-none focus:shadow-none" autoComplete="url"/>
            <button type="submit" className="btn-primary px-5 py-3 text-xs">Investigate <ArrowRight size={15}/></button>
          </form>
          <div className="mt-4 text-[10px] text-slate-600">Never visit a submitted website automatically. Demonstration data is clearly labeled.</div>
          <Link href="/dashboard" className="mt-8 inline-flex items-center gap-2 text-xs text-slate-400 hover:text-cyan-100">Explore the platform <ArrowDown size={13}/></Link>
        </div>
        <div className="relative mx-auto mt-16 max-w-4xl">
          <div className="panel overflow-hidden p-4 sm:p-5">
            <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[#202d38] pb-4">
              <div><div className="eyebrow">Sample investigation · demonstration</div><div className="mt-2 font-mono text-xs text-slate-300">accounts-micros0ft.example</div></div>
              <span className="rounded-full border border-orange-400/25 bg-orange-400/[.08] px-3 py-1 text-[10px] font-semibold text-orange-200">HIGH RISK · SAMPLE</span>
            </div>
            <div className="grid gap-5 pt-5 sm:grid-cols-[1fr_1.7fr]">
              <div className="flex items-center gap-4 rounded-lg border border-[#22303a] bg-[#0a1118] p-4">
                <div className="relative flex h-[72px] w-[72px] items-center justify-center rounded-full border-[5px] border-orange-400/50 text-xl font-semibold text-orange-200">82<span className="absolute inset-[-5px] rounded-full border-[5px] border-transparent border-t-orange-300/90 -rotate-45"/></div>
                <div><div className="text-xs font-semibold text-white">Risk score</div><div className="mt-1 text-[10px] text-slate-500">Illustrative, not a live result</div></div>
              </div>
              <div className="grid gap-2 sm:grid-cols-3">
                {["Domain signals", "TLS posture", "Threat feeds"].map((item, index) => <div key={item} className="rounded-lg border border-[#202d38] bg-[#0a1118] p-3"><div className="flex items-center gap-2 text-[10px] text-slate-500"><span className={`h-1.5 w-1.5 rounded-full ${index === 0 ? "bg-orange-300" : "bg-slate-600"}`}/>{item}</div><div className="mt-4 text-xs font-medium text-slate-200">{index === 0 ? "Lookalike pattern" : index === 1 ? "Not independently checked" : "Unavailable in demo"}</div></div>)}
              </div>
            </div>
          </div>
        </div>
      </section>
      <section id="platform" className="mx-auto max-w-7xl px-5 py-20 sm:px-8 lg:py-24">
        <div className="max-w-xl"><div className="eyebrow">One connected workspace</div><h2 className="mt-3 text-3xl font-semibold tracking-[-.04em] text-slate-100">A clearer view of digital risk.</h2><p className="mt-4 text-sm leading-6 text-slate-400">Technical evidence and human-readable context, without overstating what automated checks can tell you.</p></div>
        <div className="mt-10 grid gap-3 sm:grid-cols-2 lg:grid-cols-3">{capabilities.map(({ icon: Icon, title, copy }, index) => <article key={title} className={`panel group p-5 transition hover:border-[#3a505e] ${index === 4 ? "lg:col-span-1" : ""}`}><div className="mb-5 flex h-9 w-9 items-center justify-center rounded-md border border-cyan-200/10 bg-cyan-200/[.05] text-cyan-200"><Icon size={17}/></div><h3 className="text-sm font-semibold text-slate-100">{title}</h3><p className="mt-2 text-xs leading-5 text-slate-500">{copy}</p></article>)}</div>
      </section>
      <section id="how-it-works" className="border-y border-[#1d2934] bg-[#0b1118] px-5 py-16 sm:px-8">
        <div className="mx-auto max-w-7xl"><div className="eyebrow">How Bouclier works</div><div className="mt-3 flex flex-wrap items-end justify-between gap-4"><h2 className="text-3xl font-semibold tracking-[-.04em]">From signal to understanding.</h2><p className="max-w-sm text-xs leading-5 text-slate-500">Every result should show what was checked, what was not, and why that matters.</p></div>
          <div className="mt-10 grid gap-3 sm:grid-cols-5">{["Submit", "Investigate", "Analyse", "Assess risk", "Verify"].map((item, index) => <div key={item} className="relative border-l border-[#2b3a45] pl-4 sm:border-l-0 sm:border-t sm:pl-0 sm:pt-4"><div className="absolute -left-[4px] top-0 h-2 w-2 rounded-full bg-cyan-300 sm:left-0 sm:top-[-4px]"/><div className="font-mono text-[10px] text-cyan-200">0{index + 1}</div><div className="mt-2 text-xs font-semibold text-slate-200">{item}</div></div>)}</div>
        </div>
      </section>
      <section className="mx-auto grid max-w-7xl gap-10 px-5 py-20 sm:px-8 lg:grid-cols-2 lg:items-center lg:py-24">
        <div><div className="eyebrow">Evidence, not exaggeration</div><h2 className="mt-3 max-w-lg text-3xl font-semibold leading-tight tracking-[-.04em]">Security checks should explain their limits.</h2><p className="mt-4 max-w-lg text-sm leading-6 text-slate-400">A valid certificate is not a safety guarantee. A clean feed lookup is not proof of legitimacy. Bouclier is designed to make confidence and gaps visible.</p><div className="mt-6 flex items-start gap-3 text-xs leading-5 text-slate-300"><BadgeCheck size={16} className="mt-0.5 shrink-0 text-emerald-300"/> Reports can be anchored to a cryptographic commitment for independent integrity checks.</div></div>
        <div className="panel p-5"><div className="flex items-center justify-between"><span className="eyebrow">Verification lifecycle</span><span className="rounded-full border border-slate-600/30 bg-slate-400/[.06] px-2 py-1 text-[9px] text-slate-400">CONCEPT</span></div><div className="mt-6 space-y-4">{[["01", "Report is created", "Analysis evidence is assembled into a structured report."], ["02", "Hash is committed", "A cryptographic digest can be published to a supported network."], ["03", "Integrity is checked", "A verifier recomputes and compares the report commitment."]].map(([n, title, copy]) => <div key={n} className="flex gap-4 border-b border-[#202d38] pb-4 last:border-0 last:pb-0"><span className="font-mono text-[10px] text-cyan-200">{n}</span><div><div className="text-xs font-semibold text-slate-200">{title}</div><div className="mt-1 text-[11px] leading-5 text-slate-500">{copy}</div></div></div>)}</div></div>
      </section>
    </main>
    <footer className="border-t border-[#1d2934] px-5 py-7 sm:px-8"><div className="mx-auto flex max-w-7xl flex-col justify-between gap-4 sm:flex-row sm:items-center"><div className="text-[10px] text-slate-600">© 2026 BOUCLIER · INVESTIGATE. UNDERSTAND. VERIFY.</div><div className="flex flex-wrap gap-5 text-[10px] text-slate-500"><Link href="/dashboard" className="hover:text-white">Workspace</Link><Link href="/investigate" className="hover:text-white">URL investigation</Link><Link href="/verify" className="hover:text-white">Report verification</Link><a href="https://github.com/1steve78/Bouclier" target="_blank" rel="noreferrer" className="hover:text-white">GitHub</a></div></div></footer>
  </div>;
}
