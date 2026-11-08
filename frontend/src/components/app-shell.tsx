"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";
import {
  Activity, ArrowUpRight, BadgeCheck, Bell, ChevronLeft, ChevronRight,
  LayoutDashboard, LockKeyhole, Menu, MessageSquareText, Radar,
  Settings2, Shield, X,
} from "lucide-react";

const nav = [
  { title: "Workspace", links: [
    { label: "Overview", href: "/dashboard", icon: LayoutDashboard },
    { label: "URL investigation", href: "/investigate", icon: Radar },
    { label: "Message analysis", href: "/message-analysis", icon: MessageSquareText },
    { label: "Security assessment", href: "/security-assessment", icon: Shield },
  ] },
  { title: "Intelligence", links: [
    { label: "Threat intelligence", href: "/threat-intelligence", icon: Activity },
    { label: "Report verification", href: "/verify", icon: BadgeCheck },
  ] },
];

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const isLanding = pathname === "/";
  const sidebar = (
    <aside className={`fixed inset-y-0 left-0 z-40 flex w-[248px] flex-col border-r border-[#1d2934] bg-[#0b1118] transition-transform md:translate-x-0 ${mobileOpen ? "translate-x-0" : "-translate-x-full"} ${collapsed ? "md:w-[76px]" : ""}`}>
      <div className="flex h-[68px] items-center gap-3 border-b border-[#1d2934] px-5">
        <div className="flex h-8 w-8 items-center justify-center rounded-lg border border-cyan-300/20 bg-cyan-300/10 text-cyan-200"><Shield size={17} /></div>
        {!collapsed && <div><div className="text-[15px] font-bold tracking-[.12em] text-slate-100">BOUCLIER</div><div className="mt-0.5 text-[9px] tracking-[.13em] text-slate-500">TRUST INTELLIGENCE</div></div>}
        <button onClick={() => setMobileOpen(false)} aria-label="Close navigation" className="ml-auto text-slate-500 md:hidden"><X size={18}/></button>
      </div>
      <div className="px-3 pt-5">
        {!collapsed && <div className="mb-2 px-3 text-[10px] font-bold uppercase tracking-[.13em] text-slate-600">Platform</div>}
        {nav.map((section) => <div key={section.title} className="mb-6">
          {!collapsed && <div className="mb-2 px-3 text-[10px] font-bold uppercase tracking-[.13em] text-slate-600">{section.title}</div>}
          {section.links.map(({ label, href, icon: Icon }) => {
            const active = pathname === href;
            return <Link key={href} href={href} title={collapsed ? label : undefined} onClick={() => setMobileOpen(false)} className={`mb-1 flex items-center gap-3 rounded-lg px-3 py-2.5 text-[12px] font-medium transition ${active ? "border border-cyan-300/10 bg-cyan-300/[.08] text-cyan-100" : "text-slate-400 hover:bg-white/[.04] hover:text-slate-100"}`}>
              <Icon size={16} strokeWidth={1.8}/>{!collapsed && <span>{label}</span>}
              {active && !collapsed && <span className="ml-auto h-1.5 w-1.5 rounded-full bg-cyan-300"/>}
            </Link>;
          })}
        </div>)}
      </div>
      <div className="mt-auto p-3">
        <Link href="/settings" title={collapsed ? "Settings" : undefined} className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-xs text-slate-400 hover:bg-white/[.04] hover:text-slate-100 ${pathname === "/settings" ? "bg-white/[.04] text-white" : ""}`}><Settings2 size={16}/>{!collapsed && "Settings"}</Link>
        {!collapsed && <div className="mt-4 rounded-lg border border-[#263541] bg-[#101923] p-3">
          <div className="flex items-center gap-2 text-[11px] font-semibold text-slate-200"><LockKeyhole size={13} className="text-emerald-300"/> Private workspace</div>
          <p className="mt-1.5 text-[10px] leading-4 text-slate-500">Demo mode is active. No live checks are being run.</p>
        </div>}
        <button onClick={() => setCollapsed(!collapsed)} aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"} className="mt-3 hidden w-full items-center justify-center rounded-md py-2 text-slate-600 hover:bg-white/[.04] hover:text-slate-300 md:flex">{collapsed ? <ChevronRight size={16}/> : <><ChevronLeft size={16}/><span className="ml-1 text-[10px]">Collapse</span></>}</button>
      </div>
    </aside>
  );

  if (isLanding) return <>{children}</>;
  return <div className="min-h-screen">
    {sidebar}
    {mobileOpen && <button aria-label="Close navigation overlay" onClick={() => setMobileOpen(false)} className="fixed inset-0 z-30 bg-black/65 md:hidden"/>}
    <div className={`min-h-screen transition-[padding] ${collapsed ? "md:pl-[76px]" : "md:pl-[248px]"}`}>
      <header className="sticky top-0 z-20 flex h-[68px] items-center justify-between border-b border-[#1d2934] bg-[#080d13]/90 px-4 backdrop-blur-xl sm:px-7">
        <div className="flex items-center gap-3">
          <button onClick={() => setMobileOpen(true)} aria-label="Open navigation" className="text-slate-300 md:hidden"><Menu size={19}/></button>
          <div className="hidden items-center gap-2 text-[11px] text-slate-500 sm:flex"><span>Bouclier</span><span>/</span><span className="text-slate-300">{nav.flatMap((group) => group.links).find((link) => link.href === pathname)?.label ?? "Settings"}</span></div>
          <span className="sm:hidden text-[12px] font-semibold tracking-widest text-slate-200">BOUCLIER</span>
        </div>
        <div className="flex items-center gap-3">
          <span className="hidden items-center gap-1.5 rounded-full border border-amber-400/20 bg-amber-400/[.06] px-2.5 py-1 text-[10px] font-semibold text-amber-200 sm:inline-flex"><span className="h-1.5 w-1.5 rounded-full bg-amber-300"/> DEMO ENVIRONMENT</span>
          <Link href="/verify" aria-label="Verify reports" className="rounded-md p-2 text-slate-400 hover:bg-white/[.05] hover:text-white"><Bell size={16}/></Link>
          <div className="flex h-7 w-7 items-center justify-center rounded-full border border-[#344554] bg-[#192631] text-[10px] font-semibold text-cyan-100">B</div>
        </div>
      </header>
      <main className="mx-auto w-full max-w-[1440px] px-4 py-7 sm:px-7 lg:px-9">{children}</main>
      <footer className="mx-auto flex max-w-[1440px] items-center justify-between border-t border-[#1b2630] px-4 py-4 text-[10px] text-slate-600 sm:px-7 lg:px-9"><span>BOUCLIER · DIGITAL TRUST INTELLIGENCE</span><Link href="/" className="flex items-center gap-1 hover:text-slate-300">Public site <ArrowUpRight size={11}/></Link></footer>
    </div>
  </div>;
}
