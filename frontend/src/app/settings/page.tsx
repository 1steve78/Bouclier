import { Bell, Database, LockKeyhole, Settings2 } from "lucide-react";
import { PageHeading } from "@/components/page-heading";

export default function SettingsPage() {
  return <div>
    <PageHeading eyebrow="Workspace preferences" title="Settings" description="Frontend demonstration settings. Account, notification, and API configuration are not connected to a live service."/>
    <div className="max-w-3xl space-y-3">
      {[["Workspace", Settings2, "BOUCLIER DEMO", "Local presentation workspace"], ["API connection", Database, "Mock services active", "NEXT_PUBLIC_API_BASE_URL is reserved for the documented Go API integration."], ["Privacy", LockKeyhole, "No credentials requested", "Do not enter passwords, one-time codes, private keys, or recovery phrases."], ["Notifications", Bell, "Not configured", "No operational alerts are sent by this frontend."]].map(([title, Icon, value, detail]) => {
        const Symbol = Icon as typeof Settings2;
        return <section key={title as string} className="panel flex items-start gap-4 p-5"><span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-[#293944] bg-[#121c24] text-cyan-200"><Symbol size={16}/></span><div className="min-w-0 flex-1"><div className="text-xs font-semibold text-slate-200">{title as string}</div><div className="mt-2 text-[11px] text-cyan-100">{value as string}</div><p className="mt-1 text-[10px] leading-5 text-slate-600">{detail as string}</p></div></section>;
      })}
    </div>
  </div>;
}
