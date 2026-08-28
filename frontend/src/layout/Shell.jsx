import { Link, NavLink, Outlet } from "react-router-dom";
import {
  Activity,
  Crosshair,
  Database,
  FileSearch,
  LayoutDashboard,
  Network,
  Radio,
  Shield,
} from "lucide-react";

const links = [
  { to: "/dashboard", label: "Command Center", icon: LayoutDashboard },
  { to: "/ipdr", label: "IPDR Explorer", icon: Database },
  { to: "/attacks", label: "Attack Explorer", icon: Crosshair },
  { to: "/pcap", label: "PCAP Analyzer", icon: Radio },
  { to: "/investigate", label: "IP Investigate", icon: Network },
  { to: "/reports", label: "Reports", icon: FileSearch },
];

export default function Shell() {
  return (
    <div className="min-h-screen flex flex-col md:flex-row bg-soc-bg">
      <aside className="md:w-56 md:h-screen md:sticky md:top-0 shrink-0 border-b md:border-b-0 md:border-r border-soc-border bg-[#0a111a] flex flex-col">
        <div className="px-4 py-4 md:py-5 border-b border-soc-border">
          <Link to="/" className="flex items-center gap-2.5">
            <span className="flex h-8 w-8 items-center justify-center rounded-md border border-soc-cyan/30 bg-soc-cyan/10 text-soc-cyan">
              <Shield size={16} strokeWidth={1.75} />
            </span>
            <div>
              <div className="text-[13px] font-semibold tracking-[0.06em] text-slate-100">SignalSentry</div>
              <div className="text-[10px] text-soc-muted font-mono mt-0.5">Detect. Correlate. Investigate.</div>
            </div>
          </Link>
        </div>
        <nav className="p-2 md:p-2.5 flex-1 flex md:flex-col gap-0.5 overflow-x-auto md:overflow-visible">
          {links.map(({ to, label, icon: Icon }) => (
            <NavLink
              key={to}
              to={to}
              end={to === "/dashboard"}
              className={({ isActive }) =>
                `flex items-center gap-2.5 px-2.5 py-2 rounded-md text-[13px] whitespace-nowrap shrink-0 border-l-2 ${
                  isActive
                    ? "border-soc-cyan bg-soc-cyan/[0.08] text-soc-cyan"
                    : "border-transparent text-slate-400 hover:bg-white/[0.04] hover:text-slate-200"
                }`
              }
            >
              <Icon size={15} strokeWidth={1.75} />
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="hidden md:block p-3.5 text-[10px] leading-relaxed text-soc-muted font-mono border-t border-soc-border">
          SignalSentry · Straw Hats
          <br />
          Local prototype
          <br />
          No live intel · HTTPS not decrypted
        </div>
      </aside>
      <main className="flex-1 min-w-0 flex flex-col">
        <header className="h-11 shrink-0 border-b border-soc-border flex items-center justify-between gap-3 px-4 md:px-6 text-[11px] text-soc-muted bg-[#080d14]/80">
          <span className="flex items-center gap-2 min-w-0">
            <Activity size={13} className="text-soc-cyan shrink-0" />
          <span className="truncate">INGEST → NORMALIZE → DETECT → CORRELATE → INVESTIGATE</span>
          </span>
          <span className="font-mono shrink-0 text-slate-500">127.0.0.1 · SQLite</span>
        </header>
        <div className="flex-1 p-4 md:p-6 lg:p-7">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
