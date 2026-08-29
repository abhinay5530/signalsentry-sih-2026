import { Link, NavLink, Outlet } from "react-router-dom";
import {
  Activity,
  BookOpen,
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
  { to: "/guide", label: "User Guide", icon: BookOpen },
];

export default function Shell() {
  return (
    <div className="min-h-screen flex flex-col md:flex-row bg-soc-bg">
      <aside className="md:w-60 md:h-screen md:sticky md:top-0 shrink-0 border-b md:border-b-0 md:border-r border-soc-border bg-[#0a111a] flex flex-col">
        <div className="px-4 py-4 md:py-5 border-b border-soc-border">
          <Link to="/" className="flex items-center gap-2.5">
            <span className="flex h-9 w-9 items-center justify-center rounded-md border border-soc-cyan/35 bg-soc-cyan/10 text-soc-cyan">
              <Shield size={17} strokeWidth={1.75} />
            </span>
            <div>
              <div className="text-[14px] font-semibold tracking-[0.04em] text-slate-50">SignalSentry</div>
              <div className="text-[11px] text-soc-muted font-mono mt-0.5">Investigation console</div>
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
                `flex items-center gap-2.5 px-2.5 py-2 rounded-md text-[14px] whitespace-nowrap shrink-0 border-l-2 ${
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
        <div className="hidden md:block p-3.5 text-[11px] leading-relaxed text-soc-muted font-mono border-t border-soc-border">
          Straw Hats · SIH 2026
        </div>
      </aside>
      <main className="flex-1 min-w-0 flex flex-col">
        <header className="h-12 shrink-0 border-b border-soc-border flex items-center gap-3 px-4 md:px-6 text-[12px] text-soc-muted bg-[#080d14]">
          <span className="flex items-center gap-2 min-w-0">
            <Activity size={13} className="text-soc-cyan shrink-0" />
            <span className="truncate font-mono tracking-wide">
              INGEST → NORMALIZE → DETECT → CORRELATE → INVESTIGATE
            </span>
          </span>
        </header>
        <div className="flex-1 p-4 md:p-6 lg:p-8">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
