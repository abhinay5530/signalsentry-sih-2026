import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";
import { Crosshair, Database, FileJson, FileSearch, GitBranch, Network, Shield } from "lucide-react";
import { api } from "../api";

/** Replace when the public GitHub URL is confirmed. */
const GITHUB_URL = "https://github.com/abhinay5530/signalsentry-sih-2026";

const tooltipStyle = { background: "#0d1522", border: "1px solid #1c2a3d", fontSize: 12 };

const features = [
  {
    title: "Attack Detection",
    icon: Crosshair,
    text: "Rule families on normalized HTTP/URL fields, plus simple behavior checks. Not live threat intelligence.",
  },
  {
    title: "Evidence Correlation",
    icon: GitBranch,
    text: "Related events and HTTP metadata are combined into ATTEMPT, CONFIRMED, or UNKNOWN heuristics.",
  },
  {
    title: "IP/CIDR Investigation",
    icon: Network,
    text: "Look up a source or destination IPv4 or CIDR (demo range 10.50.1.0/24) and inspect related activity.",
  },
  {
    title: "PCAP/IPDR Analysis",
    icon: Database,
    text: "Ingest IPDR-like CSV/JSON or PCAP/PCAPNG. HTTPS paths are not invented from encrypted payloads.",
  },
  {
    title: "Explainable Verdicts",
    icon: FileSearch,
    text: "Each finding shows detectors, evidence snippets, and HTTP context already in the ingested record.",
  },
  {
    title: "CSV/JSON Reports",
    icon: FileJson,
    text: "Export the current filtered detections joined to events for offline review.",
  },
];

const steps = ["INGEST", "NORMALIZE", "DETECT", "CORRELATE", "INVESTIGATE"];

export default function Landing() {
  const [ov, setOv] = useState(null);
  const [apiErr, setApiErr] = useState("");

  useEffect(() => {
    api
      .overview()
      .then((d) => {
        setOv(d);
        setApiErr("");
      })
      .catch((e) => setApiErr(e.message));
  }, []);

  const hasData = ov && ov.events;

  return (
    <div className="min-h-screen bg-soc-bg text-slate-200 flex flex-col">
      <header className="border-b border-soc-border px-5 md:px-10 h-12 flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <span className="flex h-7 w-7 items-center justify-center rounded-md border border-soc-cyan/30 bg-soc-cyan/10 text-soc-cyan">
            <Shield size={15} strokeWidth={1.75} />
          </span>
          <span className="text-sm font-semibold tracking-[0.04em]">SignalSentry</span>
        </div>
        <Link to="/dashboard" className="si-btn-primary !py-1.5 !text-xs">
          Launch Dashboard
        </Link>
      </header>

      <main className="flex-1 max-w-5xl w-full mx-auto px-5 md:px-8 py-14 md:py-20 space-y-14">
        <section className="max-w-2xl">
          <p className="text-[11px] font-mono uppercase tracking-[0.18em] text-soc-cyan">Team Straw Hats · SIH 2026</p>
          <h1 className="mt-4 text-4xl md:text-[2.5rem] font-semibold tracking-tight text-slate-50 leading-tight">
            SignalSentry
          </h1>
          <p className="mt-3 text-soc-cyan font-mono text-[15px] md:text-base tracking-wide">
            IPDR &amp; PCAP URL-Attack Investigation
          </p>
          <p className="mt-4 text-[15px] text-soc-muted leading-relaxed">
            A local investigation workspace for URL-based attacks in IPDR-like records and packet captures. Heuristic
            findings from ingested data — not an ISP feed, not HTTPS decryption, not live intel.
          </p>
          <div className="mt-8 flex flex-wrap gap-3">
            <Link to="/dashboard" className="si-btn-primary px-5 py-2.5">
              Launch Dashboard
            </Link>
            <a className="si-btn" href={GITHUB_URL} target="_blank" rel="noreferrer">
              View GitHub
            </a>
          </div>
        </section>

        <section>
          <h2 className="si-card-h">Pipeline</h2>
          <div className="flex flex-wrap items-center gap-1.5 md:gap-2">
            {steps.map((s, i) => (
              <span key={s} className="flex items-center gap-1.5 md:gap-2">
                <span className="si-card px-3 py-2.5 text-[11px] md:text-xs font-mono tracking-[0.12em] text-slate-100">
                  {s}
                </span>
                {i < steps.length - 1 && <span className="text-soc-cyan/70 font-mono text-sm">→</span>}
              </span>
            ))}
          </div>
        </section>

        <section>
          <h2 className="si-card-h">Capabilities</h2>
          <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {features.map(({ title, icon: Icon, text }) => (
              <div key={title} className="si-card p-4">
                <div className="flex items-center gap-2 text-slate-100 text-sm font-medium">
                  <Icon size={15} className="text-soc-cyan shrink-0" strokeWidth={1.75} />
                  {title}
                </div>
                <p className="mt-2 text-[13px] text-soc-muted leading-relaxed">{text}</p>
              </div>
            ))}
          </div>
        </section>

        <section>
          <h2 className="si-card-h">Live console preview</h2>
          <p className="text-[13px] text-soc-muted mb-3">Counts below come from the same overview API as Command Center.</p>
          <div className="si-card p-4 space-y-4">
            {!ov && !apiErr && <p className="text-sm text-soc-muted">Loading overview…</p>}
            {apiErr && (
              <p className="text-sm text-soc-muted">
                Preview needs the FastAPI backend on port 8000. {apiErr}
              </p>
            )}
            {ov && !hasData && (
              <p className="text-sm text-soc-muted">
                No events ingested yet. Launch the dashboard to load the synthetic dataset or upload IPDR/PCAP.
              </p>
            )}
            {hasData && (
              <>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                  {[
                    ["Events", ov.events],
                    ["Detections", ov.detections],
                    ["Confirmed", ov.confirmed],
                    ["Attempts", ov.attempt],
                    ["Unique src IPs", ov.unique_src_ips],
                  ].map(([k, v]) => (
                    <div key={k} className="si-kpi py-3">
                      <div className="si-kpi-label">{k}</div>
                      <div className="si-kpi-value text-xl">{v}</div>
                    </div>
                  ))}
                </div>
                {ov.by_status?.length > 0 && (
                  <div className="h-40">
                    <div className="si-card-h mb-0">ATTEMPT vs CONFIRMED vs UNKNOWN</div>
                    <ResponsiveContainer width="100%" height={140}>
                      <PieChart>
                        <Pie data={ov.by_status} dataKey="c" nameKey="status" innerRadius={36} outerRadius={58}>
                          {ov.by_status.map((_, i) => (
                            <Cell key={i} fill={["#f59e0b", "#ef4444", "#64748b"][i] || "#3ee0d4"} />
                          ))}
                        </Pie>
                        <Tooltip contentStyle={tooltipStyle} />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                )}
                <Link to="/dashboard" className="text-[13px] text-soc-cyan hover:underline">
                  Open Command Center →
                </Link>
              </>
            )}
          </div>
        </section>
      </main>

      <footer className="border-t border-soc-border px-5 py-4 text-center text-[12px] text-soc-muted font-mono">
        Built by Team Straw Hats · Smart India Hackathon 2026
      </footer>
    </div>
  );
}
