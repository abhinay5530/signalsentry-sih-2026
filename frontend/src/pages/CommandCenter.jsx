import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "../api";
import StatusBadge from "../components/StatusBadge";
import VerdictLegend from "../components/VerdictLegend";

const COLORS = ["#3ee0d4", "#f59e0b", "#ef4444", "#64748b", "#a78bfa", "#34d399", "#fb7185"];
const tooltipStyle = { background: "#0d1522", border: "1px solid #1c2a3d", fontSize: 12 };

export default function CommandCenter() {
  const [ov, setOv] = useState(null);
  const [tl, setTl] = useState([]);
  const [ips, setIps] = useState({ sources: [] });
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const load = () => {
    Promise.all([api.overview(), api.timeline(), api.byIp()])
      .then(([a, b, c]) => {
        setOv(a);
        setTl(b.points || []);
        setIps(c);
        setErr("");
      })
      .catch((e) => setErr(e.message));
  };

  useEffect(load, []);

  const loadSynth = async () => {
    setBusy(true);
    setErr("");
    try {
      await api.ingestSynthetic(10000, 42);
      load();
    } catch (e) {
      setErr(e.message);
    } finally {
      setBusy(false);
    }
  };

  const buckets = {};
  tl.forEach((p) => {
    buckets[p.bucket] = buckets[p.bucket] || { bucket: p.bucket, ATTEMPT: 0, CONFIRMED: 0, UNKNOWN: 0 };
    buckets[p.bucket][p.status] = p.c;
  });
  const timeline = Object.values(buckets);

  if (!ov) {
    return (
      <div className="max-w-lg si-card p-6">
        <h1 className="si-h1">Command Center</h1>
        <p className="si-lede mb-5">
          {err || "Loading overview…"} If this persists, start FastAPI on port 8000 (Vite proxies /api).
        </p>
        <button onClick={loadSynth} disabled={busy} className="si-btn-primary">
          {busy ? "Detecting…" : "Load synthetic dataset"}
        </button>
      </div>
    );
  }

  if (!ov.events) {
    return (
      <div className="max-w-lg si-card p-6">
        <h1 className="si-h1">Command Center</h1>
        <p className="si-lede mb-5">
          No events yet. Load the seeded synthetic IPDR dataset (self-generated, not a live ISP feed).
        </p>
        <button onClick={loadSynth} disabled={busy} className="si-btn-primary">
          {busy ? "Detecting…" : "Load synthetic dataset"}
        </button>
        {err && <pre className="text-red-400 text-xs mt-3 whitespace-pre-wrap">{err}</pre>}
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3">
        <div>
          <h1 className="si-h1">Command Center</h1>
          <p className="si-lede">
            Heuristic detections from ingested IPDR-like records and PCAP — not live threat intelligence, not proof of
            compromise.
          </p>
        </div>
        <button onClick={loadSynth} disabled={busy} className="si-btn shrink-0 self-start sm:self-auto">
          {busy ? "Reloading…" : "Reload synthetic"}
        </button>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        {[
          ["Events", ov.events, "text-soc-cyan"],
          ["Detections", ov.detections, "text-soc-cyan"],
          ["Confirmed", ov.confirmed, "text-red-300"],
          ["Attempts", ov.attempt, "text-amber-200"],
          ["Unique src IPs", ov.unique_src_ips, "text-soc-cyan"],
        ].map(([k, v, color]) => (
          <div key={k} className="si-kpi">
            <div className="si-kpi-label">{k}</div>
            <div className={`si-kpi-value ${color}`}>{v}</div>
          </div>
        ))}
      </div>

      <div className="grid lg:grid-cols-2 gap-3">
        <div className="si-card p-4">
          <h2 className="si-card-h">Detection method</h2>
          <p className="text-[13px] text-soc-muted leading-relaxed">
            Rules and behavior checks run on normalized HTTP/IPDR metadata. Correlation uses request sequences and
            available HTTP fields (for example earlier errors then a later success). An optional Random Forest score
            is supporting only. HTTPS payloads are not decrypted.
          </p>
        </div>
        <VerdictLegend />
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        <div className="si-card p-4 h-80">
          <h2 className="si-card-h">Detections by attack type</h2>
          <ResponsiveContainer>
            <BarChart data={ov.by_type} layout="vertical" margin={{ left: 8, right: 12, top: 4, bottom: 4 }}>
              <CartesianGrid stroke="#1c2a3d" strokeDasharray="3 4" />
              <XAxis type="number" stroke="#8aa0b8" tick={{ fontSize: 10 }} />
              <YAxis type="category" dataKey="attack_type" width={168} tick={{ fontSize: 9, fill: "#8aa0b8" }} />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey="c" fill="#3ee0d4" radius={[0, 2, 2, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="si-card p-4 h-80">
          <h2 className="si-card-h">ATTEMPT vs CONFIRMED vs UNKNOWN</h2>
          <ResponsiveContainer>
            <PieChart>
              <Pie data={ov.by_status} dataKey="c" nameKey="status" innerRadius={52} outerRadius={88} paddingAngle={2}>
                {ov.by_status.map((_, i) => (
                  <Cell key={i} fill={["#f59e0b", "#ef4444", "#64748b"][i] || COLORS[i]} />
                ))}
              </Pie>
              <Legend wrapperStyle={{ fontSize: 12 }} />
              <Tooltip contentStyle={tooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="si-card p-4 h-80 lg:col-span-2">
          <h2 className="si-card-h">Attack timeline (hour buckets)</h2>
          <ResponsiveContainer>
            <AreaChart data={timeline} margin={{ left: 0, right: 8 }}>
              <CartesianGrid stroke="#1c2a3d" strokeDasharray="3 4" />
              <XAxis dataKey="bucket" tick={{ fontSize: 10 }} stroke="#8aa0b8" />
              <YAxis stroke="#8aa0b8" tick={{ fontSize: 10 }} />
              <Tooltip contentStyle={tooltipStyle} />
              <Area type="monotone" dataKey="ATTEMPT" stackId="1" stroke="#f59e0b" fill="#f59e0b44" />
              <Area type="monotone" dataKey="CONFIRMED" stackId="1" stroke="#ef4444" fill="#ef444444" />
              <Area type="monotone" dataKey="UNKNOWN" stackId="1" stroke="#64748b" fill="#64748b44" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div className="si-card p-4 h-80">
          <h2 className="si-card-h">Top source IPs</h2>
          <ResponsiveContainer>
            <BarChart data={ips.sources} layout="vertical" margin={{ left: 4, right: 8 }}>
              <XAxis type="number" stroke="#8aa0b8" tick={{ fontSize: 10 }} />
              <YAxis type="category" dataKey="ip" width={110} tick={{ fontSize: 10, fill: "#8aa0b8" }} />
              <Tooltip contentStyle={tooltipStyle} />
              <Bar dataKey="detections" fill="#7dd3c7" radius={[0, 2, 2, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
        <div className="si-card p-4 overflow-auto max-h-80">
          <h2 className="si-card-h">Recent detections</h2>
          {(ov.recent || []).length === 0 ? (
            <p className="si-empty">No detections yet.</p>
          ) : (
            <table className="si-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Src</th>
                  <th>Type</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {(ov.recent || []).map((r) => (
                  <tr key={r.detection_id}>
                    <td className="font-mono text-slate-400">{(r.timestamp || "").slice(0, 19)}</td>
                    <td className="font-mono">
                      <Link className="text-soc-cyan hover:underline" to={`/investigate?ip=${r.src_ip}`}>
                        {r.src_ip}
                      </Link>
                    </td>
                    <td className="text-slate-300">{r.attack_type}</td>
                    <td>
                      <Link to={`/event/${r.event_id || r.id}`}>
                        <StatusBadge status={r.status} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
      {err && <p className="text-red-400 text-xs">{err}</p>}
    </div>
  );
}
