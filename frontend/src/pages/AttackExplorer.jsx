import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import FilterBar from "../components/FilterBar";
import StatusBadge, { SeverityBadge } from "../components/StatusBadge";

export default function AttackExplorer() {
  const [filters, setFilters] = useState({});
  const [data, setData] = useState({ detections: [], total: 0 });

  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let cancelled = false;
    setErr("");
    setLoading(true);
    api
      .detections({ ...filters, limit: 250 })
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e) => {
        if (!cancelled) setErr(e.message);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [filters]);

  return (
    <div>
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-2 mb-4">
        <div>
          <h1 className="si-h1">Attack Explorer</h1>
          <p className="si-lede">Query detections by type, IP/CIDR, status, and severity. Confirmed ≠ URL-only.</p>
        </div>
        <span className="text-xs text-soc-muted font-mono tabular-nums shrink-0">
          {loading ? "Loading…" : `${data.total} detections`}
        </span>
      </div>
      <FilterBar value={filters} onChange={setFilters} />
      {err && <p className="text-red-400 text-xs mb-2">{err}</p>}
      <div className="si-table-wrap max-h-[70vh]">
        {loading ? (
          <p className="si-empty">Loading…</p>
        ) : !data.detections.length ? (
          <p className="si-empty">No detections match the current filters.</p>
        ) : (
          <table className="si-table">
            <thead>
              <tr>
                {["event", "time", "src", "type", "status", "sev", "score", "url"].map((h) => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.detections.map((d) => (
                <tr key={d.detection_id}>
                  <td>
                    <Link className="text-soc-cyan font-mono hover:underline" to={`/event/${d.event_id}`}>
                      {d.event_id}
                    </Link>
                  </td>
                  <td className="font-mono text-slate-400 whitespace-nowrap">{(d.timestamp || "").slice(0, 19)}</td>
                  <td className="font-mono">
                    <Link className="text-soc-cyan hover:underline" to={`/investigate?ip=${d.src_ip}`}>
                      {d.src_ip}
                    </Link>
                  </td>
                  <td className="text-slate-200">{d.attack_type}</td>
                  <td>
                    <StatusBadge status={d.status} />
                  </td>
                  <td>
                    <SeverityBadge severity={d.severity} />
                  </td>
                  <td className="font-mono tabular-nums text-slate-300">{d.risk_score}</td>
                  <td className="font-mono max-w-sm truncate text-slate-400">{d.url || d.path || d.tls_sni || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
