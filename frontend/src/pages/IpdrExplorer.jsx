import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import FilterBar from "../components/FilterBar";

export default function IpdrExplorer() {
  const [filters, setFilters] = useState({});
  const [data, setData] = useState({ events: [], total: 0 });
  const [msg, setMsg] = useState("");
  const [ok, setOk] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    api
      .events({ ...filters, limit: 150 })
      .then(setData)
      .catch((e) => setMsg(e.message))
      .finally(() => setLoading(false));
  };
  useEffect(load, [filters]);

  const onFile = async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    setBusy(true);
    setMsg("");
    setOk(false);
    try {
      const r = await api.ingestIpdr(f);
      setMsg(`Ingested ${r.events} events, ${r.detections} detections`);
      setOk(true);
      load();
    } catch (err) {
      setMsg(err.message);
      setOk(false);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <div className="flex flex-col lg:flex-row lg:items-end justify-between gap-3 mb-4">
        <div>
          <h1 className="si-h1">IPDR Explorer</h1>
          <p className="si-lede">
            Upload <strong className="text-slate-300 font-medium">IPDR-like CSV/JSON</strong> (column aliases:
            timestamp, src_ip, dst_ip, url/host/path…). Demo data is self-generated — not a live ISP feed.
          </p>
        </div>
        <span className="text-xs text-soc-muted font-mono tabular-nums shrink-0">
          {loading ? "Loading…" : `${data.total} events`}
        </span>
      </div>

      <div className="si-card p-4 mb-4 flex flex-col sm:flex-row sm:items-center gap-3">
        <div className="flex-1 text-xs text-soc-muted leading-relaxed">
          Ingest maps rows into the same event schema as the synthetic dataset, then runs detection and correlation.
        </div>
        <label className="si-btn-primary cursor-pointer shrink-0">
          {busy ? "Parsing…" : "Upload IPDR-like CSV/JSON"}
          <input type="file" accept=".csv,.json" className="hidden" onChange={onFile} />
        </label>
      </div>
      {msg && <p className={`mb-3 ${ok ? "si-ok" : "si-notice text-red-300"}`}>{msg}</p>}
      <FilterBar value={filters} onChange={setFilters} />
      <div className="si-table-wrap max-h-[70vh]">
        {loading ? (
          <p className="si-empty">Loading events…</p>
        ) : !data.events.length ? (
          <p className="si-empty">No events match the current filters. Load synthetic data or upload a file.</p>
        ) : (
          <table className="si-table">
            <thead>
              <tr>
                {["id", "time", "src", "dst", "method", "host", "path", "HTTP", "avail"].map((h) => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {data.events.map((e) => (
                <tr key={e.id}>
                  <td>
                    <Link className="text-soc-cyan font-mono hover:underline" to={`/event/${e.id}`}>
                      {e.id}
                    </Link>
                  </td>
                  <td className="font-mono text-slate-400 whitespace-nowrap">{(e.timestamp || "").slice(0, 19)}</td>
                  <td className="font-mono">{e.src_ip}</td>
                  <td className="font-mono">{e.dst_ip}</td>
                  <td className="font-mono text-slate-300">{e.http_method}</td>
                  <td className="max-w-[10rem] truncate">{e.host}</td>
                  <td className="font-mono max-w-xs truncate text-slate-300">{e.path}</td>
                  <td className="font-mono tabular-nums">{e.http_status}</td>
                  <td className="text-soc-muted">{e.url_availability}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
