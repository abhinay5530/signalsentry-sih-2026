import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import FilterBar from "../components/FilterBar";

export default function IpdrExplorer() {
  const [filters, setFilters] = useState({});
  const [data, setData] = useState({ events: [], total: 0 });
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);

  const load = () => {
    api.events({ ...filters, limit: 150 }).then(setData).catch((e) => setMsg(e.message));
  };
  useEffect(load, [filters]);

  const onFile = async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    setBusy(true);
    setMsg("");
    try {
      const r = await api.ingestIpdr(f);
      setMsg(`Ingested ${r.events} events, ${r.detections} detections`);
      load();
    } catch (err) {
      setMsg(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-3 mb-4">
        <div>
          <h1 className="si-h1">IPDR Explorer</h1>
          <p className="si-lede">
            Upload CSV/JSON with column aliases (timestamp, src_ip, dst_ip, url/host/path…). Simulated or mapped IPDR —
            not a live ISP feed.
          </p>
        </div>
        <div className="flex items-center gap-3 shrink-0">
          <label className="si-btn cursor-pointer">
            {busy ? "Parsing…" : "Upload IPDR CSV/JSON"}
            <input type="file" accept=".csv,.json" className="hidden" onChange={onFile} />
          </label>
          <span className="text-xs text-soc-muted font-mono tabular-nums">{data.total} events</span>
        </div>
      </div>
      {msg && <p className="text-xs text-amber-200/90 mb-3">{msg}</p>}
      <FilterBar value={filters} onChange={setFilters} />
      <div className="si-table-wrap max-h-[70vh]">
        {!data.events.length ? (
          <p className="si-empty">No events match the current filters.</p>
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
