import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import StatusBadge from "../components/StatusBadge";

const DEFAULT_CIDR = "10.50.1.0/24";

export default function IpInvestigate() {
  const [sp, setSp] = useSearchParams();
  const ipParam = sp.get("ip");
  const [q, setQ] = useState(ipParam || DEFAULT_CIDR);
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const ip = ipParam || DEFAULT_CIDR;
    setQ(ip);
    let cancelled = false;
    setErr("");
    setLoading(true);
    api
      .investigate(ip)
      .then((d) => {
        if (!cancelled) setData(d);
      })
      .catch((e) => {
        if (!cancelled) {
          setData(null);
          setErr(e.message);
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [ipParam]);

  return (
    <div>
      <h1 className="si-h1">IP investigation</h1>
      <p className="si-lede mb-4">
        Single IPv4 or CIDR against ingested events. Demo attacker range: <span className="font-mono">{DEFAULT_CIDR}</span>
      </p>
      <form
        className="flex flex-wrap gap-2 mb-6"
        onSubmit={(e) => {
          e.preventDefault();
          const next = (q || "").trim() || DEFAULT_CIDR;
          const current = ipParam || DEFAULT_CIDR;
          if (next !== current) setSp({ ip: next });
        }}
      >
        <input className="si-input w-full sm:w-72" value={q} onChange={(e) => setQ(e.target.value)} />
        <button className="si-btn-primary" disabled={loading}>
          {loading ? "Querying…" : "Investigate"}
        </button>
      </form>
      {err && <p className="si-empty text-red-300 py-4">API error: {err}</p>}
      {loading && !data && <p className="si-empty">Loading investigation…</p>}
      {data && (
        <div className="space-y-4">
          <div className="si-card px-4 py-4 flex flex-col sm:flex-row sm:items-center gap-2 sm:gap-4">
            <span className="si-kpi-label mb-0">Queried IP / CIDR</span>
            <span className="font-mono text-soc-cyan text-lg md:text-xl tracking-tight">{data.query || q}</span>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {[
              ["As source", data.as_src],
              ["As dest", data.as_dst],
              ["Events", data.event_count],
              ["Detections", data.detection_count],
            ].map(([k, v]) => (
              <div key={k} className="si-kpi">
                <div className="si-kpi-label">{k}</div>
                <div className="si-kpi-value">{v}</div>
              </div>
            ))}
          </div>
          <div className="grid md:grid-cols-2 gap-4">
            <Box title="Attack types">
              {(data.by_type || []).length === 0 ? (
                <p className="si-empty py-4">No attack types for this query.</p>
              ) : (
                (data.by_type || []).map((t) => (
                  <div key={t.attack_type} className="flex justify-between text-[13px] py-1.5 border-b border-soc-border/80">
                    <span className="text-slate-300 pr-3">{t.attack_type}</span>
                    <span className="font-mono tabular-nums text-soc-muted">{t.c}</span>
                  </div>
                ))
              )}
            </Box>
            <Box title="Verdicts">
              {(data.by_status || []).length === 0 ? (
                <p className="si-empty py-4">No verdicts for this query.</p>
              ) : (
                (data.by_status || []).map((t) => (
                  <div key={t.status} className="flex justify-between items-center text-[13px] py-1.5 border-b border-soc-border/80">
                    <StatusBadge status={t.status} />
                    <span className="font-mono tabular-nums text-soc-muted">{t.c}</span>
                  </div>
                ))
              )}
            </Box>
          </div>
          <div className="grid md:grid-cols-2 gap-4">
            <Box title="Related IPs (src↔dst)">
              {(data.neighbors || []).length === 0 ? (
                <p className="si-empty py-4">No related IPs.</p>
              ) : (
                (data.neighbors || []).map((n) => (
                  <div key={n.ip} className="flex justify-between text-[13px] py-1.5 border-b border-soc-border/80">
                    <Link className="text-soc-cyan font-mono hover:underline" to={`/investigate?ip=${n.ip}`}>
                      {n.ip}
                    </Link>
                    <span className="font-mono tabular-nums text-soc-muted">{n.c}</span>
                  </div>
                ))
              )}
            </Box>
            <Box title="Highest-risk sample">
              {(data.sample || []).length === 0 ? (
                <p className="si-empty py-4">No sample detections.</p>
              ) : (
                (data.sample || []).map((d) => (
                  <div
                    key={d.detection_id}
                    className="text-[13px] py-2 border-b border-soc-border/80 flex flex-wrap gap-2 items-center"
                  >
                    <Link className="text-soc-cyan font-mono hover:underline" to={`/event/${d.event_id}`}>
                      #{d.event_id}
                    </Link>
                    <span className="text-slate-300">{d.attack_type}</span>
                    <StatusBadge status={d.status} />
                    <span className="font-mono ml-auto tabular-nums text-soc-muted">{d.risk_score}</span>
                  </div>
                ))
              )}
            </Box>
          </div>
          <Box title="Recent matching events">
            {(data.timeline || []).length === 0 ? (
              <p className="si-empty py-4">No events in this query.</p>
            ) : (
              <div className="max-h-64 overflow-auto">
                {(data.timeline || []).map((e, i) => (
                  <div key={i} className="flex flex-wrap gap-2 text-[13px] py-1.5 border-b border-soc-border/80 font-mono">
                    <span className="text-slate-500">{(e.timestamp || "").slice(0, 19)}</span>
                    <span className="text-soc-cyan">{e.src_ip}</span>
                    <span className="text-slate-400 truncate">{e.path || "—"}</span>
                    <span className="text-soc-muted ml-auto">{e.http_status ?? "—"}</span>
                  </div>
                ))}
              </div>
            )}
          </Box>
        </div>
      )}
    </div>
  );
}

function Box({ title, children }) {
  return (
    <div className="si-card p-4">
      <h2 className="si-card-h">{title}</h2>
      {children}
    </div>
  );
}
