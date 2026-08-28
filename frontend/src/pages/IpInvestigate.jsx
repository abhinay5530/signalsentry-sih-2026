import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import StatusBadge from "../components/StatusBadge";

export default function IpInvestigate() {
  const [sp, setSp] = useSearchParams();
  const [q, setQ] = useState(sp.get("ip") || "10.50.1.0/24");
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");

  const run = (ip) => {
    setErr("");
    api.investigate(ip).then(setData).catch((e) => setErr(e.message));
  };

  useEffect(() => {
    if (sp.get("ip")) run(sp.get("ip"));
  }, [sp]);

  return (
    <div>
      <h1 className="si-h1">IP investigation</h1>
      <p className="si-lede mb-4">Single IPv4 or CIDR. Demo attacker range: 10.50.1.0/24</p>
      <form
        className="flex flex-wrap gap-2 mb-6"
        onSubmit={(e) => {
          e.preventDefault();
          setSp({ ip: q });
          run(q);
        }}
      >
        <input
          className="si-input w-full sm:w-72"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <button className="si-btn-primary">Investigate</button>
      </form>
      {err && <p className="text-red-400 text-sm mb-3">{err}</p>}
      {data && (
        <div className="space-y-4">
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
                  <div key={t.attack_type} className="flex justify-between text-xs py-1.5 border-b border-soc-border/80">
                    <span className="text-slate-300 pr-3">{t.attack_type}</span>
                    <span className="font-mono tabular-nums text-soc-muted">{t.c}</span>
                  </div>
                ))
              )}
            </Box>
            <Box title="Related IPs (src↔dst)">
              {(data.neighbors || []).length === 0 ? (
                <p className="si-empty py-4">No related IPs.</p>
              ) : (
                (data.neighbors || []).map((n) => (
                  <div key={n.ip} className="flex justify-between text-xs py-1.5 border-b border-soc-border/80">
                    <Link className="text-soc-cyan font-mono hover:underline" to={`/investigate?ip=${n.ip}`}>
                      {n.ip}
                    </Link>
                    <span className="font-mono tabular-nums text-soc-muted">{n.c}</span>
                  </div>
                ))
              )}
            </Box>
          </div>
          <Box title="Highest-risk sample">
            {(data.sample || []).length === 0 ? (
              <p className="si-empty py-4">No sample detections.</p>
            ) : (
              (data.sample || []).map((d) => (
                <div key={d.detection_id} className="text-xs py-2 border-b border-soc-border/80 flex flex-wrap gap-2 items-center">
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
