import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import EvidenceList from "../components/EvidenceList";
import MlSupportCard, { withoutMlEvidence } from "../components/MlSupportCard";
import StatusBadge, { SeverityBadge } from "../components/StatusBadge";
import { analystExplanation, selectPrimaryAttack, supportingEvidence } from "../primaryAttack";

export default function IncidentDetails() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [err, setErr] = useState("");

  useEffect(() => {
    api.event(id).then(setData).catch((e) => setErr(e.message));
  }, [id]);

  if (err) return <p className="text-red-400">{err}</p>;
  if (!data) return <p className="text-soc-muted">Loading…</p>;
  const e = data.event;
  const feats = e.features || {};
  const detections = data.detections || [];
  const { primary, supporting, reasonKey } = selectPrimaryAttack(detections, e.scenario_id);
  const explanation = analystExplanation(primary, supporting, reasonKey);

  return (
    <div className="space-y-4">
      <div>
        <h1 className="si-h1">Incident {e.id}</h1>
        <p className="si-lede">Explainable finding — pattern match + HTTP metadata, not “AI says malicious.”</p>
      </div>
      <div className="grid md:grid-cols-2 gap-4">
        <div className="si-card p-4 text-sm space-y-1.5 font-mono">
          <Row k="timestamp" v={e.timestamp} />
          <Row k="src → dst" v={`${e.src_ip}:${e.src_port} → ${e.dst_ip}:${e.dst_port}`} />
          <Row k="method" v={e.http_method} />
          <Row k="host" v={e.host} />
          <Row k="path" v={e.path} />
          <Row k="query" v={e.query} />
          <Row k="url" v={e.url} />
          <Row k="http_status" v={e.http_status} />
          <Row k="response_size" v={e.response_size} />
          <Row k="availability" v={e.url_availability} />
          <Row k="tls_sni" v={e.tls_sni} />
          <Row k="source" v={e.source_type} />
        </div>
        <div className="si-card p-4">
          <h2 className="si-card-h">URL / structural features</h2>
          <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 text-[11px] font-mono">
            {Object.entries(feats)
              .slice(0, 24)
              .map(([k, v]) => (
                <div key={k} className="flex justify-between gap-2 border-b border-soc-border/50 py-1">
                  <span className="text-soc-muted truncate">{k}</span>
                  <span className="text-slate-300">{String(v)}</span>
                </div>
              ))}
          </div>
        </div>
      </div>

      {!detections.length && <p className="si-empty si-card">No detections on this event.</p>}

      {primary && (
        <div className="si-card p-4 border-soc-cyan/35">
          <div className="text-[10px] uppercase tracking-[0.14em] text-soc-cyan font-mono mb-2">Primary attack</div>
          <div className="flex flex-wrap items-center gap-2.5 mb-3">
            <span className="text-lg font-semibold text-slate-100">{primary.attack_type}</span>
            <StatusBadge status={primary.status} />
            <SeverityBadge severity={primary.severity} />
            <span className="text-xs font-mono text-soc-muted">
              risk {primary.risk_score} · {primary.detectors}
            </span>
          </div>
          {supporting.length > 0 && (
            <p className="text-xs text-amber-100/85 mb-3 border border-amber-500/20 bg-amber-500/[0.06] rounded-md px-3 py-2 leading-relaxed">
              One HTTP transaction · {detections.length} correlated indicators. Supporting signatures are not separate
              successful attacks.
            </p>
          )}
          {explanation && <p className="text-sm text-slate-300 mb-3 leading-relaxed">{explanation}</p>}
          <EvidenceList items={withoutMlEvidence(primary.evidence || [])} hideEmpty />
          <MlSupportCard score={primary.ml_score} />
        </div>
      )}

      {supporting.length > 0 && (
        <div className="si-card p-4 bg-[#080d14]">
          <h2 className="si-card-h mb-1">Supporting indicators</h2>
          <p className="text-xs text-soc-muted mb-3 leading-relaxed">
            Multiple indicators were observed in the same HTTP transaction. These remain on the event as signature
            matches; they are not additional CONFIRMED outcomes.
          </p>
          <ul className="space-y-3">
            {supporting.map((d) => (
              <li key={d.id} className="border border-soc-border rounded-md p-3">
                <div className="flex flex-wrap items-center gap-2 mb-2">
                  <span className="font-medium text-sm text-slate-200">{d.attack_type}</span>
                  <span className="text-[10px] uppercase tracking-[0.08em] font-mono text-soc-muted border border-soc-border px-1.5 py-0.5 rounded">
                    indicator
                  </span>
                </div>
                <EvidenceList items={supportingEvidence(d)} />
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="si-card p-4">
        <h2 className="si-card-h">Related events from same source IP</h2>
        {!(data.related || []).length ? (
          <p className="text-xs text-soc-muted">No related events.</p>
        ) : (
          <ul className="text-xs space-y-1.5">
            {(data.related || []).map((r, i) => (
              <li key={i} className="flex flex-wrap items-center gap-2 border-b border-soc-border/50 py-1.5 last:border-0">
                <Link className="text-soc-cyan font-mono hover:underline" to={`/event/${r.id}`}>
                  #{r.id}
                </Link>
                <span className="font-mono text-slate-500">{r.timestamp}</span>
                <span className="font-mono text-slate-400">{r.path}</span>
                <span className="text-slate-300">{r.attack_type}</span>
                <StatusBadge status={r.status} />
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function Row({ k, v }) {
  return (
    <div className="flex gap-2">
      <span className="text-soc-muted w-28 shrink-0 text-[11px] uppercase tracking-[0.06em]">{k}</span>
      <span className="break-all text-slate-200">{v == null || v === "" ? "—" : String(v)}</span>
    </div>
  );
}
