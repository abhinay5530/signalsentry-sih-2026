export default function VerdictLegend() {
  return (
    <div className="si-card p-4">
      <h2 className="si-card-h">ATTEMPT / CONFIRMED / UNKNOWN</h2>
      <ul className="space-y-2 text-[13px] text-soc-muted leading-relaxed">
        <li>
          <span className="text-amber-200/90 font-mono">ATTEMPT</span> — suspicious evidence without enough correlated HTTP/IPDR
          context for this project’s confirmation rules.
        </li>
        <li>
          <span className="text-red-300 font-mono">CONFIRMED</span> — correlated evidence meets the heuristics (not a URL regex
          match, not proof of compromise).
        </li>
        <li>
          <span className="text-slate-300 font-mono">UNKNOWN</span> — insufficient or incomplete evidence (including HTTPS without
          a decrypted path).
        </li>
      </ul>
    </div>
  );
}
