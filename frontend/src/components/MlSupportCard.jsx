/** Presentation-only: ML remains stored on the detection; this card subordinates it to rule/HTTP evidence. */
export default function MlSupportCard({ score }) {
  if (score == null || Number.isNaN(Number(score))) return null;
  const p = Number(score);
  return (
    <div className="mt-3 border border-soc-border/50 rounded-md px-3 py-2.5 bg-[#080d14]">
      <div className="text-[11px] uppercase tracking-[0.12em] font-mono text-soc-muted">Supporting ML signal</div>
      <div className="text-[13px] text-soc-muted mt-0.5">Synthetic/demo model support</div>
      <div className="text-[13px] font-mono text-slate-500 mt-1 tabular-nums">p(malicious): {p.toFixed(2)}</div>
      <p className="text-[12px] text-soc-muted mt-1.5 leading-snug">
        Optional ML support — trained on the synthetic demonstration dataset. The verdict is determined by
        explainable rule and HTTP/IPDR correlation.
      </p>
    </div>
  );
}

export function withoutMlEvidence(items = []) {
  return items.filter((e) => e && e.code !== "ml_support");
}
