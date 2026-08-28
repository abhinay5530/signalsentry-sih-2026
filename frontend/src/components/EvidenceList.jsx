export default function EvidenceList({ items = [], hideEmpty = false }) {
  if (!items.length) {
    if (hideEmpty) return null;
    return <p className="text-sm text-soc-muted py-2">No evidence attached.</p>;
  }
  return (
    <ul className="space-y-2">
      {items.map((e, i) => (
        <li key={i} className="border border-soc-border/90 rounded-md p-3 bg-[#080d14]">
          <div className="text-[10px] font-mono text-soc-cyan/90 uppercase tracking-[0.08em]">{e.code}</div>
          <div className="text-sm text-slate-200 mt-1 leading-snug">{e.detail}</div>
          {e.snippet ? (
            <pre className="mt-2 text-[11px] font-mono text-amber-200/80 whitespace-pre-wrap break-all bg-black/30 rounded px-2 py-1.5">
              {e.snippet}
            </pre>
          ) : null}
        </li>
      ))}
    </ul>
  );
}
