export default function StatusBadge({ status }) {
  const map = {
    ATTEMPT: "bg-amber-500/12 text-amber-200/95 border-amber-500/35",
    CONFIRMED: "bg-red-500/12 text-red-300 border-red-500/35",
    UNKNOWN: "bg-slate-500/15 text-slate-300 border-slate-500/35",
  };
  return (
    <span
      className={`inline-flex items-center text-[11px] uppercase tracking-[0.1em] px-2 py-1 rounded-md border font-mono leading-none ${
        map[status] || map.UNKNOWN
      }`}
    >
      {status || "UNKNOWN"}
    </span>
  );
}

export function SeverityBadge({ severity }) {
  const map = {
    critical: "bg-red-500/15 text-red-300 border-red-500/30",
    high: "bg-orange-500/12 text-orange-200 border-orange-500/30",
    medium: "bg-amber-500/10 text-amber-100/90 border-amber-500/25",
    low: "bg-slate-500/10 text-slate-400 border-slate-500/25",
  };
  return (
    <span
      className={`inline-flex items-center font-mono text-[11px] uppercase tracking-[0.1em] px-2 py-1 rounded-md border ${
        map[severity] || map.low
      }`}
    >
      {severity}
    </span>
  );
}
