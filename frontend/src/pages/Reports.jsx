import { useMemo, useState } from "react";
import FilterBar from "../components/FilterBar";
import { api } from "../api";

export default function Reports() {
  const [filters, setFilters] = useState({});
  const qs = useMemo(() => filters, [filters]);

  return (
    <div>
      <h1 className="si-h1">Reports & export</h1>
      <p className="si-lede mb-4">
        Downloads use the <strong className="text-slate-300 font-medium">current filter</strong> below. Files contain
        detections joined to events — heuristic investigation results, not a precision/recall scorecard.
      </p>
      <FilterBar value={filters} onChange={setFilters} />
      <div className="grid sm:grid-cols-2 gap-3 max-w-2xl">
        <a className="si-card p-5 hover:border-soc-cyan/40 block" href={api.exportUrl("csv", qs)}>
          <div className="text-[10px] uppercase tracking-[0.14em] text-soc-muted mb-2">Export</div>
          <div className="text-soc-cyan font-semibold">Download CSV</div>
          <p className="text-xs text-soc-muted mt-2 leading-relaxed">
            Spreadsheet of the filtered join (same query params as Attack Explorer).
          </p>
        </a>
        <a className="si-card p-5 hover:border-soc-cyan/40 block" href={api.exportUrl("json", qs)}>
          <div className="text-[10px] uppercase tracking-[0.14em] text-soc-muted mb-2">Export</div>
          <div className="text-slate-100 font-semibold">Download JSON</div>
          <p className="text-xs text-soc-muted mt-2 leading-relaxed">
            Same filtered set as JSON for tooling or further review.
          </p>
        </a>
      </div>
      <div className="si-notice mt-6 max-w-2xl space-y-2">
        <p>
          Confirmation is based on HTTP status, response size bands, and request sequences in the ingested data — not
          host forensics.
        </p>
        <p>Do not present export counts as real-world precision/recall.</p>
      </div>
    </div>
  );
}
