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
        Exports the current filter as CSV or JSON (detections joined to events). Heuristic findings only.
      </p>
      <FilterBar value={filters} onChange={setFilters} />
      <div className="flex flex-wrap gap-3">
        <a className="si-btn-primary" href={api.exportUrl("csv", qs)}>
          Download CSV
        </a>
        <a className="si-btn" href={api.exportUrl("json", qs)}>
          Download JSON
        </a>
      </div>
      <div className="si-card p-4 mt-6 text-sm text-soc-muted max-w-2xl space-y-2 leading-relaxed">
        <p>
          Confirmation is based on HTTP status, response size bands, and request sequences in the ingested data — not
          host forensics.
        </p>
        <p>Do not present export counts as real-world precision/recall.</p>
      </div>
    </div>
  );
}
