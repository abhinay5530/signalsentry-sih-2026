const TYPES = [
  "",
  "Typosquatting / URL spoofing",
  "SQL Injection",
  "Cross-Site Scripting (XSS)",
  "Directory Traversal",
  "Command Injection",
  "Server-Side Request Forgery (SSRF)",
  "Local File Inclusion / Remote File Inclusion (LFI/RFI)",
  "Credential Stuffing / Brute Force",
  "HTTP Parameter Pollution (HPP)",
  "XML External Entity Injection (XXE)",
  "Web shell upload indicators",
  "ANOMALOUS_URL",
];

export default function FilterBar({ value, onChange, extra }) {
  const set = (k, v) => onChange({ ...value, [k]: v });
  return (
    <div className="si-card p-4 md:p-4 mb-4">
      <h2 className="si-card-h mb-3">Filters</h2>
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <label>
          <span className="si-label">Source IP</span>
          <input
            className="si-input"
            placeholder="e.g. 10.50.1.10"
            value={value.src_ip || ""}
            onChange={(e) => set("src_ip", e.target.value)}
          />
        </label>
        <label>
          <span className="si-label">Dest IP</span>
          <input
            className="si-input"
            placeholder="e.g. 10.20.0.10"
            value={value.dst_ip || ""}
            onChange={(e) => set("dst_ip", e.target.value)}
          />
        </label>
        <label>
          <span className="si-label">IP range</span>
          <input
            className="si-input"
            placeholder="e.g. 10.50.1.0/24"
            value={value.cidr || ""}
            onChange={(e) => set("cidr", e.target.value)}
          />
          <span className="block text-[11px] text-soc-muted mt-1 leading-snug">
            Use CIDR to investigate a network range.
          </span>
        </label>
        <label>
          <span className="si-label">Attack type</span>
          <select
            className="si-input"
            value={value.attack_type || ""}
            onChange={(e) => set("attack_type", e.target.value)}
          >
            <option value="">All attack types</option>
            {TYPES.filter(Boolean).map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
        </label>
        <label>
          <span className="si-label">Verdict</span>
          <select className="si-input" value={value.status || ""} onChange={(e) => set("status", e.target.value)}>
            <option value="">All statuses</option>
            <option>ATTEMPT</option>
            <option>CONFIRMED</option>
            <option>UNKNOWN</option>
          </select>
        </label>
        <label>
          <span className="si-label">Severity</span>
          <select className="si-input" value={value.severity || ""} onChange={(e) => set("severity", e.target.value)}>
            <option value="">All severities</option>
            <option>critical</option>
            <option>high</option>
            <option>medium</option>
            <option>low</option>
          </select>
        </label>
        {extra}
      </div>
    </div>
  );
}
