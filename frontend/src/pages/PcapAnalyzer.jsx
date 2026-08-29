import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

export default function PcapAnalyzer() {
  const [msg, setMsg] = useState("");
  const [ok, setOk] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [events, setEvents] = useState([]);

  useEffect(() => {
    api
      .events({ source_type: "pcap", limit: 200 })
      .then((ev) => setEvents(ev.events || []))
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  const onFile = async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    setBusy(true);
    setMsg("");
    setOk(false);
    try {
      const r = await api.ingestPcap(f);
      setMsg(`Parsed ${r.events} packet-derived events, ${r.detections} detections. Encrypted HTTPS paths are not invented.`);
      setOk(true);
      const ev = await api.events({ source_type: "pcap", limit: 200 });
      setEvents(ev.events || []);
    } catch (err) {
      setMsg(err.message);
      setOk(false);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h1 className="si-h1">PCAP Analyzer</h1>
      <p className="si-lede mb-4">
        <span className="font-mono text-slate-300">PCAP → metadata/events → detection/correlation</span>. Same pipeline as
        IPDR. Encrypted HTTPS payloads are not decrypted.
      </p>
      <div className="si-card border-amber-500/25 bg-amber-500/[0.04] text-amber-100/90 text-sm rounded-md p-3.5 mb-4 leading-relaxed">
        Encrypted HTTPS typically has no URL path in the capture. SignalSentry records SNI/DNS when present and sets
        availability to <span className="font-mono text-amber-50">tls_sni_only</span>. Payloads are never executed and
        URLs are never visited.
      </div>
      <div className="si-card p-5 mb-4 flex flex-col sm:flex-row sm:items-center gap-4">
        <p className="flex-1 text-sm text-soc-muted leading-relaxed">
          Upload a <span className="font-mono">.pcap</span> or <span className="font-mono">.pcapng</span>. Synthetic ingest
          may also write <span className="font-mono">backend/data/sample.pcap</span>.
        </p>
        <label className="si-btn-primary cursor-pointer shrink-0">
          {busy ? "Parsing PCAP…" : "Upload PCAP / PCAPNG"}
          <input type="file" accept=".pcap,.pcapng,.cap" className="hidden" onChange={onFile} />
        </label>
      </div>
      {msg && <p className={`mb-3 ${ok ? "si-ok" : "si-notice text-red-300"}`}>{msg}</p>}
      <div className="si-table-wrap max-h-[70vh]">
        {loading ? (
          <p className="si-empty">Loading PCAP-derived events…</p>
        ) : !events.length ? (
          <p className="si-empty">No PCAP-derived events yet. Upload a .pcap or .pcapng file.</p>
        ) : (
          <table className="si-table">
            <thead>
              <tr>
                {["id", "src", "dst", "port", "avail", "host/sni", "path"].map((h) => (
                  <th key={h}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {events.map((e) => (
                <tr key={e.id}>
                  <td>
                    <Link className="text-soc-cyan font-mono hover:underline" to={`/event/${e.id}`}>
                      {e.id}
                    </Link>
                  </td>
                  <td className="font-mono">{e.src_ip}</td>
                  <td className="font-mono">{e.dst_ip}</td>
                  <td className="font-mono tabular-nums">{e.dst_port}</td>
                  <td className="text-soc-muted">{e.url_availability}</td>
                  <td>{e.host || e.tls_sni}</td>
                  <td className="font-mono text-slate-300">{e.path || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
