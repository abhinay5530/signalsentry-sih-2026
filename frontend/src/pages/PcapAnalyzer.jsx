import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";

export default function PcapAnalyzer() {
  const [msg, setMsg] = useState("");
  const [busy, setBusy] = useState(false);
  const [events, setEvents] = useState([]);

  useEffect(() => {
    api.events({ source_type: "pcap", limit: 200 }).then((ev) => setEvents(ev.events || [])).catch(() => {});
  }, []);

  const onFile = async (e) => {
    const f = e.target.files?.[0];
    if (!f) return;
    setBusy(true);
    setMsg("");
    try {
      const r = await api.ingestPcap(f);
      setMsg(`Parsed ${r.events} packet-derived events, ${r.detections} detections. Encrypted HTTPS paths are not invented.`);
      const ev = await api.events({ source_type: "pcap", limit: 200 });
      setEvents(ev.events || []);
    } catch (err) {
      setMsg(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div>
      <h1 className="si-h1">PCAP Analyzer</h1>
      <p className="si-lede mb-4">Ingest a capture and inspect packet-derived HTTP/SNI events. Same detection pipeline as IPDR.</p>
      <div className="si-card border-amber-500/25 bg-amber-500/[0.04] text-amber-100/90 text-sm rounded-md p-3.5 mb-4 leading-relaxed">
        Encrypted HTTPS traffic typically has no URL path in the capture. SignalSentry records SNI/DNS when present and
        sets availability to <span className="font-mono text-amber-50">tls_sni_only</span>. Payloads are never executed
        and URLs are never visited.
      </div>
      <label className="si-btn cursor-pointer inline-flex mb-4">
        {busy ? "Parsing PCAP…" : "Upload PCAP / PCAPNG"}
        <input type="file" accept=".pcap,.pcapng,.cap" className="hidden" onChange={onFile} />
      </label>
      {msg && <p className="text-sm text-slate-300 mb-3">{msg}</p>}
      <div className="si-table-wrap max-h-[70vh]">
        {!events.length ? (
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
