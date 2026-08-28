const API = "/api";

async function handle(res) {
  if (!res.ok) {
    const t = await res.text();
    throw new Error(t || res.statusText);
  }
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("text/csv")) return res.blob();
  return res.json();
}

export const api = {
  health: () => fetch(`${API}/health`).then(handle),
  overview: () => fetch(`${API}/stats/overview`).then(handle),
  timeline: () => fetch(`${API}/stats/timeline`).then(handle),
  byIp: () => fetch(`${API}/stats/by-ip`).then(handle),
  batches: () => fetch(`${API}/batches`).then(handle),
  attackTypes: () => fetch(`${API}/attack-types`).then(handle),
  events: (params = {}) => fetch(`${API}/events?${new URLSearchParams(clean(params))}`).then(handle),
  event: (id) => fetch(`${API}/events/${id}`).then(handle),
  detections: (params = {}) => fetch(`${API}/detections?${new URLSearchParams(clean(params))}`).then(handle),
  investigate: (ip) => fetch(`${API}/investigate/ip?ip=${encodeURIComponent(ip)}`).then(handle),
  ingestSynthetic: (n = 10000, seed = 42) =>
    fetch(`${API}/ingest/synthetic?n=${n}&seed=${seed}`, { method: "POST" }).then(handle),
  ingestIpdr: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return fetch(`${API}/ingest/ipdr`, { method: "POST", body: fd }).then(handle);
  },
  ingestPcap: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return fetch(`${API}/ingest/pcap`, { method: "POST", body: fd }).then(handle);
  },
  exportUrl: (format, params = {}) => `${API}/export?format=${format}&${new URLSearchParams(clean(params))}`,
};

function clean(obj) {
  const o = {};
  Object.entries(obj).forEach(([k, v]) => {
    if (v !== undefined && v !== null && v !== "") o[k] = v;
  });
  return o;
}
