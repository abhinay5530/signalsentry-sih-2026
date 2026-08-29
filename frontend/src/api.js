const API = "/api";

const RETRIES = 3;
const RETRY_DELAY_MS = 3000;

async function handle(res) {
  if (!res.ok) {
    const t = await res.text();
    throw new Error(t || res.statusText);
  }
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("text/csv")) return res.blob();
  return res.json();
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Retry only when fetch itself fails (cold start / network). HTTP 4xx/5xx are not retried. */
async function request(url, options) {
  let lastErr;
  for (let attempt = 0; attempt <= RETRIES; attempt++) {
    try {
      const res = await fetch(url, options);
      return await handle(res);
    } catch (err) {
      lastErr = err;
      const networkFail = err instanceof TypeError;
      if (!networkFail || attempt === RETRIES) throw err;
      await sleep(RETRY_DELAY_MS);
    }
  }
  throw lastErr;
}

export const api = {
  health: () => request(`${API}/health`),
  overview: () => request(`${API}/stats/overview`),
  timeline: () => request(`${API}/stats/timeline`),
  byIp: () => request(`${API}/stats/by-ip`),
  batches: () => request(`${API}/batches`),
  attackTypes: () => request(`${API}/attack-types`),
  events: (params = {}) => request(`${API}/events?${new URLSearchParams(clean(params))}`),
  event: (id) => request(`${API}/events/${id}`),
  detections: (params = {}) => request(`${API}/detections?${new URLSearchParams(clean(params))}`),
  investigate: (ip) => request(`${API}/investigate/ip?ip=${encodeURIComponent(ip)}`),
  ingestSynthetic: (n = 10000, seed = 42) =>
    request(`${API}/ingest/synthetic?n=${n}&seed=${seed}`, { method: "POST" }),
  ingestIpdr: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return request(`${API}/ingest/ipdr`, { method: "POST", body: fd });
  },
  ingestPcap: (file) => {
    const fd = new FormData();
    fd.append("file", file);
    return request(`${API}/ingest/pcap`, { method: "POST", body: fd });
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
