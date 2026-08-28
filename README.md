# SignalSentry

Local **IPDR / PCAP URL-attack investigation** prototype for Smart India Hackathon.

This is **not** a paste-a-URL phishing checker and **not** live threat intelligence. It ingests IPDR-like CSV/JSON or PCAP/PCAPNG, normalizes HTTP/URL events, runs explainable rule + behavior (+ optional Random Forest) detection, classifies **ATTEMPT / CONFIRMED / UNKNOWN**, and supports IP/CIDR investigation plus CSV/JSON export.

## Honest limitations

- Confirmation is a **heuristic** on available HTTP metadata and event sequences — not proof of server compromise.
- **HTTPS is not decrypted.** Missing paths are labeled `tls_sni_only` / `metadata_only` and are not invented.
- The bundled dataset is **self-generated**. Do not claim ISP-scale or real-world accuracy.
- Pattern matching **never executes** payloads and **never visits** extracted URLs.

## Requirements

- Python 3.10–3.13 recommended (`python3 --version`). Python 3.14 may not have wheels for all packages yet.
- Node.js 18+

## Run locally

```bash
# Backend
cd backend
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# optional ML complement (synthetic labels only)
python app/ml/train.py
uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

```bash
# Frontend (second terminal)
cd frontend
npm install
npm run dev
```

Open [http://127.0.0.1:5173](http://127.0.0.1:5173). Use **Load synthetic dataset** on the Command Center (seed 42). Demo attacker CIDR: `10.50.1.0/24`.

Optional sample PCAP is written to `backend/data/sample.pcap` after synthetic ingest (or `python datasets/generate.py` from `backend/` with `PYTHONPATH=.`).

## Tests

```bash
cd backend
source .venv/bin/activate
PYTHONPATH=. pytest -q
```

## IPDR columns

Accepted aliases include: `timestamp`, `src_ip`/`source_ip`, `dst_ip`/`dest_ip`, `src_port`, `dst_port`, `protocol`, `http_method`/`method`, `host`, `path`, `query`, `url`, `http_status`/`status`, `response_size`, `user_agent`, `tls_sni`, `dns_qname`.

## Architecture

Modular monolith: FastAPI + SQLite + React (Vite, Tailwind, Recharts). Detection lives in `backend/app/detection/`.
