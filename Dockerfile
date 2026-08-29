# Single-service image: Vite build + FastAPI (Koyeb).
FROM node:20-alpine AS frontend
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt
COPY backend /app/backend
COPY --from=frontend /src/frontend/dist /app/frontend/dist
WORKDIR /app/backend
ENV PYTHONPATH=/app/backend
ENV PYTHONUNBUFFERED=1
EXPOSE 8000
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
