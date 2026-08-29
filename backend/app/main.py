from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import router
from app.config import CORS_ORIGINS, FRONTEND_DIST
from app.db import init_db

app = FastAPI(title="SentinelIP", description="IPDR/PCAP URL-attack investigation (local prototype)")
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(router)


@app.on_event("startup")
def startup():
    init_db()


def _mount_frontend() -> None:
    """Serve Vite build from the same origin as /api. No-op if dist is missing (local API-only)."""
    if not FRONTEND_DIST.is_dir():
        return
    assets = FRONTEND_DIST / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        if full_path == "api" or full_path.startswith("api/"):
            raise HTTPException(status_code=404, detail="Not found")
        dist = FRONTEND_DIST.resolve()
        if full_path:
            target = (dist / full_path).resolve()
            if str(target).startswith(str(dist)) and target.is_file():
                return FileResponse(target)
        index = dist / "index.html"
        if not index.is_file():
            raise HTTPException(status_code=404, detail="Frontend not built")
        return FileResponse(index)


_mount_frontend()
