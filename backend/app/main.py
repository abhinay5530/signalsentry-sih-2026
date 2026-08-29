from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException

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


def _index_file():
    return FRONTEND_DIST / "index.html"


def _mount_frontend() -> None:
    """Serve Vite build on the same origin as /api. No-op if dist is missing (local API-only)."""
    if not FRONTEND_DIST.is_dir() or not _index_file().is_file():
        return

    assets = FRONTEND_DIST / "assets"
    if assets.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets)), name="assets")

    @app.get("/")
    def root():
        return FileResponse(_index_file())

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        if exc.status_code != 404:
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        path = request.url.path
        if path.startswith("/api") or path.startswith("/assets"):
            return JSONResponse({"detail": exc.detail}, status_code=404)
        return FileResponse(_index_file())


_mount_frontend()
