"""Application factory for the protected lab application."""

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.staticfiles import StaticFiles

from app.ai.service import AnalysisService
from app.ai.settings import AIConfiguration
from app.api.scans import router as scans_router
from app.api.settings import router as settings_router
from app.api.system import router as system_router
from app.config import PROJECT_ROOT, Settings
from app.errors import (
    OperationError,
    http_error_handler,
    operation_error_handler,
    validation_error_handler,
)
from app.schemas import ToolId
from app.security import AccessControlMiddleware
from app.services.cve_lookup import CVELookupService
from app.services.scan_manager import Analyzer, ScanManager
from app.store import MemoryScanStore, ScanStore, SQLiteScanStore
from app.tools.base import ToolAdapter
from app.tools.registry import build_registry, probe_capabilities


def create_app(
    settings: Settings | None = None,
    *,
    testing: bool = False,
    registry: dict[ToolId, ToolAdapter] | None = None,
    analyzer: Analyzer | None = None,
    store: ScanStore | None = None,
    ai_config_path: Path | None = None,
) -> FastAPI:
    settings = settings if settings is not None else Settings()
    configuration = AIConfiguration(
        ai_config_path
        if ai_config_path is not None
        else None
        if testing
        else PROJECT_ROOT / ".env.ai"
    )
    settings = configuration.apply(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        adapters = registry
        capabilities = None
        if adapters is None:
            capabilities = await asyncio.to_thread(probe_capabilities)
            adapters = build_registry(capabilities)
        async with httpx.AsyncClient(
            trust_env=False,
            verify=True,
            follow_redirects=False,
            timeout=httpx.Timeout(settings.ai_total_timeout_seconds, connect=10),
        ) as client:
            app.state.ai_client = client
            app.state.cve_service = CVELookupService(client)
            runtime_analyzer = (
                analyzer if analyzer is not None else AnalysisService(settings, client)
            )
            runtime_store = (
                store
                if store is not None
                else (
                    MemoryScanStore(
                        retain_completed=settings.retain_completed_scans,
                        ttl_seconds=settings.scan_ttl_seconds,
                    )
                    if testing
                    else SQLiteScanStore(settings.history_db_path)
                )
            )
            app.state.manager = ScanManager(
                settings,
                runtime_store,
                adapters,
                runtime_analyzer,
                capabilities=capabilities,
            )
            app.state.manager.ai_configuration = configuration
            try:
                yield
            finally:
                await app.state.manager.shutdown()
                if isinstance(runtime_store, SQLiteScanStore):
                    runtime_store.close()

    app = FastAPI(
        title="PenChecker",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.ai_configuration = configuration
    app.add_middleware(AccessControlMiddleware, settings=settings, testing=testing)
    app.add_exception_handler(HTTPException, http_error_handler)
    app.add_exception_handler(RequestValidationError, validation_error_handler)
    app.add_exception_handler(OperationError, operation_error_handler)
    app.include_router(system_router)
    app.include_router(scans_router)
    app.include_router(settings_router)
    directory = Path(__file__).resolve().parent
    templates = Jinja2Templates(directory=directory / "templates")

    @app.get("/healthz")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return templates.TemplateResponse(request=request, name="index.html")

    app.mount("/static", StaticFiles(directory=directory / "static"), name="static")
    return app
