"""Authenticated settings edits; admission shares the operation lock."""

from fastapi import APIRouter, Request
from pydantic import ValidationError

from app.ai.service import AnalysisService
from app.errors import OperationError
from app.schemas import (
    AISettingsUpdate,
    AISettingsView,
    EmptyRequest,
    ErrorResponse,
    ProjectSettingsUpdate,
    ProjectSettingsView,
    ProviderKey,
    ProviderProfileCreate,
    ProviderProfileList,
    ProviderProfileUpdate,
    ProviderProfileView,
    TargetProfileCreate,
    TargetProfileList,
    TargetProfileUpdate,
    TargetSpec,
)
from app.services.targets import configured_targets
from app.store import SQLiteScanStore

router = APIRouter(
    prefix="/api/settings",
    responses={s: {"model": ErrorResponse} for s in (403, 404, 409, 422, 500)},
)


def configuration(request):
    config = request.app.state.ai_configuration
    if config.path is None:
        raise OperationError(
            404, "settings_unavailable", "AI settings editor is unavailable."
        )
    return config


@router.get("/ai", response_model=AISettingsView)
async def get_ai_settings(request: Request):
    return configuration(request).view(request.app.state.manager.settings)


@router.post("/ai", response_model=AISettingsView)
async def save_ai_settings(body: AISettingsUpdate, request: Request):
    updated, _ = await apply_change(
        request, lambda config, current: (config.save(current, body), None)
    )
    return configuration(request).view(updated)


@router.get("/project", response_model=ProjectSettingsView)
async def get_project_settings(request: Request):
    return request.app.state.ai_configuration.project_view(
        request.app.state.manager.settings,
        persistent=isinstance(request.app.state.manager.store, SQLiteScanStore),
    )


@router.post("/project", response_model=ProjectSettingsView)
async def save_project_settings(body: ProjectSettingsUpdate, request: Request):
    await apply_change(
        request,
        lambda config, current: (config.save_project(current, body), None),
        project=True,
    )
    return await get_project_settings(request)


async def apply_change(request, change, *, project=False):
    config = configuration(request)
    manager = request.app.state.manager
    async with manager.lock:
        if manager.operation is not None or manager.closed:
            raise OperationError(
                409,
                "operation_in_progress",
                "Wait for the current operation before saving settings.",
            )
        try:
            updated, selected_id = change(config, manager.settings)
        except KeyError:
            raise OperationError(
                404,
                "target_not_found" if project else "provider_not_found",
                "Saved profile was not found.",
            ) from None
        except (ValueError, ValidationError):
            raise OperationError(
                422,
                "invalid_project_settings" if project else "invalid_ai_settings",
                "Use a public domain root URL or an allowed Host-only DVWA IP/URL, "
                "and valid limits."
                if project
                else "AI settings are invalid; check endpoint, model and limits.",
            ) from None
        except OSError:
            raise OperationError(
                500,
                "settings_save_failed",
                "Settings could not be saved; existing settings remain active.",
            ) from None
        manager.settings = updated
        manager.target = TargetSpec(
            ip=updated.lab_target_ip,
            url=updated.lab_target_url,
            auth_mode=updated.dvwa_auth_mode,
            security_level=updated.dvwa_security_level,
        )
        manager.analyzer = AnalysisService(
            updated, request.app.state.ai_client, request.app.state.cve_service
        )
        request.app.state.settings = updated
        return updated, selected_id


@router.get("/targets", response_model=TargetProfileList)
async def list_targets(request: Request):
    return TargetProfileList(
        targets=configured_targets(request.app.state.manager.settings),
        editable=request.app.state.ai_configuration.path is not None,
    )


@router.post("/targets", response_model=TargetSpec, status_code=201)
async def create_target(body: TargetProfileCreate, request: Request):
    updated, selected = await apply_change(
        request,
        lambda config, current: config.save_target(current, body),
        project=True,
    )
    return next(t for t in configured_targets(updated) if t.target_id == selected)


@router.post("/targets/{target_id}", response_model=TargetSpec)
async def edit_target(target_id: str, body: TargetProfileUpdate, request: Request):
    updated, selected = await apply_change(
        request,
        lambda config, current: config.save_target(current, body, target_id),
        project=True,
    )
    return next(t for t in configured_targets(updated) if t.target_id == selected)


@router.post("/targets/{target_id}/delete", response_model=TargetProfileList)
async def delete_target(target_id: str, body: EmptyRequest, request: Request):
    await apply_change(
        request,
        lambda config, current: config.delete_target(current, target_id),
        project=True,
    )
    return await list_targets(request)


@router.get("/providers", response_model=ProviderProfileList)
async def list_providers(request: Request):
    config = configuration(request)
    return ProviderProfileList(
        providers=config.profile_views(request.app.state.manager.settings)
    )


@router.post("/providers", response_model=ProviderProfileView, status_code=201)
async def create_provider(body: ProviderProfileCreate, request: Request):
    updated, selected_id = await apply_change(
        request, lambda config, current: config.save_provider(current, body)
    )
    return next(
        p
        for p in configuration(request).profile_views(updated)
        if p.provider_id == selected_id
    )


@router.post("/providers/{provider_id}", response_model=ProviderProfileView)
async def edit_provider(
    provider_id: ProviderKey, body: ProviderProfileUpdate, request: Request
):
    updated, selected_id = await apply_change(
        request,
        lambda config, current: config.save_provider(current, body, provider_id),
    )
    return next(
        p
        for p in configuration(request).profile_views(updated)
        if p.provider_id == selected_id
    )


@router.post("/providers/{provider_id}/delete", response_model=ProviderProfileList)
async def delete_provider(
    provider_id: ProviderKey, body: EmptyRequest, request: Request
):
    updated, _ = await apply_change(
        request, lambda config, current: config.delete_provider(current, provider_id)
    )
    return ProviderProfileList(providers=configuration(request).profile_views(updated))
