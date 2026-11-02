"""Authenticated AI-only settings edits; admission shares the operation lock."""

from fastapi import APIRouter, Request
from pydantic import ValidationError

from app.ai.service import AnalysisService
from app.errors import OperationError
from app.schemas import (
    AISettingsUpdate,
    AISettingsView,
    EmptyRequest,
    ErrorResponse,
    ProviderKey,
    ProviderProfileCreate,
    ProviderProfileList,
    ProviderProfileUpdate,
    ProviderProfileView,
)

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


async def apply_change(request, change):
    config = configuration(request)
    manager = request.app.state.manager
    async with manager.lock:
        if manager.operation is not None or manager.closed:
            raise OperationError(
                409,
                "operation_in_progress",
                "Wait for the current operation before saving AI settings.",
            )
        try:
            updated, selected_id = change(config, manager.settings)
        except KeyError:
            raise OperationError(
                404, "provider_not_found", "Saved provider was not found."
            ) from None
        except (ValueError, ValidationError):
            raise OperationError(
                422,
                "invalid_ai_settings",
                "AI settings are invalid; check endpoint, model and limits.",
            ) from None
        except OSError:
            raise OperationError(
                500,
                "settings_save_failed",
                "AI settings could not be saved; existing settings remain active.",
            ) from None
        manager.settings = updated
        manager.analyzer = AnalysisService(updated, request.app.state.ai_client)
        request.app.state.settings = updated
        return updated, selected_id


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
