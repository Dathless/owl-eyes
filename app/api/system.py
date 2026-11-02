"""Explicit safe metadata for the UI; never dump settings or internal capabilities."""

from urllib.parse import urlsplit

from fastapi import APIRouter, Request

from app.ai.settings import AI_FIELDS
from app.schemas import (
    Capabilities,
    ProviderCapability,
    PublicToolCapability,
    SettingDescriptor,
)
from app.store import SQLiteScanStore

router = APIRouter()

# Mirrors fixed T03 presets; these descriptions are not commands.
TOOL_DISPLAY = {
    "nmap": ("TCP port 80 service detection", 90),
    "curl": ("Verified DVWA session; HTTP headers without redirects", 20),
    "whatweb": ("Verified DVWA session; passive HTTP technology baseline", 30),
    "nikto": ("Limited web baseline; shared-origin observations retain scope", 630),
    "ffuf": ("Verified DVWA session; bounded paths; redirects not followed", 35),
    "nuclei": (
        "Authenticated DVWA; four reviewed HTTP templates; critical/high/medium/low",
        180,
    ),
    "httpx": (
        "HTTPX Toolkit: verified DVWA session; status/title/technology; no redirects",
        30,
    ),
    "wafw00f": ("Verified DVWA session; WAF fingerprint; no redirects", 90),
    "gobuster": (
        "Verified DVWA session; eight paths; wildcard precheck; no redirects",
        75,
    ),
    "wapiti": ("Verified DVWA session; passive headers, cookie flags and CSP", 90),
}
LIMITS = (
    "max_concurrent_tools",
    "tool_capture_limit_bytes",
    "retain_completed_scans",
    "scan_ttl_seconds",
    "ai_total_timeout_seconds",
    "ai_input_utf8_bytes",
    "ai_output_tokens",
    "ai_max_response_bytes",
    "ollama_context_tokens",
    "ollama_num_threads",
)


def capabilities(manager) -> Capabilities:
    settings = manager.settings
    configuration = getattr(manager, "ai_configuration", None)
    editable_ai = configuration is not None and configuration.path is not None
    tools = []
    for tool, capability in manager.capabilities.items():
        summary, timeout = TOOL_DISPLAY[tool]
        tools.append(
            PublicToolCapability(
                tool_id=tool,
                default_selected=tool in {"nmap", "curl", "whatweb", "ffuf", "nikto"},
                enabled=capability.enabled,
                version=capability.version,
                reason=capability.reason,
                preset_summary=summary,
                timeout_seconds=timeout,
                applicability_note="Configured lab target only",
                streams=(
                    ["stdout", "stderr", "artifact"]
                    if tool
                    in {
                        "whatweb",
                        "nikto",
                        "ffuf",
                        "nuclei",
                        "httpx",
                        "wafw00f",
                        "gobuster",
                        "wapiti",
                    }
                    else ["stdout", "stderr"]
                ),
            )
        )
    providers = [
        ProviderCapability(
            provider_id="ollama",
            display_name="Ollama",
            kind="local",
            enabled=settings.ollama_enabled,
            model=settings.ollama_model,
            host=urlsplit(settings.ollama_base_url).hostname,
            output_mode="json_schema",
            token_limit_field=None,
            key_configured=False,
            reason=None if settings.ollama_enabled else "missing_model",
        ),
        ProviderCapability(
            provider_id="openai_compatible",
            display_name=settings.openai_provider_name,
            model_display_name=settings.openai_model_display_name,
            kind="external",
            enabled=settings.openai_compatible_enabled,
            model=settings.openai_model,
            host=urlsplit(settings.openai_base_url).hostname
            if settings.openai_base_url
            else None,
            output_mode=settings.openai_output_mode,
            token_limit_field=settings.openai_token_limit_field,
            key_configured=bool(
                settings.openai_api_key
                and settings.openai_api_key.get_secret_value().strip()
            ),
            reason=None
            if settings.openai_compatible_enabled
            else "missing_configuration",
        ),
    ]
    providers.extend(
        ProviderCapability(
            provider_id=p.provider_id,
            kind="external",
            enabled=p.enabled,
            display_name=p.name,
            model=p.model_id,
            model_display_name=p.model_display_name,
            host=urlsplit(p.base_url).hostname,
            output_mode=p.output_mode,
            token_limit_field=p.token_limit_field,
            key_configured=p.enabled,
            reason=None if p.enabled else "missing_api_key",
        )
        for p in settings.external_providers
    )
    limits = {name: getattr(settings, name) for name in LIMITS}
    rows = []
    for name in LIMITS:
        rows.append(
            SettingDescriptor(
                key=name.upper(),
                label=name.upper(),
                group="limits",
                kind="bytes"
                if name.endswith("bytes")
                else "duration"
                if name.endswith("seconds")
                else "int",
                value=getattr(settings, name),
                source="ui"
                if configuration and name in configuration.overrides
                else "env"
                if name in settings.model_fields_set
                else "default",
                editable=editable_ai and name in AI_FIELDS,
            )
        )
    for name in (
        "lab_target_id",
        "lab_target_ip",
        "lab_target_url",
        "dvwa_auth_mode",
        "dvwa_security_level",
    ):
        value = getattr(settings, name)
        rows.append(
            SettingDescriptor(
                key=name.upper(),
                label=name.upper(),
                group="target",
                kind="string",
                value=str(value),
                source="ui"
                if configuration and name in configuration.overrides
                else "env"
                if name in settings.model_fields_set
                else "default",
                status="warn" if name.startswith("dvwa_") else "ok",
            )
        )
    for provider in providers[:2]:
        prefix = "OLLAMA" if provider.kind == "local" else "OPENAI"
        rows.append(
            SettingDescriptor(
                key=f"{prefix}_MODEL",
                label=f"{prefix}_MODEL",
                group="providers",
                kind="string",
                value=provider.model,
                source="ui"
                if configuration
                and f"{prefix.lower()}_model" in configuration.overrides
                else "env"
                if provider.model
                else "default",
                editable=bool(editable_ai),
                status="ok" if provider.model else "unset",
            )
        )
    for name, configured in (
        ("APP_PASSWORD", bool(settings.app_password.get_secret_value())),
        ("DVWA_PASSWORD", bool(settings.dvwa_password.get_secret_value())),
        ("OPENAI_API_KEY", providers[1].key_configured),
    ):
        rows.append(
            SettingDescriptor(
                key=name,
                label=name,
                group="target"
                if name == "DVWA_PASSWORD"
                else "server"
                if name == "APP_PASSWORD"
                else "providers",
                kind="secret_state",
                secret=True,
                editable=bool(editable_ai and name == "OPENAI_API_KEY"),
                source="ui"
                if configuration and name.lower() in configuration.overrides
                else "env"
                if name.lower() in settings.model_fields_set
                else "default",
                status="ok" if configured else "unset",
            )
        )
    return Capabilities(
        server_instance_id=manager.server_instance_id,
        app_version="0.1.0",
        target=manager.target,
        tools=tools,
        providers=[
            p
            for p in providers
            if p.provider_id != "openai_compatible"
            or not settings.openai_provider_deleted
        ],
        features={
            "recent_scans": True,
            "pdf_export": True,
            "cve_lookup": True,
            "analysis": manager.analyzer is not None,
            "provider_check": False,
            "persistent_state": isinstance(manager.store, SQLiteScanStore),
            "ai_settings": bool(editable_ai),
        },
        limits=limits,
        settings=rows,
    )


@router.get(
    "/api/capabilities", response_model=Capabilities, response_model_exclude_none=True
)
async def get_capabilities(request: Request):
    return capabilities(request.app.state.manager)
