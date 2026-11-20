"""Explicit safe metadata for the UI; never dump settings or internal capabilities."""

from urllib.parse import urlsplit

from fastapi import APIRouter, Request

from app.ai.settings import AI_FIELDS
from app.schemas import (
    DOMAIN_TOOL_IDS,
    HOST_TOOL_IDS,
    PUBLIC_TOOL_IDS,
    RECOMMENDED_PUBLIC_TOOL_IDS,
    Capabilities,
    ProviderCapability,
    PublicToolCapability,
    SettingDescriptor,
)
from app.services.targets import configured_targets
from app.store import SQLiteScanStore
from app.tools.adapters.ffuf import PATHS

router = APIRouter()

# Mirrors fixed T03 presets; these descriptions are not commands.
TOOL_DISPLAY = {
    "dig": ("Public DNS: A/AAAA/MX/NS/TXT/CAA; bounded queries", 30),
    "whois": ("Public domain registration; no registrar referral recursion", 25),
    "openssl": ("HTTPS TLS handshake and hostname verification with domain SNI", 20),
    "nmap": ("TCP/80 service detection; public: 24 reviewed TCP ports", 150),
    "curl": ("One HTTP response; no redirects; verified session for DVWA", 20),
    "whatweb": (
        "HTTP technology baseline; no redirects; verified session for DVWA",
        30,
    ),
    "nikto": ("DVWA-root web baseline; 200ms pause; other paths retain scope", 930),
    "ffuf": (
        f"Verified DVWA session; {len(PATHS)} paths including modules; no redirects",
        35,
    ),
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
        f"Verified DVWA session; {len(PATHS)} DVWA/module paths; wildcard precheck",
        75,
    ),
    "wapiti": ("Verified DVWA session; passive headers, cookie flags and CSP", 90),
    "dirb": (f"Verified DVWA session; {len(PATHS)} DVWA/module paths; 200ms delay", 75),
    "wget": ("Verified DVWA session; one HTTP response, no redirects", 20),
    "smbclient": ("Anonymous SMB share names on lab host TCP/445; no file access", 25),
    "rpcclient": ("Anonymous read-only srvinfo on lab host TCP/445", 20),
    "snmpget": ("Two read-only system OIDs with public on lab host UDP/161", 8),
}
PUBLIC_PRESETS = {
    "dig": "DNS công khai: A/AAAA/MX/NS/TXT/CAA; truy vấn có giới hạn",
    "whois": "Thông tin đăng ký tên miền; không theo giới thiệu registrar",
    "openssl": "Một bắt tay HTTPS với SNI và xác minh tên miền chứng thư",
    "nmap": "Nhận diện dịch vụ trên 24 cổng TCP phổ biến tại IP nslookup đã ghim",
    "curl": "Một phản hồi HTTP công khai; không theo redirect",
    "whatweb": "Nhận diện công nghệ website với tốc độ thấp; không theo redirect",
    "nikto": "Kiểm tra origin gốc; nghỉ 200ms; giới hạn scanner 900 giây",
    "ffuf": "Danh sách đường dẫn website cố định; không đệ quy hoặc theo redirect",
    "nuclei": "Bốn template HTTP đã duyệt; không OAST, headless hoặc tải template",
    "httpx": "HTTPX Toolkit: status, tiêu đề và công nghệ; không theo redirect",
    "wafw00f": "Nhận diện WAF tại origin công khai; không theo redirect",
    "gobuster": "Đường dẫn website cố định; một luồng; kiểm tra wildcard",
    "wapiti": "Kiểm tra thụ động header, cờ cookie và CSP; không crawl hoặc tấn công",
    "dirb": "Đường dẫn website cố định; không đệ quy; nghỉ 200ms",
    "wget": "Một phản hồi HTTP công khai; không redirect hoặc tải liên kết",
    "smbclient": "Liệt kê share SMB ẩn danh tại IP đã phân giải, TCP/445",
    "rpcclient": "srvinfo ẩn danh chỉ đọc tại IP đã phân giải, TCP/445",
    "snmpget": "Hai OID hệ thống chỉ đọc (public) tại IP đã phân giải, UDP/161",
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
                preset_summaries={
                    **({"dvwa": summary} if tool not in DOMAIN_TOOL_IDS else {}),
                    **(
                        {"public_domain": PUBLIC_PRESETS[tool]}
                        if tool in PUBLIC_TOOL_IDS
                        else {}
                    ),
                },
                timeout_seconds=timeout,
                requires_https=tool == "openssl",
                category="domain"
                if tool in DOMAIN_TOOL_IDS
                else "host"
                if tool in HOST_TOOL_IDS
                else "web",
                applicable_to=(
                    ["public_domain"]
                    if tool in DOMAIN_TOOL_IDS
                    else ["dvwa", "public_domain"]
                    if tool in PUBLIC_TOOL_IDS
                    else ["dvwa"]
                ),
                recommended_for=["public_domain"]
                if tool in RECOMMENDED_PUBLIC_TOOL_IDS
                else [],
                applicability_note=(
                    "Public domain only; registration/DNS or one HTTPS handshake"
                    if tool in DOMAIN_TOOL_IDS
                    else "Host-service inventory on the lab IP or the domain's "
                    "nslookup-resolved IP; does not test web modules"
                    if tool in HOST_TOOL_IDS
                    else "Lab: verified session; public: pinned origin without login"
                ),
                streams=(
                    ["stdout", "stderr", "artifact"]
                    if tool
                    in {
                        "curl",
                        "whatweb",
                        "nikto",
                        "ffuf",
                        "nuclei",
                        "httpx",
                        "wafw00f",
                        "gobuster",
                        "wapiti",
                        "dirb",
                        "wget",
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
            context_tokens=settings.ollama_context_tokens,
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
            context_tokens=settings.openai_context_tokens,
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
            context_tokens=p.context_tokens,
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
        targets=configured_targets(settings),
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
            "target_profiles": True,
        },
        limits=limits,
        settings=rows,
    )


@router.get(
    "/api/capabilities", response_model=Capabilities, response_model_exclude_none=True
)
async def get_capabilities(request: Request):
    return capabilities(request.app.state.manager)
