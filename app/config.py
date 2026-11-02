"""Bootstrap configuration; lab addresses must be supplied explicitly."""

from ipaddress import IPv4Address, IPv4Network
from pathlib import Path
from typing import Annotated, Literal, Self
from urllib.parse import urlsplit

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    field_validator,
    model_validator,
)
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LAB_NETWORK = IPv4Network("192.168.146.0/24")


def validate_lab_address(address: IPv4Address) -> IPv4Address:
    if address not in LAB_NETWORK or int(address) - int(
        LAB_NETWORK.network_address
    ) in (
        0,
        1,
        255,
    ):
        raise ValueError("Address must be an allowed Host-only lab address")
    return address


LabAddress = Annotated[IPv4Address, AfterValidator(validate_lab_address)]


def validate_target_url(url: str, ip: IPv4Address) -> str:
    if any(ord(character) <= 32 or ord(character) == 127 for character in url):
        raise ValueError("Target URL contains whitespace or control characters")
    parts = urlsplit(url)
    if (
        parts.scheme != "http"
        or parts.netloc not in {str(ip), f"{ip}:80"}
        or parts.path not in {"/dvwa", "/dvwa/"}
        or "?" in url
        or "#" in url
    ):
        raise ValueError("Target must be the configured lab IPv4 at HTTP port 80 /dvwa")
    return url


def normalize_external_url(url: str) -> str:
    parts = urlsplit(url)
    if (
        any(ord(c) <= 32 or ord(c) == 127 for c in url)
        or parts.scheme != "https"
        or not parts.hostname
        or parts.username is not None
        or parts.password is not None
        or "?" in url
        or "#" in url
        or "\\" in url
    ):
        raise ValueError(
            "External provider requires an HTTPS URL without credentials/query"
        )
    _ = parts.port
    path = parts.path.rstrip("/")
    if not path:
        path = "/v1"
    return parts._replace(path=path).geturl()


class ExternalProviderConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", hide_input_in_errors=True)
    provider_id: str = Field(pattern=r"^external_[0-9a-f]{32}$")
    name: str = Field(min_length=1, max_length=100)
    base_url: str = Field(max_length=2048)
    model_id: str = Field(min_length=1, max_length=200)
    api_key: SecretStr | None = Field(default=None, max_length=4096)
    model_display_name: str | None = Field(default=None, min_length=1, max_length=100)
    output_mode: Literal["json_schema", "json_object", "prompt_json"] = "json_schema"
    token_limit_field: Literal["max_tokens", "max_completion_tokens"] = "max_tokens"

    @field_validator("base_url")
    @classmethod
    def normalize_url(cls, value):
        return normalize_external_url(value)

    @property
    def enabled(self) -> bool:
        return bool(self.api_key and self.api_key.get_secret_value().strip())


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="forbid",
        hide_input_in_errors=True,
        allow_inf_nan=False,
    )

    app_host: LabAddress
    app_port: int = Field(default=8000, ge=1, le=65535)
    app_username: str = Field(default="labadmin", min_length=1)
    app_password: SecretStr = Field(min_length=16)
    lab_target_id: Literal["dvwa"] = "dvwa"
    lab_target_ip: LabAddress
    lab_target_url: str
    history_db_path: Path = PROJECT_ROOT / "data" / "penchecker.sqlite3"
    dvwa_username: str = Field(default="admin", min_length=1, max_length=100)
    dvwa_password: SecretStr = Field(default=SecretStr("password"), min_length=1)
    dvwa_auth_mode: Literal[
        "public_only_unknown",
        "public_only_login_required",
        "operator_declared_disabled",
    ] = "public_only_unknown"
    dvwa_security_level: Literal["unknown", "low", "medium", "high", "impossible"] = (
        "unknown"
    )
    max_concurrent_tools: int = Field(default=3, ge=1, le=3)
    tool_capture_limit_bytes: int = Field(default=524288, gt=0)
    retain_completed_scans: int = Field(default=10, gt=0)
    scan_ttl_seconds: int = Field(default=3600, gt=0)
    ai_total_timeout_seconds: float = Field(default=180, gt=0)
    ai_input_utf8_bytes: int = Field(default=12000, gt=0)
    ai_output_tokens: int = Field(default=3072, gt=0)
    ai_max_response_bytes: int = Field(default=262144, gt=0)
    external_providers: list[ExternalProviderConfig] = Field(
        default_factory=list, max_length=32
    )
    openai_provider_deleted: bool = False
    openai_provider_name: str = Field(
        default="External AI", min_length=1, max_length=100
    )
    openai_model_display_name: str | None = Field(
        default=None, min_length=1, max_length=100
    )
    openai_base_url: str | None = None
    openai_api_key: SecretStr | None = None
    openai_model: str | None = Field(default=None, min_length=1, max_length=200)
    openai_output_mode: Literal["json_schema", "json_object", "prompt_json"] = (
        "json_schema"
    )
    openai_token_limit_field: Literal["max_tokens", "max_completion_tokens"] = (
        "max_tokens"
    )
    ollama_base_url: str = "http://127.0.0.1:11434"
    ollama_num_threads: int = Field(default=4, ge=1, le=64)
    ollama_context_tokens: int = Field(default=8192, ge=1024, le=262144)
    ollama_model: str | None = Field(default=None, min_length=1, max_length=200)

    @field_validator("history_db_path")
    @classmethod
    def resolve_history_path(cls, path: Path) -> Path:
        return path if path.is_absolute() else PROJECT_ROOT / path

    @field_validator("openai_base_url", "ollama_base_url")
    @classmethod
    def validate_provider_url(cls, url: str | None, info) -> str | None:
        if url is None:
            return None
        parts = urlsplit(url)
        if (
            any(ord(character) <= 32 or ord(character) == 127 for character in url)
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or "?" in url
            or "#" in url
            or "\\" in url
        ):
            raise ValueError("Invalid provider URL")
        # Accessing port also rejects malformed/out-of-range ports.
        _ = parts.port
        if info.field_name == "openai_base_url":
            return normalize_external_url(url)
        elif parts.scheme not in {"http", "https"} or parts.path not in {"", "/"}:
            raise ValueError("Ollama requires an HTTP(S) origin URL")
        return url.rstrip("/")

    @field_validator("external_providers")
    @classmethod
    def unique_provider_ids(cls, values):
        if len({p.provider_id for p in values}) != len(values):
            raise ValueError("Duplicate saved provider ID")
        return values

    def provider_enabled(self, provider_id: str) -> bool:
        if provider_id == "ollama":
            return self.ollama_enabled
        if provider_id == "openai_compatible":
            return self.openai_compatible_enabled
        return any(
            p.provider_id == provider_id and p.enabled for p in self.external_providers
        )

    def provider_model(self, provider_id: str) -> str | None:
        if provider_id == "ollama":
            return self.ollama_model
        if provider_id == "openai_compatible":
            return self.openai_model
        return next(
            (
                p.model_id
                for p in self.external_providers
                if p.provider_id == provider_id
            ),
            None,
        )

    @property
    def app_origin(self) -> str:
        return f"http://{self.app_host}:{self.app_port}"

    @property
    def ollama_enabled(self) -> bool:
        return bool(self.ollama_model and self.ollama_model.strip())

    @property
    def openai_compatible_enabled(self) -> bool:
        return bool(
            not self.openai_provider_deleted
            and self.openai_base_url
            and self.openai_model
            and self.openai_model.strip()
            and self.openai_api_key
            and self.openai_api_key.get_secret_value().strip()
        )

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        if self.app_host == self.lab_target_ip:
            raise ValueError("Application and target addresses must differ")
        validate_target_url(self.lab_target_url, self.lab_target_ip)
        return self
