"""Private atomic AI-only overrides; saved credentials are never returned."""

import json
import os
import tempfile
from pathlib import Path
from uuid import uuid4

from pydantic import BaseModel, SecretStr

from app.config import ExternalProviderConfig, Settings
from app.schemas import AISettingsUpdate, AISettingsView, ProviderProfileView

AI_FIELDS = tuple(
    name for name in AISettingsUpdate.model_fields if name != "clear_openai_api_key"
)
PRIVATE_FILE_LIMIT = 262144
STORAGE_FIELDS = {*AI_FIELDS, "external_providers", "openai_provider_deleted"}


def private_value(value):
    if isinstance(value, SecretStr):
        return value.get_secret_value()
    if isinstance(value, BaseModel):
        return private_value(value.model_dump())
    if isinstance(value, dict):
        return {key: private_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [private_value(item) for item in value]
    return value


OPTIONS = {
    "openai_output_mode": ["json_schema", "json_object", "prompt_json"],
    "openai_token_limit_field": ["max_tokens", "max_completion_tokens"],
}


class AIConfiguration:
    def __init__(self, path: Path | None):
        self.path = path
        self.overrides = {}
        if path is not None and path.exists():
            if path.is_symlink() or path.stat().st_size > PRIVATE_FILE_LIMIT:
                raise ValueError("Invalid private AI settings file")
            path.chmod(0o600)
            for line in path.read_text(encoding="utf-8").split("\n"):
                if not line.strip() or line.startswith("#"):
                    continue
                key, sep, value = line.partition("=")
                if not sep or key.lower() not in STORAGE_FIELDS:
                    raise ValueError("Invalid private AI settings field")
                self.overrides[key.lower()] = json.loads(value)

    def apply(self, base: Settings) -> Settings:
        effective = Settings(_env_file=None, **(base.model_dump() | self.overrides))
        effective.__pydantic_fields_set__ = base.model_fields_set | set(self.overrides)
        return effective

    def view(self, settings: Settings) -> AISettingsView:
        fields = []
        values = {}
        for name in AI_FIELDS:
            secret = name == "openai_api_key"
            value = getattr(settings, name)
            if not secret:
                values[name] = value
            fields.append(
                {
                    "key": name,
                    "label": name.upper(),
                    "secret": secret,
                    "kind": "password"
                    if secret
                    else "select"
                    if name in OPTIONS
                    else "number"
                    if isinstance(value, (int, float))
                    else "text",
                    "options": OPTIONS.get(name, []),
                }
            )
        return AISettingsView(
            values=values,
            fields=fields,
            openai_key_configured=bool(
                settings.openai_api_key
                and settings.openai_api_key.get_secret_value().strip()
            ),
        )

    def save(self, base: Settings, patch: AISettingsUpdate) -> Settings:
        if self.path is None:
            raise ValueError("AI settings editor is unavailable")
        changes = patch.model_dump(exclude_unset=True)
        clear = changes.pop("clear_openai_api_key", False)
        key = changes.get("openai_api_key")
        if key is None or not key.get_secret_value().strip():
            changes.pop("openai_api_key", None)
        elif clear:
            raise ValueError("Cannot set and clear a key together")
        if clear:
            changes["openai_api_key"] = None
        if any(
            name.startswith("openai_") and value is not None
            for name, value in changes.items()
        ):
            changes["openai_provider_deleted"] = False
        return self._persist(base, changes)

    def _persist(self, base: Settings, changes: dict) -> Settings:
        if self.path is None:
            raise ValueError("AI settings editor is unavailable")
        overrides = self.overrides | changes
        effective = Settings(_env_file=None, **(base.model_dump() | overrides))
        effective.__pydantic_fields_set__ = base.model_fields_set | set(overrides)
        # Serialize only the UI-owned override fields, never the complete Settings.
        encoded = private_value(overrides)
        content = "".join(
            f"{name.upper()}={json.dumps(value, ensure_ascii=False)}\n"
            for name, value in encoded.items()
        )
        if len(content.encode()) > PRIVATE_FILE_LIMIT:
            raise ValueError("AI settings exceed the file limit")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(
            prefix=".env.ai.", dir=self.path.parent
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        finally:
            Path(temporary).unlink(missing_ok=True)
        self.overrides = encoded
        return effective

    def profile_views(self, settings: Settings) -> list[ProviderProfileView]:
        profiles = [
            ProviderProfileView(
                provider_id="openai_compatible",
                name=settings.openai_provider_name,
                base_url=settings.openai_base_url,
                model_id=settings.openai_model,
                model_display_name=settings.openai_model_display_name,
                output_mode=settings.openai_output_mode,
                token_limit_field=settings.openai_token_limit_field,
                key_configured=bool(
                    settings.openai_api_key
                    and settings.openai_api_key.get_secret_value().strip()
                ),
                enabled=settings.openai_compatible_enabled,
            )
        ]
        if settings.openai_provider_deleted:
            profiles = []
        profiles.extend(
            ProviderProfileView(
                provider_id=p.provider_id,
                name=p.name,
                base_url=p.base_url,
                model_id=p.model_id,
                model_display_name=p.model_display_name,
                output_mode=p.output_mode,
                token_limit_field=p.token_limit_field,
                key_configured=p.enabled,
                enabled=p.enabled,
            )
            for p in settings.external_providers
        )
        return profiles

    def save_provider(self, base, patch, provider_id=None):
        changes = patch.model_dump(exclude_unset=True)
        clear = changes.pop("clear_api_key", False)
        key = changes.get("api_key")
        if key is None or not key.get_secret_value().strip():
            changes.pop("api_key", None)
        elif clear:
            raise ValueError("Cannot set and clear a key together")
        if clear:
            changes["api_key"] = None
        if provider_id == "openai_compatible":
            if base.openai_provider_deleted:
                raise KeyError(provider_id)
            names = {
                "name": "openai_provider_name",
                "base_url": "openai_base_url",
                "model_id": "openai_model",
                "model_display_name": "openai_model_display_name",
                "api_key": "openai_api_key",
                "output_mode": "openai_output_mode",
                "token_limit_field": "openai_token_limit_field",
            }
            values = {names[key]: value for key, value in changes.items()}
            # Profile edits reuse legacy key semantics, including explicit clearing.
            if clear:
                values.pop("openai_api_key", None)
                values["clear_openai_api_key"] = True
            return self.save(base, AISettingsUpdate(**values)), provider_id
        profiles = list(base.external_providers)
        if provider_id is None:
            provider_id = "external_" + uuid4().hex
            profile = ExternalProviderConfig(provider_id=provider_id, **changes)
            profiles.append(profile)
        else:
            old = next((p for p in profiles if p.provider_id == provider_id), None)
            if old is None:
                raise KeyError(provider_id)
            profile = ExternalProviderConfig(**(old.model_dump() | changes))
            profiles = [
                profile if p.provider_id == provider_id else p for p in profiles
            ]
        return self._persist(base, {"external_providers": profiles}), provider_id

    def delete_provider(self, base: Settings, provider_id: str):
        if provider_id == "openai_compatible":
            if base.openai_provider_deleted:
                raise KeyError(provider_id)
            changes = {
                "openai_provider_deleted": True,
                "openai_base_url": None,
                "openai_api_key": None,
                "openai_model": None,
                "openai_model_display_name": None,
                "openai_provider_name": "External AI",
            }
            return self._persist(base, changes), provider_id
        profiles = [p for p in base.external_providers if p.provider_id != provider_id]
        if len(profiles) == len(base.external_providers):
            raise KeyError(provider_id)
        return self._persist(base, {"external_providers": profiles}), provider_id
