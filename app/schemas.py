"""Strict shared contracts. Runtime ownership belongs to the manager/adapters."""

import json
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Literal, Self
from uuid import UUID

from pydantic import (
    AfterValidator,
    AwareDatetime,
    BaseModel,
    ConfigDict,
    Field,
    IPvAnyAddress,
    JsonValue,
    SecretStr,
    field_validator,
    model_validator,
)

from app.config import (
    normalize_domain_url,
    public_address,
    validate_lab_address,
    validate_target_url,
)


class ContractModel(BaseModel):
    model_config = ConfigDict(
        extra="forbid", hide_input_in_errors=True, allow_inf_nan=False
    )


def uuid_string(value: str) -> str:
    return str(UUID(value))


def utc_timestamp(value: datetime) -> datetime:
    return value.astimezone(UTC)


UUIDString = Annotated[
    str, AfterValidator(uuid_string), Field(json_schema_extra={"format": "uuid"})
]
UTCTimestamp = Annotated[AwareDatetime, AfterValidator(utc_timestamp)]
Note = Annotated[str, Field(max_length=500)]
ModelName = Annotated[str, Field(min_length=1, max_length=200)]


class ToolId(StrEnum):
    DIG = "dig"
    WHOIS = "whois"
    OPENSSL = "openssl"
    NMAP = "nmap"
    CURL = "curl"
    WHATWEB = "whatweb"
    FFUF = "ffuf"
    NIKTO = "nikto"
    NUCLEI = "nuclei"
    HTTPX = "httpx"
    WAFW00F = "wafw00f"
    GOBUSTER = "gobuster"
    WAPITI = "wapiti"
    DIRB = "dirb"
    WGET = "wget"
    SMBCLIENT = "smbclient"
    RPCCLIENT = "rpcclient"
    SNMPGET = "snmpget"


HOST_TOOL_IDS = frozenset(
    {ToolId.NMAP, ToolId.SMBCLIENT, ToolId.RPCCLIENT, ToolId.SNMPGET}
)
DOMAIN_TOOL_IDS = frozenset({ToolId.DIG, ToolId.WHOIS, ToolId.OPENSSL})
PUBLIC_TOOL_IDS = DOMAIN_TOOL_IDS | {ToolId.CURL, ToolId.WHATWEB}
WEB_TOOL_IDS = frozenset(ToolId) - HOST_TOOL_IDS - DOMAIN_TOOL_IDS


class ProviderId(StrEnum):
    OLLAMA = "ollama"
    OPENAI_COMPATIBLE = "openai_compatible"


ProviderKey = Annotated[
    str, Field(pattern=r"^(ollama|openai_compatible|external_[0-9a-f]{32})$")
]


class ToolCapability(ContractModel):
    tool_id: ToolId
    executable: str | None = None
    version: str | None = Field(default=None, max_length=500)
    enabled: bool
    reason: str | None = Field(default=None, max_length=240)


class ToolState(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    OUTPUT_LIMITED = "output_limited"


class ParseStatus(StrEnum):
    PENDING = "pending"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class Scope(StrEnum):
    DOMAIN = "domain"
    HOST_SERVICE = "host_service"
    HTTP_ORIGIN = "http_origin"
    DVWA_PATH = "dvwa_path"
    OTHER_PATH = "other_path"
    UNKNOWN = "unknown"


class ScanState(StrEnum):
    QUEUED = "queued"
    COLLECTING = "collecting"
    ANALYZING = "analyzing"
    CANCELLING = "cancelling"
    COMPLETED = "completed"
    ANALYSIS_FAILED = "analysis_failed"
    COLLECTION_FAILED = "collection_failed"
    CANCELLED = "cancelled"


class TargetSpec(ContractModel):
    target_id: str = Field(default="dvwa", pattern=r"^(dvwa|target_[0-9a-f]{32})$")
    kind: Literal["dvwa", "public_domain"] = "dvwa"
    name: str | None = Field(default=None, min_length=1, max_length=100)
    url: str
    ip: IPvAnyAddress | None = None
    port: Literal[80, 443] = 80
    scheme: Literal["http", "https"] = "http"
    base_path: Literal["/dvwa", "/"] = "/dvwa"
    auth_mode: Literal[
        "public_only_unknown",
        "public_only_login_required",
        "operator_declared_disabled",
    ] = "public_only_unknown"
    security_level: Literal["unknown", "low", "medium", "high", "impossible"] = (
        "unknown"
    )

    @model_validator(mode="after")
    def validate_target(self) -> Self:
        if self.kind == "dvwa":
            if self.ip is None or self.ip.version != 4:
                raise ValueError("DVWA requires a lab IPv4 address")
            validate_lab_address(self.ip)
            validate_target_url(self.url, self.ip)
            if (self.port, self.scheme, self.base_path) != (80, "http", "/dvwa"):
                raise ValueError("Invalid DVWA target metadata")
        else:
            from urllib.parse import urlsplit

            self.url = normalize_domain_url(self.url)
            parts = urlsplit(self.url)
            if (self.scheme, self.port, self.base_path) != (
                parts.scheme,
                443 if parts.scheme == "https" else 80,
                "/",
            ):
                raise ValueError("Invalid public target metadata")
            if self.ip is not None:
                public_address(self.ip)
        return self


class ScanCreate(ContractModel):
    target_id: str = Field(default="dvwa", pattern=r"^(dvwa|target_[0-9a-f]{32})$")
    tools: list[ToolId] = Field(min_length=1, max_length=18)
    provider_id: ProviderKey

    @field_validator("tools")
    @classmethod
    def unique_tools(cls, tools: list[ToolId]) -> list[ToolId]:
        if len(set(tools)) != len(tools):
            raise ValueError("Duplicate tools are not allowed")
        return tools


class AnalysisRetry(ContractModel):
    provider_id: ProviderKey


class EmptyRequest(ContractModel):
    pass


class ToolSpec(ContractModel):
    tool_id: ToolId
    argv: tuple[str, ...] = Field(min_length=1)
    config_directory: Path | None = None
    timeout_seconds: float = Field(gt=0)
    artifact_paths: tuple[Path, ...] = ()


class Capture(ContractModel):
    stdout: str = ""
    stderr: str = ""
    artifacts: dict[str, str] = Field(default_factory=dict)
    return_code: int | None = None
    started_at: UTCTimestamp | None = None
    finished_at: UTCTimestamp
    duration_ms: float = Field(default=0, ge=0)
    termination_reason: (
        Literal["normal", "spawn_error", "timeout", "cancelled", "output_limit"] | None
    ) = None
    output_truncated: bool = False


class ErrorInfo(ContractModel):
    code: str = Field(pattern=r"^[a-z][a-z0-9_]{0,79}$")
    message: str = Field(min_length=1, max_length=240)
    retryable: bool = False
    scan_id: UUIDString | None = None


class ErrorResponse(ContractModel):
    error: ErrorInfo


class Evidence(ContractModel):
    id: UUIDString
    tool_id: ToolId
    source: Literal["stdout", "stderr", "artifact"]
    locator: str = Field(min_length=1, max_length=500)
    excerpt: str = Field(max_length=1000)


def json_depth(value: JsonValue) -> int:
    if isinstance(value, dict):
        return 1 + max((json_depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((json_depth(item) for item in value), default=0)
    return 0


class Observation(ContractModel):
    id: UUIDString
    tool_id: ToolId
    kind: Literal[
        "port", "http", "technology", "scanner_signal", "dns", "registration", "tls"
    ]
    scope: Scope
    subject: str = Field(max_length=200)
    value: dict[str, JsonValue]
    evidence_ids: list[UUIDString]

    @field_validator("value")
    @classmethod
    def bounded_json(cls, value: dict[str, JsonValue]) -> dict[str, JsonValue]:
        if json_depth(value) > 4:
            raise ValueError("Observation JSON exceeds depth 4")
        try:
            size = len(
                json.dumps(
                    value, ensure_ascii=False, allow_nan=False, separators=(",", ":")
                ).encode("utf-8")
            )
        except (ValueError, UnicodeError) as error:
            raise ValueError("Observation value must be finite UTF-8 JSON") from error
        if size > 2048:
            raise ValueError("Observation JSON exceeds 2048 UTF-8 bytes")
        return value


class ToolRunSummary(ContractModel):
    preset_id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    reason: Note = ""
    state: ToolState
    parse_status: ParseStatus = ParseStatus.PENDING
    started_at: UTCTimestamp | None = None
    finished_at: UTCTimestamp | None = None
    duration_ms: float = Field(default=0, ge=0)
    warnings: list[Note] = Field(default_factory=list, max_length=20)


class ToolSnapshot(ContractModel):
    tool_id: ToolId
    state: ToolState
    parse_status: ParseStatus = ParseStatus.PENDING
    started_at: UTCTimestamp | None = None
    finished_at: UTCTimestamp | None = None
    duration_ms: float = Field(default=0, ge=0)
    observations: list[Observation] = Field(default_factory=list, max_length=400)
    evidence: list[Evidence] = Field(default_factory=list, max_length=400)
    runs: list[ToolRunSummary] = Field(default_factory=list, max_length=4)
    warnings: list[Note] = Field(default_factory=list, max_length=20)
    error: ErrorInfo | None = None


class ToolResult(ToolSnapshot):
    capture: Capture | None = None
    run_captures: list[Capture | None] = Field(default_factory=list, max_length=3)


class CollectionAction(ContractModel):
    action_id: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    reason: Note


class CollectionDecision(ContractModel):
    actions: list[CollectionAction] = Field(max_length=2)
    reason: Note


class CollectionStep(ContractModel):
    round: int = Field(ge=1, le=5)
    provider_id: ProviderKey
    model: str | None = Field(default=None, max_length=200)
    state: Literal["planned", "stopped", "rejected", "unavailable", "limited"]
    reason: Note = ""
    actions: list[CollectionAction] = Field(default_factory=list, max_length=2)
    created_at: UTCTimestamp


class FindingDraft(ContractModel):
    title: str = Field(min_length=1, max_length=160)
    severity: Severity
    assessment: Literal["observed", "suspected"]
    scope: Scope
    description: str = Field(max_length=3000)
    impact: str = Field(max_length=3000)
    evidence_ids: list[UUIDString] = Field(min_length=1, max_length=10)
    recommendation: str = Field(max_length=3000)

    @field_validator("evidence_ids")
    @classmethod
    def unique_evidence(cls, ids: list[str]) -> list[str]:
        if len(set(ids)) != len(ids):
            raise ValueError("Finding evidence IDs must be unique")
        return ids


class Finding(FindingDraft):
    id: UUIDString


class AnalysisDraft(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    summary: str = Field(max_length=2000)
    overall_risk: Severity
    findings: list[FindingDraft] = Field(max_length=30)
    limitations: list[Note] = Field(max_length=12)


class AnalysisReport(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    summary: str = Field(max_length=2000)
    overall_risk: Severity
    findings: list[Finding] = Field(max_length=30)
    limitations: list[Note] = Field(max_length=32)


class ReportEnvelope(ContractModel):
    report: AnalysisReport
    revision: int = Field(ge=1)
    provider_id: ProviderKey
    model: ModelName
    generated_at: UTCTimestamp


class AnalysisAttempt(ContractModel):
    attempt_no: int = Field(ge=1)
    provider_id: ProviderKey
    model: ModelName
    state: Literal["running", "succeeded", "failed", "cancelled"]
    started_at: UTCTimestamp
    finished_at: UTCTimestamp | None = None
    duration_ms: float | None = Field(default=None, ge=0)
    error: ErrorInfo | None = None


class AnalysisOutcome(ContractModel):
    report: AnalysisReport | None = None
    attempts: list[AnalysisAttempt] = Field(default_factory=list, max_length=2)
    error: ErrorInfo | None = None

    @model_validator(mode="after")
    def exclusive_result(self) -> Self:
        if self.report is not None and self.error is not None:
            raise ValueError("Analysis cannot return both a report and an error")
        return self


class CVEScore(ContractModel):
    version: str = Field(max_length=16)
    score: float = Field(ge=0, le=10)
    vector: str = Field(max_length=500)
    source: str = Field(max_length=300)


class CVEMatchReason(ContractModel):
    basis: Literal["scanner_reference", "reported_version"]
    detail: str = Field(max_length=500)
    scope: Scope
    evidence_ids: list[UUIDString] = Field(min_length=1, max_length=10)


class CVECandidate(ContractModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,19}$")
    title: str = Field(max_length=160)
    description: str = Field(max_length=6000)
    affected: list[Annotated[str, Field(max_length=1000)]] = Field(max_length=20)
    scores: list[CVEScore] = Field(max_length=8)
    weaknesses: list[Annotated[str, Field(max_length=100)]] = Field(max_length=20)
    references: list[Annotated[str, Field(max_length=2000)]] = Field(max_length=20)
    source_url: str = Field(max_length=200)
    published: str | None = Field(default=None, max_length=80)
    modified: str | None = Field(default=None, max_length=80)
    retrieved_at: UTCTimestamp
    reasons: list[CVEMatchReason] = Field(min_length=1, max_length=10)


class CVELookup(ContractModel):
    state: Literal["completed", "partial", "failed", "insufficient_evidence"]
    checked_at: UTCTimestamp
    matches: list[CVECandidate] = Field(default_factory=list, max_length=20)
    warnings: list[Note] = Field(default_factory=list, max_length=20)
    queries_completed: int = Field(default=0, ge=0, le=4)


class ScanRecord(ContractModel):
    scan_id: UUIDString
    server_instance_id: UUIDString
    target: TargetSpec
    collection_phase: Literal["default", "planning", "followup", "complete"] = "default"
    collection_finished_at: UTCTimestamp | None = None
    collection_steps: list[CollectionStep] = Field(default_factory=list, max_length=6)
    state: ScanState
    provider_id: ProviderKey
    tools: dict[ToolId, ToolResult] = Field(default_factory=dict, max_length=18)
    attempts: list[AnalysisAttempt] = Field(default_factory=list, max_length=20)
    next_attempt_no: int = Field(default=1, ge=1)
    report: ReportEnvelope | None = None
    report_url: str | None = Field(
        default=None, pattern=r"^/api/scans/[0-9a-f-]{36}/reports/[1-9][0-9]*\.html$"
    )
    analysis_revision: int = Field(default=0, ge=0)
    partial: bool = False
    warnings: list[Note] = Field(default_factory=list, max_length=100)
    created_at: UTCTimestamp
    finished_at: UTCTimestamp | None = None
    failure: ErrorInfo | None = None
    cve_lookup: CVELookup | None = None


class ScanSnapshot(ContractModel):
    scan_id: UUIDString
    server_instance_id: UUIDString
    target: TargetSpec
    collection_phase: Literal["default", "planning", "followup", "complete"] = "default"
    collection_finished_at: UTCTimestamp | None = None
    collection_steps: list[CollectionStep] = Field(default_factory=list, max_length=6)
    state: ScanState
    provider_id: ProviderKey
    tools: dict[ToolId, ToolSnapshot] = Field(max_length=18)
    attempts: list[AnalysisAttempt] = Field(max_length=20)
    report: ReportEnvelope | None
    report_url: str | None = None
    analysis_revision: int = Field(ge=0)
    partial: bool
    warnings: list[Note] = Field(max_length=100)
    created_at: UTCTimestamp
    finished_at: UTCTimestamp | None
    failure: ErrorInfo | None = None
    cve_lookup: CVELookup | None = None

    @classmethod
    def from_record(cls, record: ScanRecord) -> Self:
        # Project only named public fields; internal capture/counters never enter JSON.
        values = {
            name: getattr(record, name) for name in cls.model_fields if name != "tools"
        }
        values["tools"] = {
            tool: ToolSnapshot(
                **{name: getattr(result, name) for name in ToolSnapshot.model_fields}
            )
            for tool, result in record.tools.items()
        }
        return cls(**values)


class ToolCoverage(ContractModel):
    tool_id: ToolId
    state: ToolState
    parse_status: ParseStatus
    warnings: list[Note] = Field(default_factory=list, max_length=20)


class AnalysisSnapshot(ContractModel):
    target: TargetSpec
    tool_coverage: list[ToolCoverage] = Field(max_length=18)
    observations: list[Observation] = Field(max_length=1800)
    included_evidence: list[Evidence] = Field(max_length=50)
    omitted_evidence_count: int = Field(ge=0)
    truncated: bool
    verified_sessions: dict[
        ToolId, Literal["low", "medium", "high", "impossible", "unknown"]
    ] = Field(default_factory=dict, max_length=11)


class OutputPage(ContractModel):
    text: str = Field(max_length=16384)
    next_offset: int = Field(ge=0)
    has_more: bool


class ScanSummary(ContractModel):
    scan_id: UUIDString
    state: ScanState
    provider_id: ProviderKey
    partial: bool
    created_at: UTCTimestamp
    finished_at: UTCTimestamp | None
    tools: dict[ToolId, ToolState]
    overall_risk: Severity | None
    target_url: str | None = None
    report_url: str | None = None


class HistoryCleared(ContractModel):
    deleted: int = Field(ge=0)


class ScanList(ContractModel):
    scans: list[ScanSummary]
    total: int = 0
    offset: int = 0
    has_more: bool = False
    active_scan_id: UUIDString | None = None


class AISettingsUpdate(ContractModel):
    openai_provider_name: str | None = Field(default=None, min_length=1, max_length=100)
    openai_model_display_name: str | None = Field(
        default=None, min_length=1, max_length=100
    )
    ollama_base_url: str | None = Field(default=None, max_length=2048)
    ollama_model: ModelName | None = None
    openai_base_url: str | None = Field(default=None, max_length=2048)
    openai_model: ModelName | None = None
    openai_api_key: SecretStr | None = Field(default=None, max_length=4096)
    clear_openai_api_key: bool = False
    openai_output_mode: Literal["json_schema", "json_object", "prompt_json"] | None = (
        None
    )
    openai_token_limit_field: Literal["max_tokens", "max_completion_tokens"] | None = (
        None
    )
    ai_total_timeout_seconds: float | None = Field(default=None, gt=0, le=3600)
    ai_input_utf8_bytes: int | None = Field(default=None, gt=0, le=1048576)
    ai_output_tokens: int | None = Field(default=None, gt=0, le=32768)
    ai_max_response_bytes: int | None = Field(default=None, gt=0, le=4194304)
    ollama_context_tokens: int | None = Field(default=None, ge=1024, le=262144)
    ollama_num_threads: int | None = Field(default=None, ge=1, le=64)


class AISettingsView(ContractModel):
    values: dict[str, JsonValue]
    fields: list[dict[str, JsonValue]]
    openai_key_configured: bool


class ProjectSettingsUpdate(ContractModel):
    lab_target_ip: str | None = Field(default=None, max_length=64)
    lab_target_url: str | None = Field(default=None, max_length=2048)
    dvwa_username: str | None = Field(default=None, min_length=1, max_length=100)
    dvwa_password: SecretStr | None = Field(default=None, max_length=4096)
    ai_agent_enabled: bool | None = None
    ai_agent_max_loops: int | None = Field(default=None, ge=1, le=20)
    ai_total_timeout_seconds: float | None = Field(default=None, gt=0, le=3600)


class ProjectSettingsView(ContractModel):
    editable: bool
    host: dict[str, JsonValue]
    target: dict[str, JsonValue]
    general: dict[str, JsonValue]
    system: dict[str, JsonValue]


class PublicToolCapability(ContractModel):
    tool_id: ToolId
    default_selected: bool = True
    enabled: bool
    version: str | None = None
    reason: str | None = None
    preset_summary: str
    timeout_seconds: float | None = None
    applicability_note: str
    applicable_to: list[Literal["dvwa", "public_domain"]] = Field(
        default_factory=lambda: ["dvwa"]
    )
    recommended_for: list[Literal["dvwa", "public_domain"]] = Field(
        default_factory=list
    )
    requires_https: bool = False
    streams: list[Literal["stdout", "stderr", "artifact"]]


class ProviderCapability(ContractModel):
    display_name: str | None = Field(default=None, max_length=100)
    model_display_name: str | None = Field(default=None, max_length=100)
    provider_id: ProviderKey
    kind: Literal["local", "external"]
    enabled: bool
    model: ModelName | None = None
    host: str | None = None
    output_mode: str
    token_limit_field: str | None = None
    key_configured: bool
    reason: str | None = None


class SettingDescriptor(ContractModel):
    key: str
    group: str
    label: str
    kind: Literal[
        "string",
        "int",
        "bytes",
        "duration",
        "bool",
        "enum",
        "url",
        "ip",
        "secret_state",
        "list",
    ]
    value: JsonValue = None
    source: Literal["env", "default", "derived", "ui"]
    status: Literal["ok", "warn", "error", "unset"] = "ok"
    secret: bool = False
    editable: bool = False


class Capabilities(ContractModel):
    server_instance_id: UUIDString
    app_version: str
    schema_version: str = "1.0"
    target: TargetSpec
    targets: list[TargetSpec] = Field(default_factory=list, max_length=33)
    tools: list[PublicToolCapability]
    providers: list[ProviderCapability]
    features: dict[str, bool]
    limits: dict[str, int | float]
    settings: list[SettingDescriptor]


class TargetProfileUpdate(ContractModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    kind: Literal["dvwa", "public_domain"] | None = None
    url: str | None = Field(default=None, min_length=1, max_length=2048)
    ip: str | None = Field(default=None, max_length=64)


class TargetProfileCreate(TargetProfileUpdate):
    name: str = Field(min_length=1, max_length=100)
    kind: Literal["dvwa", "public_domain"] = "public_domain"
    url: str = Field(min_length=1, max_length=2048)


class TargetProfileList(ContractModel):
    targets: list[TargetSpec]
    editable: bool


class ProviderProfileUpdate(ContractModel):
    name: str | None = Field(default=None, min_length=1, max_length=100)
    base_url: str | None = Field(default=None, max_length=2048)
    api_key: SecretStr | None = Field(default=None, max_length=4096)
    model_id: ModelName | None = None
    model_display_name: str | None = Field(default=None, min_length=1, max_length=100)
    output_mode: Literal["json_schema", "json_object", "prompt_json"] | None = None
    token_limit_field: Literal["max_tokens", "max_completion_tokens"] | None = None
    clear_api_key: bool = False

    @field_validator("name", "model_id", "model_display_name", mode="before")
    @classmethod
    def trim_display_fields(cls, value, info):
        if isinstance(value, str):
            value = value.strip()
            if not value and info.field_name == "model_display_name":
                return None
        return value


class ProviderProfileCreate(ProviderProfileUpdate):
    name: str = Field(min_length=1, max_length=100)
    base_url: str = Field(max_length=2048)
    model_id: ModelName


class ProviderProfileView(ContractModel):
    provider_id: ProviderKey
    name: str
    base_url: str | None
    model_id: str | None
    model_display_name: str | None
    output_mode: str
    token_limit_field: str
    key_configured: bool
    enabled: bool


class ProviderProfileList(ContractModel):
    providers: list[ProviderProfileView]
