"""Bounded parser output, provenance IDs, and capture outcome mapping."""

import json
import posixpath
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit
from uuid import UUID, uuid5
from xml.etree.ElementTree import ParseError

from defusedxml.common import DefusedXmlException
from pydantic import ValidationError

from app.schemas import (
    Capture,
    ErrorInfo,
    Evidence,
    Observation,
    ParseStatus,
    Scope,
    TargetSpec,
    ToolCapability,
    ToolId,
    ToolResult,
    ToolSpec,
    ToolState,
)


def uri_scope(target: TargetSpec, uri: str) -> Scope:
    if not uri or "\\" in uri or any(ord(c) <= 32 for c in uri):
        return Scope.UNKNOWN
    try:
        raw_path = unquote(urlsplit(uri).path)
        if any(part in {".", ".."} for part in raw_path.split("/")):
            return Scope.UNKNOWN
        parts = urlsplit(urljoin(target.url, uri))
        port = parts.port if parts.port is not None else 80
        if (parts.scheme, parts.hostname, port) != (
            target.scheme,
            str(target.ip),
            target.port,
        ) or parts.username is not None:
            return Scope.UNKNOWN
        path = unquote(parts.path)
        if (
            "%" in path
            or "\\" in path
            or any(ord(c) <= 32 for c in path)
            or posixpath.normpath(path) != (path.rstrip("/") or "/")
        ):
            return Scope.UNKNOWN
        return (
            Scope.DVWA_PATH
            if path == "/dvwa" or path.startswith("/dvwa/")
            else Scope.OTHER_PATH
        )
    except ValueError:
        return Scope.UNKNOWN


class ParsedOutput:
    def __init__(self, tool_id: ToolId, scan_id: str):
        self.tool_id = tool_id
        self.namespace = UUID(scan_id)
        self.observations: list[Observation] = []
        self.evidence: list[Evidence] = []
        self.warnings: list[str] = []
        self.ordinal = 0

    def warn(self, warning: str) -> None:
        if warning not in self.warnings and len(self.warnings) < 20:
            self.warnings.append(warning[:500])

    def add(self, *, kind, scope, subject, value, source, locator, excerpt):
        ordinal = self.ordinal
        self.ordinal += 1
        if len(self.observations) >= 100:
            self.warn("parser_output_truncated")
            return
        evidence_id = str(uuid5(self.namespace, f"{self.tool_id}:evidence:{ordinal}"))
        try:
            item = Observation(
                id=str(uuid5(self.namespace, f"{self.tool_id}:observation:{ordinal}")),
                tool_id=self.tool_id,
                kind=kind,
                scope=scope,
                subject=subject,
                value=value,
                evidence_ids=[evidence_id],
            )
            evidence = Evidence(
                id=evidence_id,
                tool_id=self.tool_id,
                source=source,
                locator=locator,
                excerpt=excerpt[:1000],
            )
        except ValidationError:
            self.warn("parser_output_truncated")
            return
        self.observations.append(item)
        self.evidence.append(evidence)

    def json_item(self, *, filename, pointer, item, kind, scope, subject, value):
        self.add(
            kind=kind,
            scope=scope,
            subject=subject,
            value=value,
            source="artifact",
            locator=f"{filename}#{pointer}",
            excerpt=json.dumps(item, ensure_ascii=False, separators=(",", ":")),
        )


class Adapter:
    tool_id: ToolId

    def __init__(self, capability: ToolCapability):
        self.capability = capability

    def applicability(self, target: TargetSpec) -> str | None:
        return (
            None
            if self.capability.enabled
            else self.capability.reason or "tool_disabled"
        )

    def build_spec(self, target: TargetSpec, workdir: Path) -> ToolSpec:
        if reason := self.applicability(target):
            raise ValueError(reason)
        executable = self.capability.executable
        if not executable or not Path(executable).is_absolute():
            raise ValueError("absolute_executable_required")
        if not workdir.is_absolute() or not workdir.is_dir():
            raise ValueError("absolute_existing_workdir_required")
        argv, timeout, artifacts = self.preset(target, workdir)
        return ToolSpec(
            tool_id=self.tool_id,
            argv=(executable, *argv),
            timeout_seconds=timeout,
            artifact_paths=artifacts,
        )

    def preset(self, target, workdir):
        raise NotImplementedError

    def extract(self, target, capture, output):
        raise NotImplementedError

    def parse(self, target: TargetSpec, capture: Capture, scan_id: str) -> ToolResult:
        output = ParsedOutput(self.tool_id, scan_id)
        state = {
            "timeout": ToolState.TIMED_OUT,
            "cancelled": ToolState.CANCELLED,
            "output_limit": ToolState.OUTPUT_LIMITED,
            "spawn_error": ToolState.FAILED,
        }.get(capture.termination_reason, ToolState.SUCCEEDED)
        error = None
        if state != ToolState.SUCCEEDED:
            error = ErrorInfo(
                code=f"tool_{capture.termination_reason}",
                message="Tool collection did not complete.",
            )
        elif capture.return_code != 0:
            state = ToolState.FAILED
            error = ErrorInfo(
                code="tool_nonzero_exit", message="Tool exited without success."
            )
        parse_status = ParseStatus.SUCCEEDED
        try:
            self.extract(target, capture, output)
        except (
            ValueError,
            TypeError,
            KeyError,
            IndexError,
            AttributeError,
            RecursionError,
            DefusedXmlException,
            ParseError,
        ):
            parse_status = ParseStatus.FAILED
            if state == ToolState.SUCCEEDED:
                state = ToolState.FAILED
            error = error or ErrorInfo(
                code="parse_error", message="Tool output is missing or malformed."
            )
            output.warn("incomplete_tool_output")
        if capture.output_truncated:
            output.warn("capture_output_truncated")
        if not output.observations:
            output.warn("no_observations_coverage_unknown")
        return ToolResult(
            tool_id=self.tool_id,
            state=state,
            parse_status=parse_status,
            started_at=capture.started_at,
            finished_at=capture.finished_at,
            duration_ms=capture.duration_ms,
            observations=output.observations,
            evidence=output.evidence,
            warnings=output.warnings,
            error=error,
            capture=capture,
        )


class AuthenticatedWebAdapter(Adapter):
    """Supply a verified session through each binary's supported CLI syntax."""

    def cookie_arguments(self, cookies):
        return ("-H", f"Cookie: {cookies}")

    def build_authenticated_spec(self, target, workdir, cookie_header):
        spec = self.build_spec(target, workdir)
        cookies = "; ".join(part.strip() for part in cookie_header.split(";"))
        return spec.model_copy(
            update={"argv": (*spec.argv, *self.cookie_arguments(cookies))}
        )


def artifact_json(capture: Capture, filename: str):
    return json.loads(capture.artifacts[filename])


def require(condition):
    if not condition:
        raise ValueError("Unexpected tool output")
