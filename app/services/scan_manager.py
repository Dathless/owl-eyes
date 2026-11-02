"""Own admission, collection tasks, cancellation and atomic report replacement."""

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

from app.ai.service import AnalysisService
from app.config import Settings
from app.errors import OperationError
from app.schemas import (
    AnalysisAttempt,
    AnalysisOutcome,
    ErrorInfo,
    ProviderKey,
    ReportEnvelope,
    ScanCreate,
    ScanRecord,
    ScanState,
    TargetSpec,
    ToolCapability,
    ToolId,
    ToolResult,
    ToolState,
)
from app.store import ACTIVE_STATES, ScanStore, SQLiteScanStore
from app.tools.adapters.common import AuthenticatedWebAdapter
from app.tools.base import ToolAdapter
from app.tools.dvwa_auth import DvwaAuthError, authenticate_dvwa
from app.tools.runner import run_tool

Analyzer = Callable[[ScanRecord], Awaitable[AnalysisOutcome]]


@dataclass
class Operation:
    scan_id: str
    generation: int
    cancel: asyncio.Event = field(default_factory=asyncio.Event)
    worker: asyncio.Task | None = None
    task: asyncio.Task | None = None
    result: ScanRecord | None = None
    attempt_numbers: dict[int, int] = field(default_factory=dict)


class ScanManager:
    def __init__(
        self,
        settings: Settings,
        store: ScanStore,
        registry: dict[ToolId, ToolAdapter],
        analyzer: Analyzer | None = None,
        *,
        capabilities: dict[ToolId, ToolCapability] | None = None,
    ):
        self.settings, self.store, self.registry, self.analyzer = (
            settings,
            store,
            registry,
            analyzer,
        )
        self.capabilities = capabilities or {
            tool: adapter.capability for tool, adapter in registry.items()
        }
        self.server_instance_id = str(uuid4())
        self.semaphore = asyncio.Semaphore(settings.max_concurrent_tools)
        self.lock = asyncio.Lock()
        self.tasks: set[asyncio.Task] = set()
        self.operation: Operation | None = None
        self.generation = 0
        self.closed = False
        self.target = TargetSpec(
            url=settings.lab_target_url,
            ip=settings.lab_target_ip,
            auth_mode=settings.dvwa_auth_mode,
            security_level=settings.dvwa_security_level,
        )

    def get_scan(self, scan_id: str) -> ScanRecord:
        self.store.prune(datetime.now(UTC))
        try:
            scan = self.store.get(scan_id)
            if isinstance(self.store, SQLiteScanStore):
                scan.server_instance_id = self.server_instance_id
            return scan
        except KeyError:
            raise OperationError(
                404,
                "scan_not_found",
                "Scan was not found in the current history store.",
            ) from None

    def list_scans(self, offset: int = 0, limit: int = 10) -> list[ScanRecord]:
        self.store.prune(datetime.now(UTC))
        return self.store.list(offset=offset, limit=limit)

    def _check_admission(self, provider_id: ProviderKey) -> None:
        if self.closed:
            raise OperationError(503, "server_stopping", "Server is shutting down.")
        if self.operation is not None:
            raise OperationError(
                409,
                "operation_in_progress",
                "An operation is in progress.",
                retryable=True,
            )
        enabled = self.settings.provider_enabled(provider_id)
        if not enabled:
            raise OperationError(
                422, "provider_unavailable", "The selected provider is not configured."
            )

    def _launch(self, scan: ScanRecord, *, collect: bool) -> None:
        self.generation += 1
        operation = Operation(scan.scan_id, self.generation)
        self.operation = operation
        task = asyncio.create_task(self._supervise(operation, collect=collect))
        operation.task = task
        self.tasks.add(task)
        task.add_done_callback(self._done)

    def _done(self, task: asyncio.Task) -> None:
        self.tasks.discard(task)
        if not task.cancelled():
            task.exception()

    async def start_scan(self, request: ScanCreate) -> ScanRecord:
        async with self.lock:
            self._check_admission(request.provider_id)
            for tool in request.tools:
                capability = self.capabilities.get(tool)
                if capability is None or not capability.enabled:
                    raise OperationError(
                        422, "tool_unavailable", "A selected tool is unavailable."
                    )
            self.store.prune(datetime.now(UTC))
            scan = ScanRecord(
                scan_id=str(uuid4()),
                server_instance_id=self.server_instance_id,
                target=self.target,
                state="queued",
                provider_id=request.provider_id,
                tools={
                    tool: ToolResult(tool_id=tool, state="queued")
                    for tool in request.tools
                },
                created_at=datetime.now(UTC),
            )
            self.store.create(scan)
            self._launch(scan, collect=True)
            return self.store.get(scan.scan_id)

    async def retry_analysis(
        self, scan_id: str, provider_id: ProviderKey
    ) -> ScanRecord:
        async with self.lock:
            scan = self.get_scan(scan_id)
            self._check_admission(provider_id)
            if scan.state not in {
                ScanState.COMPLETED,
                ScanState.ANALYSIS_FAILED,
            } or not any(t.evidence for t in scan.tools.values()):
                raise OperationError(
                    409,
                    "analysis_not_retryable",
                    "Analysis cannot be retried for this scan.",
                )
            scan.state, scan.provider_id = ScanState.ANALYZING, provider_id
            scan.finished_at, scan.failure = None, None
            self.store.update(scan)
            self._launch(scan, collect=False)
            return self.store.get(scan_id)

    async def cancel_scan(self, scan_id: str) -> ScanRecord:
        async with self.lock:
            scan = self.get_scan(scan_id)
            if scan.state not in ACTIVE_STATES:
                raise OperationError(
                    409, "operation_terminal", "The operation has already finished."
                )
            operation = self.operation
            if operation is None or operation.scan_id != scan_id:
                raise OperationError(
                    409, "operation_terminal", "The operation has already finished."
                )
            self._request_cancel(operation, scan)
            return self.store.get(scan_id)

    def _can_commit(self, operation: Operation) -> bool:
        return (
            self.operation is operation
            and self.generation == operation.generation
            and not operation.cancel.is_set()
        )

    async def _supervise(self, operation: Operation, *, collect: bool) -> None:
        try:
            if not operation.cancel.is_set():
                operation.worker = asyncio.create_task(
                    self._execute(operation, collect=collect)
                )
                await operation.worker
        except asyncio.CancelledError:
            operation.cancel.set()
        except Exception:
            scan = self.store.get(operation.scan_id)
            if self._can_commit(operation):
                scan.state = (
                    ScanState.COLLECTION_FAILED
                    if collect and scan.state != ScanState.ANALYZING
                    else ScanState.ANALYSIS_FAILED
                )
                scan.failure = ErrorInfo(
                    code="internal_operation_error",
                    message="The operation could not be completed.",
                )
                self.store.update(scan)
        finally:
            scan = (
                operation.result
                if operation.result is not None and self._can_commit(operation)
                else self.store.get(operation.scan_id)
            )
            if operation.cancel.is_set():
                scan.state = ScanState.CANCELLED
                scan.failure = ErrorInfo(
                    code="operation_cancelled", message="The operation was cancelled."
                )
                for tool in scan.tools.values():
                    if tool.state in {ToolState.QUEUED, ToolState.RUNNING}:
                        tool.state, tool.parse_status, tool.finished_at = (
                            ToolState.CANCELLED,
                            "not_applicable",
                            datetime.now(UTC),
                        )
                scan.partial = (
                    any(t.state == ToolState.CANCELLED for t in scan.tools.values())
                    or scan.partial
                )
            scan.finished_at = datetime.now(UTC)
            self.store.update(scan)
            # No await between terminal publication and releasing the global slot.
            if self.operation is operation:
                self.operation = None
            self.store.prune(datetime.now(UTC))

    async def _execute(self, operation: Operation, *, collect: bool) -> None:
        if not self._can_commit(operation):
            return
        if collect:
            scan = self.store.get(operation.scan_id)
            scan.state = ScanState.COLLECTING
            self.store.update(scan)
            children = [
                asyncio.create_task(self._collect_tool(operation, tool))
                for tool in scan.tools
            ]
            try:
                await asyncio.gather(*children)
            finally:
                for task in children:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*children, return_exceptions=True)
            if not self._can_commit(operation):
                return
            scan = self.store.get(operation.scan_id)
            scan.partial = any(
                t.state
                in {
                    ToolState.FAILED,
                    ToolState.TIMED_OUT,
                    ToolState.OUTPUT_LIMITED,
                    ToolState.CANCELLED,
                }
                or t.parse_status == "failed"
                or any("truncated" in w for w in t.warnings)
                for t in scan.tools.values()
            )
            if not any(t.evidence for t in scan.tools.values()):
                all_skipped = all(
                    t.state == ToolState.SKIPPED for t in scan.tools.values()
                )
                scan.state = ScanState.COLLECTION_FAILED
                scan.failure = ErrorInfo(
                    code="no_applicable_tools" if all_skipped else "no_usable_evidence",
                    message="Collection produced no usable evidence.",
                )
                operation.result = scan
                return
            scan.state = ScanState.ANALYZING
            self.store.update(scan)
        if self._can_commit(operation):
            await self._analyze(operation)

    async def _collect_tool(self, operation: Operation, tool_id: ToolId) -> None:
        capture = None
        try:
            adapter = self.registry[tool_id]
            reason = adapter.applicability(self.target)
            if reason:
                result = ToolResult(
                    tool_id=tool_id,
                    state="skipped",
                    parse_status="not_applicable",
                    warnings=[reason],
                    finished_at=datetime.now(UTC),
                )
            else:

                def on_started(started_at: datetime) -> None:
                    if self._can_commit(operation):
                        scan = self.store.get(operation.scan_id)
                        scan.tools[tool_id].state = ToolState.RUNNING
                        scan.tools[tool_id].started_at = started_at
                        self.store.update(scan)

                with TemporaryDirectory(prefix="penchecker-") as directory:
                    session = None
                    if isinstance(adapter, AuthenticatedWebAdapter):
                        session = await authenticate_dvwa(
                            self.target, self.settings, operation.cancel
                        )
                        spec = adapter.build_authenticated_spec(
                            self.target,
                            Path(directory),
                            session.cookie_header.get_secret_value(),
                        )
                    else:
                        spec = adapter.build_spec(self.target, Path(directory))
                    capture = await run_tool(
                        spec,
                        self.semaphore,
                        operation.cancel,
                        self.settings.tool_capture_limit_bytes,
                        on_started=on_started,
                        redact_values=(
                            session.cookie_header.get_secret_value()
                            .split(";", 1)[0]
                            .split("=", 1)[1],
                        )
                        if session is not None
                        else (),
                    )
                    result = adapter.parse(self.target, capture, operation.scan_id)
                    if session is not None:
                        result.warnings = [
                            w for w in result.warnings if w != "public_only_coverage"
                        ]
                        result.warnings.extend(
                            [
                                "authenticated_session_verified_before_scan",
                                f"dvwa_security_level_{session.security_level}",
                                "authenticated_module_coverage_not_proven",
                            ]
                        )
                    result.capture = capture
        except asyncio.CancelledError:
            raise
        except DvwaAuthError:
            result = ToolResult(
                tool_id=tool_id,
                state="failed",
                parse_status="not_applicable",
                finished_at=datetime.now(UTC),
                warnings=["authenticated_coverage_unavailable"],
                error=ErrorInfo(
                    code="dvwa_auth_failed",
                    message="DVWA login failed verification; scanner was not started.",
                ),
            )
        except Exception:
            result = ToolResult(
                tool_id=tool_id,
                state="failed",
                parse_status="failed",
                capture=capture,
                finished_at=datetime.now(UTC),
                error=ErrorInfo(
                    code="internal_tool_error",
                    message="Tool collection or parsing failed.",
                ),
            )
        if self.operation is operation and self.generation == operation.generation:
            scan = self.store.get(operation.scan_id)
            scan.tools[tool_id] = result
            self.store.update(scan)

    async def _analyze(self, operation: Operation) -> None:
        analysis_input = self.store.get(operation.scan_id)
        try:
            if self.analyzer is None:
                outcome = AnalysisOutcome(
                    error=ErrorInfo(
                        code="analysis_unavailable",
                        message="AI integration is not implemented yet.",
                        retryable=True,
                    )
                )
            elif isinstance(self.analyzer, AnalysisService):
                outcome = await self.analyzer.analyze(
                    analysis_input,
                    on_attempt=lambda attempt: self._record_attempt(
                        operation, attempt, analysis_input.partial
                    ),
                )
            else:
                outcome = await self.analyzer(analysis_input)
        except asyncio.CancelledError:
            raise
        except Exception:
            outcome = AnalysisOutcome(
                error=ErrorInfo(
                    code="internal_analysis_error",
                    message="Analysis could not be completed.",
                    retryable=True,
                )
            )
        if not self._can_commit(operation):
            return
        scan = self.store.get(operation.scan_id)
        scan.partial |= analysis_input.partial
        for attempt in (
            [] if isinstance(self.analyzer, AnalysisService) else outcome.attempts
        ):
            attempt = attempt.model_copy(deep=True)
            attempt.attempt_no = scan.next_attempt_no
            scan.next_attempt_no += 1
            scan.attempts.append(attempt)
        if len(scan.attempts) > 20:
            scan.attempts = scan.attempts[-20:]
            if "analysis_history_truncated" not in scan.warnings:
                scan.warnings.append("analysis_history_truncated")
        if outcome.report is not None:
            scan.analysis_revision += 1
            model = (
                outcome.attempts[-1].model
                if outcome.attempts
                else self.settings.provider_model(scan.provider_id)
            )
            scan.report = ReportEnvelope(
                report=outcome.report,
                revision=scan.analysis_revision,
                provider_id=scan.provider_id,
                model=model,
                generated_at=datetime.now(UTC),
            )
            scan.state, scan.failure = ScanState.COMPLETED, None
        else:
            scan.state = ScanState.ANALYSIS_FAILED
            scan.failure = outcome.error or ErrorInfo(
                code="internal_analysis_error", message="Analysis returned no report."
            )
        # Publish the terminal result with slot release in the supervisor.
        operation.result = scan

    def _record_attempt(
        self, operation: Operation, attempt: AnalysisAttempt, partial: bool
    ) -> None:
        if self.operation is not operation or self.generation != operation.generation:
            return
        scan = self.store.get(operation.scan_id)
        scan.partial |= partial
        local_number = attempt.attempt_no
        attempt = attempt.model_copy(deep=True)
        if local_number not in operation.attempt_numbers:
            operation.attempt_numbers[local_number] = scan.next_attempt_no
            scan.next_attempt_no += 1
            scan.attempts.append(attempt)
        attempt.attempt_no = operation.attempt_numbers[local_number]
        if operation.cancel.is_set():
            attempt.state = "cancelled"
        for index, previous in enumerate(scan.attempts):
            if previous.attempt_no == attempt.attempt_no:
                scan.attempts[index] = attempt
                break
        if len(scan.attempts) > 20:
            scan.attempts = scan.attempts[-20:]
            if "analysis_history_truncated" not in scan.warnings:
                scan.warnings.append("analysis_history_truncated")
        self.store.update(scan)

    async def shutdown(self) -> None:
        async with self.lock:
            self.closed = True
            operation = self.operation
            if operation is not None:
                self._request_cancel(operation, self.store.get(operation.scan_id))
            tasks = tuple(self.tasks)
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
            self.tasks.difference_update(tasks)

    def _request_cancel(self, operation: Operation, scan: ScanRecord) -> None:
        if operation.cancel.is_set():
            return
        analyzing = scan.state == ScanState.ANALYZING
        scan.state = ScanState.CANCELLING
        self.store.update(scan)
        operation.cancel.set()
        # Collection uses the runner's event path to retain bounded partial output.
        if analyzing and operation.worker is not None:
            operation.worker.cancel()
