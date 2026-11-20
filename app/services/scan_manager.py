"""Own admission, collection tasks, cancellation and atomic report replacement."""

import asyncio
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import UUID, uuid4, uuid5

from app.ai.base import AnalysisError
from app.ai.service import AnalysisService
from app.config import Settings
from app.errors import OperationError
from app.schemas import (
    DOMAIN_TOOL_IDS,
    PUBLIC_TOOL_IDS,
    WEB_TOOL_IDS,
    AnalysisAttempt,
    AnalysisOutcome,
    CollectionDecision,
    CollectionStep,
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
    ToolRunSummary,
    ToolState,
)
from app.services.targets import (
    alternate_target,
    configured_targets,
    resolve_public_target,
)
from app.store import ACTIVE_STATES, ScanStore, SQLiteScanStore
from app.tools.adapters.common import AuthenticatedWebAdapter
from app.tools.base import ToolAdapter
from app.tools.dvwa_auth import DvwaAuthError, authenticate_dvwa
from app.tools.public_proxy import PinnedOriginProxy
from app.tools.public_web import apply_public_proxy
from app.tools.refinement import FOLLOWUPS, followup_catalog, followup_spec
from app.tools.runner import run_tool

ALTERNATE_ORIGIN = "alternate_origin"

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
            target = next(
                (
                    t
                    for t in configured_targets(self.settings)
                    if t.target_id == request.target_id
                ),
                None,
            )
            if target is None:
                raise OperationError(
                    404, "target_not_found", "Selected target was not found."
                )
            for tool in request.tools:
                capability = self.capabilities.get(tool)
                if capability is None or not capability.enabled:
                    raise OperationError(
                        422, "tool_unavailable", "A selected tool is unavailable."
                    )
            connection_tools = (PUBLIC_TOOL_IDS - DOMAIN_TOOL_IDS) | {ToolId.OPENSSL}
            resolution = None
            if target.kind == "public_domain" and set(request.tools) & connection_tools:
                target, resolution = await resolve_public_target(
                    target,
                    probe_alternate=bool(
                        set(request.tools) & (WEB_TOOL_IDS | {ToolId.OPENSSL})
                    ),
                )
            self.store.prune(datetime.now(UTC))
            scan = ScanRecord(
                scan_id=str(uuid4()),
                server_instance_id=self.server_instance_id,
                target=target.model_copy(deep=True),
                state="queued",
                provider_id=request.provider_id,
                tools={
                    tool: ToolResult(tool_id=tool, state="queued")
                    for tool in request.tools
                },
                created_at=datetime.now(UTC),
                resolution=resolution,
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
                asyncio.create_task(self._collect_origins(operation, tool))
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
            await self._refine_collection(operation)
            if not self._can_commit(operation):
                return
            scan = self.store.get(operation.scan_id)
            scan.collection_phase = "complete"
            scan.collection_finished_at = datetime.now(UTC)
            scan.partial = any(
                t.state
                in {
                    ToolState.FAILED,
                    ToolState.TIMED_OUT,
                    ToolState.OUTPUT_LIMITED,
                    ToolState.CANCELLED,
                }
                or t.parse_status == "failed"
                or any(
                    r.state in {"failed", "timed_out", "output_limited", "cancelled"}
                    or r.parse_status == "failed"
                    for r in t.runs
                )
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

    async def _refine_collection(self, operation):
        planner = getattr(self.analyzer, "plan_collection", None)
        if not self.settings.ai_agent_enabled or not callable(planner):
            return
        used = set()
        remaining = min(self.settings.ai_total_timeout_seconds, 120)
        rounds = min(self.settings.ai_agent_max_loops, 5)
        last_call = 0.0
        for round_no in range(1, rounds + 1):
            if not self._can_commit(operation):
                return
            scan = self.store.get(operation.scan_id)
            choices = followup_catalog(scan, used)
            if not choices or not any(t.evidence for t in scan.tools.values()):
                return
            # A round slower than the remaining budget would only time out.
            if len(used) >= 6 or remaining < last_call:
                break
            scan.collection_phase = "planning"
            self.store.update(scan)
            started = asyncio.get_running_loop().time()
            step = CollectionStep(
                round=round_no,
                provider_id=scan.provider_id,
                model=getattr(
                    getattr(self.analyzer, "providers", {}).get(scan.provider_id),
                    "model",
                    None,
                ),
                state="stopped",
                created_at=datetime.now(UTC),
            )
            try:
                raw = await asyncio.wait_for(
                    planner(scan.model_copy(deep=True), choices, started + remaining),
                    max(0.001, remaining),
                )
                decision = CollectionDecision.model_validate(raw)
                ids = [action.action_id for action in decision.actions]
                if len(set(ids)) != len(ids) or any(
                    identifier not in choices for identifier in ids
                ):
                    raise ValueError("Unlisted or duplicate action")
                step.reason = decision.reason
                step.actions = decision.actions
                step.state = "planned" if ids else "stopped"
            except asyncio.CancelledError:
                raise
            except (ValueError, TypeError):
                step.state = "rejected"
                step.reason = "LLM returned an invalid or unlisted collection action."
            except Exception as error:
                step.state = "unavailable"
                code = (
                    error.error.code
                    if isinstance(error, AnalysisError)
                    else "provider_timeout"
                    if isinstance(error, TimeoutError)
                    else "internal_error"
                )
                step.reason = (
                    f"Collection planning was unavailable ({code}); "
                    "retain collected evidence."
                )
            last_call = asyncio.get_running_loop().time() - started
            remaining -= last_call
            if not self._can_commit(operation):
                return
            scan = self.store.get(operation.scan_id)
            scan.collection_steps.append(step)
            if step.state in {"rejected", "unavailable"}:
                scan.warnings.append("collection_refinement_" + step.state)
            self.store.update(scan)
            if step.state != "planned":
                return
            for action in step.actions:
                if not self._can_commit(operation) or len(used) >= 6:
                    return
                scan = self.store.get(operation.scan_id)
                if action.action_id not in followup_catalog(scan, used):
                    scan.warnings.append("collection_action_limit_reached")
                    self.store.update(scan)
                    continue
                used.add(action.action_id)
                scan.collection_phase = "followup"
                self.store.update(scan)
                await self._collect_tool(
                    operation,
                    FOLLOWUPS[action.action_id][0],
                    action.action_id,
                    action.reason,
                )
            if remaining <= 0:
                break
        if self._can_commit(operation):
            scan = self.store.get(operation.scan_id)
            scan.warnings.append("collection_refinement_limit_reached")
            self.store.update(scan)

    async def _collect_origins(self, operation: Operation, tool_id: ToolId) -> None:
        """Default preset on the saved origin, then on the other reachable scheme."""
        await self._collect_tool(operation, tool_id)
        if tool_id not in WEB_TOOL_IDS or not self._can_commit(operation):
            return
        scan = self.store.get(operation.scan_id)
        alternate = alternate_target(scan.target, scan.resolution)
        if alternate is not None and scan.tools[tool_id].state != ToolState.SKIPPED:
            await self._collect_tool(
                operation,
                tool_id,
                ALTERNATE_ORIGIN,
                f"Same preset on {alternate.url} (same pinned address)",
            )

    @staticmethod
    def _tool_target(scan: ScanRecord, tool_id: ToolId, preset_id: str):
        alternate = alternate_target(scan.target, scan.resolution)
        if alternate is not None and (
            preset_id == ALTERNATE_ORIGIN
            or (tool_id == ToolId.OPENSSL and scan.target.scheme != "https")
        ):
            return alternate
        return scan.target

    async def _collect_tool(
        self,
        operation: Operation,
        tool_id: ToolId,
        preset_id="default",
        action_reason="",
    ) -> None:
        capture = None
        proxy = None
        previous = (
            self.store.get(operation.scan_id).tools[tool_id].model_copy(deep=True)
        )
        run_no = len(previous.runs) + 1
        scan = self.store.get(operation.scan_id)
        scan.tools[tool_id].runs.append(
            ToolRunSummary(preset_id=preset_id, reason=action_reason, state="queued")
        )
        scan.tools[tool_id].state = ToolState.QUEUED
        self.store.update(scan)
        try:
            target = self._tool_target(
                self.store.get(operation.scan_id), tool_id, preset_id
            )
            adapter = self.registry[tool_id]
            reason = adapter.applicability(target)
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
                        scan.tools[tool_id].runs[-1].state = ToolState.RUNNING
                        scan.tools[tool_id].runs[-1].started_at = started_at
                        self.store.update(scan)

                async with AsyncExitStack() as resources:
                    directory = resources.enter_context(
                        TemporaryDirectory(prefix="penchecker-")
                    )
                    session = None
                    if target.kind == "dvwa" and isinstance(
                        adapter, AuthenticatedWebAdapter
                    ):
                        session = await authenticate_dvwa(
                            target, self.settings, operation.cancel
                        )
                        if preset_id == "default":
                            spec = adapter.build_authenticated_spec(
                                target,
                                Path(directory),
                                session.cookie_header.get_secret_value(),
                            )
                        else:
                            target, spec = followup_spec(
                                adapter,
                                target,
                                preset_id,
                                Path(directory),
                                session.cookie_header.get_secret_value(),
                            )
                    else:
                        if preset_id in {"default", ALTERNATE_ORIGIN}:
                            spec = adapter.build_spec(target, Path(directory))
                        else:
                            target, spec = followup_spec(
                                adapter, target, preset_id, Path(directory)
                            )
                    if target.kind == "public_domain" and tool_id in WEB_TOOL_IDS:
                        proxy = await resources.enter_async_context(
                            PinnedOriginProxy(target)
                        )
                        spec = apply_public_proxy(spec, proxy.url)
                    redactions = []
                    if session is not None:
                        redactions.append(
                            session.cookie_header.get_secret_value()
                            .split(";", 1)[0]
                            .split("=", 1)[1]
                        )
                    if proxy is not None:
                        redactions.extend(
                            (proxy.url, proxy.url.removeprefix("http://"))
                        )
                    capture = await run_tool(
                        spec,
                        self.semaphore,
                        operation.cancel,
                        self.settings.tool_capture_limit_bytes,
                        on_started=on_started,
                        redact_values=tuple(redactions),
                    )
                    namespace = (
                        operation.scan_id
                        if run_no == 1
                        else str(
                            uuid5(
                                UUID(operation.scan_id),
                                f"{tool_id}:{run_no}:{preset_id}",
                            )
                        )
                    )
                    result = adapter.parse(target, capture, namespace)
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
                if proxy is not None and proxy.warnings:
                    result.warnings.extend([*proxy.warnings, "tool_run_incomplete"])
                    if result.state == ToolState.SUCCEEDED:
                        result.state = ToolState.FAILED
                    result.error = result.error or ErrorInfo(
                        code="public_proxy_incomplete",
                        message="Some public requests were rejected or incomplete; "
                        "retained evidence is partial.",
                    )
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
            summary = ToolRunSummary(
                preset_id=preset_id,
                reason=action_reason,
                state=result.state,
                parse_status=result.parse_status,
                started_at=result.started_at,
                finished_at=result.finished_at,
                duration_ms=result.duration_ms,
                warnings=result.warnings[:20],
            )
            result.runs = [*previous.runs, summary]
            result.run_captures = (
                [*previous.run_captures, result.capture] if previous.runs else []
            )
            if previous.runs:
                for evidence in result.evidence:
                    evidence.locator = f"run:{run_no}/{evidence.locator}"[:500]
                result.observations = [*previous.observations, *result.observations][
                    :400
                ]
                result.evidence = [*previous.evidence, *result.evidence][:400]
                result.started_at = previous.started_at or result.started_at
                result.duration_ms += previous.duration_ms
                result.warnings = list(
                    dict.fromkeys([*previous.warnings, *result.warnings])
                )[:20]
                if any(
                    r.state in {"failed", "timed_out", "output_limited", "cancelled"}
                    or r.parse_status == "failed"
                    for r in result.runs
                ):
                    result.warnings = ["tool_run_incomplete", *result.warnings][:20]
                result.capture = previous.capture
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
        analyzing = (
            scan.state == ScanState.ANALYZING or scan.collection_phase == "planning"
        )
        scan.state = ScanState.CANCELLING
        self.store.update(scan)
        operation.cancel.set()
        # Collection uses the runner's event path to retain bounded partial output.
        if analyzing and operation.worker is not None:
            operation.worker.cancel()
