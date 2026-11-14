"""Scan lifecycle routes; polling and summaries never serialize internal captures."""

import asyncio
import sqlite3
from typing import Annotated, Literal

from fastapi import APIRouter, Path, Query, Request, Response
from fastapi.responses import RedirectResponse

from app.errors import OperationError
from app.schemas import (
    AnalysisRetry,
    EmptyRequest,
    ErrorResponse,
    HistoryCleared,
    OutputPage,
    ScanCreate,
    ScanList,
    ScanSnapshot,
    ScanSummary,
    ToolId,
    ToolState,
    UUIDString,
)
from app.services.report_html import APP
from app.services.report_pdf import render_report_pdf
from app.store import ACTIVE_STATES

router = APIRouter(
    prefix="/api/scans",
    responses={
        s: {"model": ErrorResponse} for s in (403, 404, 409, 413, 415, 422, 502, 503)
    },
)


@router.get("", response_model=ScanList, response_model_exclude_defaults=True)
async def list_scans(
    request: Request,
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 10,
):
    manager = request.app.state.manager
    records = manager.list_scans(offset, limit)
    total = manager.store.count()
    return ScanList(
        scans=[
            ScanSummary(
                scan_id=s.scan_id,
                state=s.state,
                provider_id=s.provider_id,
                partial=s.partial,
                created_at=s.created_at,
                finished_at=s.finished_at,
                tools={tool: result.state for tool, result in s.tools.items()},
                overall_risk=s.report.report.overall_risk if s.report else None,
                target_url=s.target.url,
                report_url=s.report_url,
            )
            for s in records
        ],
        total=total,
        offset=offset,
        has_more=offset + len(records) < total,
        active_scan_id=manager.operation.scan_id if manager.operation else None,
    )


@router.post("/clear", response_model=HistoryCleared)
async def clear_history(body: EmptyRequest, request: Request):
    manager = request.app.state.manager
    async with manager.lock:
        if manager.operation is not None or manager.closed:
            raise OperationError(
                409,
                "operation_in_progress",
                "Wait for the current operation before clearing history.",
            )
        try:
            deleted = manager.store.clear()
        except (OSError, ValueError, sqlite3.Error):
            raise OperationError(
                503,
                "history_clear_failed",
                "History could not be completely cleared; "
                "retry when storage is available.",
            ) from None
        return HistoryCleared(deleted=deleted)


@router.post("", response_model=ScanSnapshot, status_code=202)
async def start_scan(body: ScanCreate, request: Request, response: Response):
    record = await request.app.state.manager.start_scan(body)
    response.headers["Location"] = f"/api/scans/{record.scan_id}"
    return ScanSnapshot.from_record(record)


@router.get("/{scan_id}", response_model=ScanSnapshot)
async def get_scan(scan_id: UUIDString, request: Request):
    return ScanSnapshot.from_record(request.app.state.manager.get_scan(scan_id))


@router.post("/{scan_id}/cves", response_model=ScanSnapshot)
async def lookup_cves(scan_id: UUIDString, body: EmptyRequest, request: Request):
    manager = request.app.state.manager
    scan = manager.get_scan(scan_id)
    if scan.state in ACTIVE_STATES:
        raise OperationError(
            409, "cve_evidence_not_ready", "CVE lookup requires a finished scan."
        )
    result = await request.app.state.cve_service.lookup(scan)
    if result.state == "failed":
        raise OperationError(
            502,
            "cve_source_unavailable",
            "CVE source unavailable; saved results retained.",
            retryable=True,
        )
    # Collection is immutable; merge only lookup data into the latest AI revision.
    latest = manager.get_scan(scan_id)
    latest.cve_lookup = result
    manager.store.update(latest)
    return ScanSnapshot.from_record(manager.get_scan(scan_id))


@router.post("/{scan_id}/cancel", response_model=ScanSnapshot, status_code=202)
async def cancel_scan(scan_id: UUIDString, body: EmptyRequest, request: Request):
    return ScanSnapshot.from_record(
        await request.app.state.manager.cancel_scan(scan_id)
    )


@router.post("/{scan_id}/analysis", response_model=ScanSnapshot, status_code=202)
async def retry_analysis(scan_id: UUIDString, body: AnalysisRetry, request: Request):
    return ScanSnapshot.from_record(
        await request.app.state.manager.retry_analysis(scan_id, body.provider_id)
    )


@router.get("/{scan_id}/tools/{tool_id}/output", response_model=OutputPage)
async def tool_output(
    scan_id: UUIDString,
    tool_id: ToolId,
    request: Request,
    stream: Literal["stdout", "stderr", "artifact"] = "stdout",
    offset: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=16384)] = 16384,
):
    scan = request.app.state.manager.get_scan(scan_id)
    tool = scan.tools.get(tool_id)
    if tool is None:
        raise OperationError(404, "tool_not_found", "Tool is not part of this scan.")
    if tool.state in {ToolState.QUEUED, ToolState.RUNNING}:
        raise OperationError(
            409, "output_not_ready", "Tool output is not ready.", retryable=True
        )
    capture = tool.capture
    text = ""
    if len(tool.runs) > 1:
        pieces = []
        captures = [tool.capture, *tool.run_captures]
        for index, run in enumerate(tool.runs):
            item = captures[index] if index < len(captures) else None
            data = (
                ""
                if item is None
                else "\n".join(item.artifacts.values())
                if stream == "artifact"
                else getattr(item, stream)
            )
            pieces.append(f"=== {run.preset_id} ({run.state}) ===\n{data}")
        text = "\n\n".join(pieces)
    elif capture is not None:
        text = (
            next(iter(capture.artifacts.values()), "")
            if stream == "artifact"
            else getattr(capture, stream)
        )
    page = text[offset : offset + limit]
    return OutputPage(
        text=page,
        next_offset=offset + len(page),
        has_more=offset + len(page) < len(text),
    )


@router.get(
    "/{scan_id}/report.pdf",
    response_class=Response,
    responses={
        200: {"content": {"application/pdf": {}}, "description": "Saved assessment PDF"}
    },
)
async def download_report(scan_id: UUIDString, request: Request):
    scan = request.app.state.manager.get_scan(scan_id)
    if scan.report is None:
        raise OperationError(
            409, "report_unavailable", "No validated report is available to export."
        )
    data = await asyncio.to_thread(render_report_pdf, scan)
    filename = f"penchecker-{scan.scan_id}-r{scan.report.revision}.pdf"
    return Response(
        data,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@router.get("/{scan_id}/report.html", response_class=Response)
async def latest_html_report(scan_id: UUIDString, request: Request):
    scan = request.app.state.manager.get_scan(scan_id)
    if scan.report is None:
        raise OperationError(
            409, "report_unavailable", "No validated report is available."
        )
    return RedirectResponse(f"/api/scans/{scan_id}/reports/{scan.report.revision}.html")


@router.get("/{scan_id}/reports/{revision}.html", response_class=Response)
async def html_report(
    scan_id: UUIDString, revision: Annotated[int, Path(ge=1)], request: Request
):
    manager = request.app.state.manager
    scan = manager.get_scan(scan_id)
    if scan.report is None:
        raise OperationError(
            409, "report_unavailable", "No validated report is available."
        )
    archive = getattr(manager.store, "archive", None)
    if archive is None:
        raise OperationError(
            503, "report_archive_unavailable", "HTML report storage is unavailable."
        )
    try:
        try:
            if revision == scan.report.revision and scan.report_url is None:
                raise FileNotFoundError
            content = archive.read(scan_id, revision)
        except FileNotFoundError:
            if revision != scan.report.revision:
                raise OperationError(
                    404, "report_not_found", "Saved report revision was not found."
                ) from None
            scan.warnings = [
                w for w in scan.warnings if w != "report_archive_unavailable"
            ]
            scan.report_url = archive.save(scan)
            manager.store.update(scan)
            content = archive.read(scan_id, revision)
    except (OSError, ValueError):
        raise OperationError(
            503, "report_archive_unavailable", "HTML report storage is unavailable."
        ) from None
    return Response(
        content,
        media_type="text/html",
        headers={
            "Content-Disposition": (
                f'inline; filename="penchecker-{scan_id}-r{revision}.html"'
            ),
        },
    )


@router.get("/{scan_id}/report.css", response_class=Response)
async def html_report_style(scan_id: UUIDString, request: Request):
    request.app.state.manager.get_scan(scan_id)
    return Response(
        (APP / "static/css/report-archive.css").read_text(encoding="utf-8"),
        media_type="text/css",
    )
