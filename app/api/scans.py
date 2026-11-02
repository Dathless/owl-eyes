"""Scan lifecycle routes; polling and summaries never serialize internal captures."""

import asyncio
from typing import Annotated, Literal

from fastapi import APIRouter, Query, Request, Response

from app.errors import OperationError
from app.schemas import (
    AnalysisRetry,
    EmptyRequest,
    ErrorResponse,
    OutputPage,
    ScanCreate,
    ScanList,
    ScanSnapshot,
    ScanSummary,
    ToolId,
    ToolState,
    UUIDString,
)
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
            )
            for s in records
        ],
        total=total,
        offset=offset,
        has_more=offset + len(records) < total,
        active_scan_id=manager.operation.scan_id if manager.operation else None,
    )


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
    return ScanSnapshot.from_record(latest)


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
    if capture is not None:
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
