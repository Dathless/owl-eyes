"""Single-event-loop stores for durable sanitized scan records."""

import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from app.schemas import ErrorInfo, ScanRecord, ScanState

ACTIVE_STATES = frozenset(
    {ScanState.QUEUED, ScanState.COLLECTING, ScanState.ANALYZING, ScanState.CANCELLING}
)


class ScanStore(Protocol):
    def create(self, scan: ScanRecord) -> None: ...
    def get(self, scan_id: str) -> ScanRecord: ...
    def update(self, scan: ScanRecord) -> None: ...
    def prune(self, now: datetime) -> None: ...
    def list(self, offset: int = 0, limit: int | None = None) -> list[ScanRecord]: ...
    def count(self) -> int: ...


class MemoryScanStore:
    def __init__(self, *, retain_completed: int, ttl_seconds: int):
        self._records: dict[str, ScanRecord] = {}
        self.retain_completed = retain_completed
        self.ttl_seconds = ttl_seconds

    def create(self, scan: ScanRecord) -> None:
        if scan.scan_id in self._records:
            raise KeyError(scan.scan_id)
        self._records[scan.scan_id] = scan.model_copy(deep=True)

    def get(self, scan_id: str) -> ScanRecord:
        return self._records[scan_id].model_copy(deep=True)

    def update(self, scan: ScanRecord) -> None:
        if scan.scan_id not in self._records:
            raise KeyError(scan.scan_id)
        self._records[scan.scan_id] = scan.model_copy(deep=True)

    def list(self, offset: int = 0, limit: int | None = None) -> list[ScanRecord]:
        records = [
            scan.model_copy(deep=True)
            for scan in sorted(
                self._records.values(), key=lambda scan: scan.created_at, reverse=True
            )
        ]
        return records[offset:] if limit is None else records[offset : offset + limit]

    def count(self) -> int:
        return len(self._records)

    def prune(self, now: datetime) -> None:
        terminal = sorted(
            (
                scan
                for scan in self._records.values()
                if scan.state not in ACTIVE_STATES
            ),
            key=lambda scan: scan.finished_at or scan.created_at,
            reverse=True,
        )
        for index, scan in enumerate(terminal):
            if (
                index >= self.retain_completed
                or (now - (scan.finished_at or scan.created_at)).total_seconds()
                >= self.ttl_seconds
            ):
                del self._records[scan.scan_id]


class SQLiteScanStore:
    """Durable sanitized records without automatic history deletion."""

    def __init__(self, path: Path):
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.is_symlink():
            raise ValueError("History database cannot be a symlink")
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
        os.close(descriptor)
        path.chmod(0o600)
        self.connection = sqlite3.connect(path, timeout=5)
        try:
            version = self.connection.execute("PRAGMA user_version").fetchone()[0]
            if version not in (0, 1):
                raise ValueError("Unsupported history database schema")
            self.connection.execute("PRAGMA journal_mode=WAL")
            with self.connection:
                self.connection.execute(
                    "CREATE TABLE IF NOT EXISTS scans ("
                    "scan_id TEXT PRIMARY KEY, created_at TEXT NOT NULL, "
                    "state TEXT NOT NULL, record TEXT NOT NULL)"
                )
                self.connection.execute(
                    "CREATE INDEX IF NOT EXISTS scans_created ON scans(created_at DESC)"
                )
                self.connection.execute("PRAGMA user_version=1")
            self._recover_interrupted()
        except BaseException:
            self.connection.close()
            raise

    def create(self, scan: ScanRecord) -> None:
        try:
            with self.connection:
                self.connection.execute(
                    "INSERT INTO scans VALUES (?, ?, ?, ?)",
                    (
                        scan.scan_id,
                        scan.created_at.isoformat(),
                        scan.state,
                        scan.model_dump_json(),
                    ),
                )
        except sqlite3.IntegrityError:
            raise KeyError(scan.scan_id) from None

    def update(self, scan: ScanRecord) -> None:
        with self.connection:
            changed = self.connection.execute(
                "UPDATE scans SET state=?, record=? WHERE scan_id=?",
                (scan.state, scan.model_dump_json(), scan.scan_id),
            ).rowcount
            if not changed:
                raise KeyError(scan.scan_id)

    def get(self, scan_id: str) -> ScanRecord:
        row = self.connection.execute(
            "SELECT record FROM scans WHERE scan_id=?", (scan_id,)
        ).fetchone()
        if row is None:
            raise KeyError(scan_id)
        return ScanRecord.model_validate_json(row[0])

    def list(self, offset: int = 0, limit: int | None = None) -> list[ScanRecord]:
        rows = self.connection.execute(
            "SELECT record FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?",
            (-1 if limit is None else limit, offset),
        )
        return [ScanRecord.model_validate_json(row[0]) for row in rows]

    def count(self) -> int:
        return self.connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

    def prune(self, now: datetime) -> None:
        # Long-term history is never removed by the transient store's TTL/capacity.
        pass

    def close(self) -> None:
        self.connection.close()

    def _recover_interrupted(self) -> None:
        rows = self.connection.execute(
            "SELECT record FROM scans WHERE state IN ('queued','collecting',"
            "'analyzing','cancelling')"
        ).fetchall()
        for (raw,) in rows:
            scan = ScanRecord.model_validate_json(raw)
            interrupted_analysis = scan.state == ScanState.ANALYZING
            scan.state = (
                ScanState.ANALYSIS_FAILED
                if interrupted_analysis
                else ScanState.CANCELLED
            )
            scan.finished_at = datetime.now(UTC)
            scan.failure = ErrorInfo(
                code="server_restarted",
                message="Operation interrupted by backend restart.",
                retryable=interrupted_analysis,
            )
            scan.warnings = [*scan.warnings[-99:], "server_restarted"]
            for tool in scan.tools.values():
                if tool.state in {"queued", "running"}:
                    tool.state, tool.parse_status = "cancelled", "not_applicable"
                    # The actual stop time is unknown after a crash.
                    tool.finished_at = None
                    tool.error = scan.failure.model_copy(deep=True)
                    scan.partial = True
            for attempt in scan.attempts:
                if attempt.state == "running":
                    attempt.state = "cancelled"
                    attempt.finished_at = scan.finished_at
                    attempt.error = scan.failure.model_copy(deep=True)
            self.update(scan)
