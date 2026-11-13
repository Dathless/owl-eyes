"""One escaped report template and private, versioned HTML archive."""

import json
import os
import shutil
import tempfile
from pathlib import Path
from uuid import UUID

from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.schemas import ScanRecord

APP = Path(__file__).resolve().parents[1]
TEMPLATE_VERSION = "1.0"
ENVIRONMENT = Environment(
    loader=FileSystemLoader(APP / "templates"), autoescape=select_autoescape(["html"])
)


def render_report_html(scan: ScanRecord) -> str:
    if scan.report is None:
        raise ValueError("No validated report")
    observations = [
        {
            "tool": tool.tool_id,
            "scope": observation.scope,
            "subject": observation.subject,
            "value": json.dumps(observation.value, ensure_ascii=False, indent=2),
        }
        for tool in scan.tools.values()
        for observation in tool.observations
    ]
    return ENVIRONMENT.get_template("report_archive.html").render(
        scan=scan,
        envelope=scan.report,
        report=scan.report.report,
        template_version=TEMPLATE_VERSION,
        observations=observations,
    )


class ReportArchive:
    def __init__(self, directory: Path):
        self.directory = Path(directory)

    @staticmethod
    def identifier(value: str) -> str:
        if str(UUID(value)) != value:
            raise ValueError("Noncanonical scan identifier")
        return value

    @staticmethod
    def url(scan: ScanRecord) -> str:
        return f"/api/scans/{scan.scan_id}/reports/{scan.report.revision}.html"

    def _root(self):
        if self.directory.is_symlink():
            raise OSError("Archive symlinks are disabled")
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)

    def path(self, scan_id: str, revision: int) -> Path:
        scan_id = self.identifier(scan_id)
        if type(revision) is not int or revision < 1:
            raise ValueError("Invalid report revision")
        self._root()
        folder = self.directory / scan_id
        path = folder / f"r{revision}.html"
        if folder.is_symlink() or path.is_symlink():
            raise OSError("Archive symlinks are disabled")
        return path

    @staticmethod
    def _write(path: Path, content: str):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary = tempfile.mkstemp(prefix=".report-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            Path(temporary).unlink(missing_ok=True)

    def prepare(self):
        self._root()
        css = self.directory / "report.css"
        if css.is_symlink():
            raise OSError("Archive symlinks are disabled")
        content = (APP / "static/css/report-archive.css").read_text(encoding="utf-8")
        if not css.exists() or css.read_text(encoding="utf-8") != content:
            self._write(css, content)

    def save(self, scan: ScanRecord) -> str:
        if scan.report is None:
            raise ValueError("No validated report")
        path = self.path(scan.scan_id, scan.report.revision)
        self.prepare()
        self._write(path, render_report_html(scan))
        return self.url(scan)

    def read(self, scan_id: str, revision: int) -> str:
        return self.path(scan_id, revision).read_text(encoding="utf-8")

    def clear(self):
        self._root()
        for path in self.directory.iterdir():
            try:
                self.identifier(path.name)
            except ValueError:
                continue
            if path.is_symlink():
                path.unlink()
            elif path.is_dir():
                shutil.rmtree(path)
