"""Adapter interface; callers allocate a disposable workdir before build_spec."""

from pathlib import Path
from typing import Protocol

from app.schemas import Capture, TargetSpec, ToolId, ToolResult, ToolSpec


class ToolAdapter(Protocol):
    tool_id: ToolId

    def applicability(self, target: TargetSpec) -> str | None: ...

    def build_spec(self, target: TargetSpec, workdir: Path) -> ToolSpec: ...

    def parse(
        self, target: TargetSpec, capture: Capture, scan_id: str
    ) -> ToolResult: ...
