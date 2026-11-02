"""Baseline scanner signals; no exploit or severity inference."""

from io import StringIO
from pathlib import Path
from urllib.parse import urlsplit

from defusedxml.ElementTree import iterparse, tostring

from app.schemas import ErrorInfo, ToolId
from app.tools.adapters.common import (
    AuthenticatedWebAdapter,
    artifact_json,
    require,
    uri_scope,
)

NIKTO_CONFIG = Path(__file__).resolve().parent.parent / "nikto.conf"
NIKTO_PLUGINS = "tests;headers;report_xml"


class NiktoAdapter(AuthenticatedWebAdapter):
    tool_id = ToolId.NIKTO

    def build_authenticated_spec(self, target, workdir, cookie_header):
        spec = self.build_spec(target, workdir)
        # Kali 2.6.0 consumes STATIC-COOKIE; addcookie alone is silently ignored.
        static_cookies = ";".join(f'"{cookie}"' for cookie in cookie_header.split(";"))
        return spec.model_copy(
            update={
                "argv": (
                    *spec.argv,
                    "-Option",
                    f"addcookie={cookie_header}",
                    "-Option",
                    f"STATIC-COOKIE={static_cookies}",
                )
            }
        )

    def preset(self, target, workdir):
        artifact = workdir / "nikto.xml"
        origin = urlsplit(target.url)._replace(path="", query="", fragment="").geturl()
        return (
            (
                "-config",
                str(NIKTO_CONFIG),
                "-Plugins",
                NIKTO_PLUGINS,
                "-h",
                origin,
                "-root",
                target.base_path,
                "-Tuning",
                "123b",
                "-maxtime",
                "600s",
                "-timeout",
                "5",
                "-nointeractive",
                "-nolookup",
                "-nocheck",
                "-ask",
                "no",
                "-nocookies",
                "-Format",
                "xml",
                "-output",
                str(workdir / "nikto"),
            ),
            630,
            (artifact,),
        )

    def extract(self, target, capture, output):
        output.warn("public_only_coverage")
        output.warn("scanner_signals_require_validation")
        output.warn("nikto_root_is_not_a_path_sandbox")
        if "nikto.xml" in capture.artifacts:
            self.extract_xml(target, capture, output)
            return
        # Historical JSON captures remain replayable; production emits XML.
        document = artifact_json(capture, "nikto.json")
        require(isinstance(document, list))
        for host_index, host in enumerate(document):
            require(
                isinstance(host, dict)
                and host.get("ip") == str(target.ip)
                and str(host.get("port")) == "80"
                and isinstance(host.get("vulnerabilities"), list)
            )
            for index, item in enumerate(host["vulnerabilities"]):
                require(isinstance(item, dict) and isinstance(item.get("msg"), str))
                require(item.get("id") != "FAIL")
                uri = item.get("url", "")
                require(isinstance(uri, str))
                value = {
                    key: item[key]
                    for key in ("id", "msg", "url", "method", "references")
                    if key in item
                }
                output.json_item(
                    filename="nikto.json",
                    pointer=f"/{host_index}/vulnerabilities/{index}",
                    item=item,
                    kind="scanner_signal",
                    scope=(
                        "http_origin"
                        if str(item.get("id")) in {"999986", "013587"}
                        else uri_scope(target, uri)
                    ),
                    subject=str(item.get("id", "scanner signal")),
                    value=value,
                )

    def extract_xml(self, target, capture, output):
        stack = []
        host_index, index = -1, 0
        for event, item in iterparse(
            StringIO(capture.artifacts["nikto.xml"]), events=("start", "end")
        ):
            if event == "start":
                if not stack:
                    require(item.tag == "niktoscans")
                stack.append(item.tag)
                if item.tag == "scandetails":
                    require(
                        item.get("targetip") == str(target.ip)
                        and item.get("targetport") == "80"
                    )
                    host_index += 1
                    index = 0
                continue
            if item.tag == "item":
                require(host_index >= 0 and stack[-2] == "scandetails")
                identifier = item.get("id")
                message, uri = item.findtext("description"), item.findtext("uri", "")
                require(identifier and identifier != "FAIL" and message)
                output.add(
                    kind="scanner_signal",
                    scope="http_origin"
                    if identifier in {"999986", "013587"}
                    else uri_scope(target, uri),
                    subject=identifier,
                    value={
                        "id": identifier,
                        "msg": message,
                        "url": uri,
                        "method": item.get("method", ""),
                        "references": item.findtext("references", ""),
                    },
                    source="artifact",
                    locator=f"nikto.xml#scandetails/{host_index}/item/{index}",
                    excerpt=tostring(item, encoding="unicode"),
                )
                index += 1
            stack.pop()
        require(host_index >= 0)

    def parse(self, target, capture, scan_id):
        result = super().parse(target, capture, scan_id)
        if "Host maximum execution time of" in capture.stderr + capture.stdout:
            result.state = "timed_out"
            result.error = ErrorInfo(
                code="tool_timeout",
                message="Nikto reached its time limit; coverage is incomplete.",
            )
            result.warnings.append("nikto_internal_time_limit")
        return result
