"""Technology fingerprints with source versions only."""

from app.schemas import ToolId
from app.tools.adapters.common import AuthenticatedWebAdapter, artifact_json, require


class WhatwebAdapter(AuthenticatedWebAdapter):
    tool_id = ToolId.WHATWEB

    def cookie_arguments(self, cookies):
        return (f"--cookie={cookies}",)

    def preset(self, target, workdir):
        artifact = workdir / "whatweb.json"
        return (
            (
                "-a",
                "1",
                "--max-threads",
                "1",
                "--follow-redirect=never",
                "--open-timeout",
                "5",
                "--read-timeout",
                "10",
                "--color=never",
                f"--log-json={artifact}",
                target.url,
            ),
            30,
            (artifact,),
        )

    def extract(self, target, capture, output):
        document = artifact_json(capture, "whatweb.json")
        require(isinstance(document, list))
        output.warn("public_only_coverage")
        for index, item in enumerate(document):
            require(
                isinstance(item, dict)
                and item.get("target") == target.url
                and isinstance(item.get("plugins"), dict)
            )
            status = item.get("http_status")
            if status in {401, 403}:
                output.warn("authentication_required")
            if isinstance(status, int) and 300 <= status < 400:
                output.warn("redirect_not_followed")
            for name, plugin in item["plugins"].items():
                if plugin == "[REDACTED]":
                    output.warn("sensitive_fingerprint_omitted")
                    continue
                require(isinstance(plugin, dict))
                # No inference of versions, CVEs, or application ownership from banners.
                value = {
                    key: plugin[key]
                    for key in (
                        "version",
                        "string",
                        "os",
                        "module",
                        "model",
                        "firmware",
                        "certainty",
                    )
                    if key in plugin
                }
                pointer_name = name.replace("~", "~0").replace("/", "~1")
                output.json_item(
                    filename="whatweb.json",
                    pointer=f"/{index}/plugins/{pointer_name}",
                    item=plugin,
                    kind="technology",
                    scope="http_origin",
                    subject=name,
                    value=value,
                )
