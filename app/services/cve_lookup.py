"""Bounded external advisory correlation; never probe or certify a target."""

import asyncio
import json
import re
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from app.errors import OperationError
from app.schemas import CVECandidate, CVELookup, CVEMatchReason, CVEScore

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REQUEST_INTERVAL = 6.2
CVE_ID = re.compile(r"\bCVE-\d{4}-\d{4,19}\b", re.I)
VERSION = re.compile(r"\d+(?:\.\d+){1,3}(?:[a-z]\d*)?", re.ASCII)
PRODUCTS = {
    "apache": ("apache", "http_server"),
    "apache httpd": ("apache", "http_server"),
    "apache http server": ("apache", "http_server"),
    "php": ("php", "php"),
}


@dataclass
class Query:
    params: dict[str, str]
    detail: str
    basis: str
    scope: str
    evidence_ids: list[str] = field(default_factory=list)
    additional_reasons: list[CVEMatchReason] = field(default_factory=list)


def extract_queries(scan):
    queries, warnings = {}, []
    for tool in scan.tools.values():
        available = {item.id for item in tool.evidence}
        for observation in tool.observations:
            ids = [eid for eid in observation.evidence_ids if eid in available][:10]
            if not ids:
                continue
            candidates = []
            value = observation.value
            if observation.kind == "scanner_signal":
                for identifier in dict.fromkeys(
                    CVE_ID.findall(json.dumps(value, ensure_ascii=False))
                ):
                    candidates.append(
                        (
                            {"cveId": identifier.upper()},
                            identifier.upper(),
                            "scanner_reference",
                        )
                    )
            product, version = None, None
            if isinstance(value, dict):
                if observation.kind == "port":
                    service = value.get("service", {})
                    if isinstance(service, dict):
                        product, version = (
                            service.get("product"),
                            service.get("version"),
                        )
                elif observation.kind == "technology":
                    product, version = observation.subject, value.get("version")
                elif observation.kind == "http" and observation.subject in {
                    "server",
                    "x-powered-by",
                }:
                    banner = value.get(observation.subject)
                    if isinstance(banner, str):
                        match = re.fullmatch(
                            r"(Apache|PHP)/([0-9.a-z]+)(?:\s.*)?", banner
                        )
                        if match:
                            product, version = match.groups()
            if isinstance(version, list):
                version = version[0] if len(version) == 1 else None
            known = PRODUCTS.get(product.lower()) if isinstance(product, str) else None
            if known and isinstance(version, str) and VERSION.fullmatch(version):
                vendor, name = known
                cpe = f"cpe:2.3:a:{vendor}:{name}:{version}:*:*:*:*:*:*:*"
                candidates.append(
                    (
                        {"cpeName": cpe, "isVulnerable": ""},
                        f"{product} {version}",
                        "reported_version",
                    )
                )
            for params, detail, basis in candidates:
                key = tuple(params.items())
                if key not in queries:
                    if len(queries) >= 4:
                        if "query_limit_reached" not in warnings:
                            warnings.append("query_limit_reached")
                        continue
                    queries[key] = Query(params, detail, basis, observation.scope, ids)
                else:
                    query = queries[key]
                    reason = CVEMatchReason(
                        basis=basis,
                        detail=detail,
                        scope=observation.scope,
                        evidence_ids=ids,
                    )
                    if reason.scope == query.scope and reason.detail == query.detail:
                        query.evidence_ids = list(
                            dict.fromkeys(query.evidence_ids + ids)
                        )[:10]
                    elif (
                        reason not in query.additional_reasons
                        and len(query.additional_reasons) < 9
                    ):
                        query.additional_reasons.append(reason)
    return list(queries.values()), warnings


def public_reference(value):
    if not isinstance(value, str) or len(value) > 2000:
        return False
    try:
        parts = urlsplit(value)
        return (
            parts.scheme in {"http", "https"}
            and bool(parts.hostname)
            and not parts.username
        )
    except ValueError:
        return False


def parse_record(row, query, retrieved_at):
    identifier = row["id"]
    if not isinstance(identifier, str) or not CVE_ID.fullmatch(identifier):
        raise ValueError("Invalid CVE identifier")
    identifier = identifier.upper()
    if row.get("vulnStatus", "").lower() == "rejected":
        return None
    if "cveId" in query.params and identifier != query.params["cveId"]:
        return None
    description = next(
        item["value"] for item in row["descriptions"] if item.get("lang") == "en"
    )
    if not isinstance(description, str) or not description.strip():
        raise ValueError("No description")
    name = row.get("cisaVulnerabilityName")
    title = name if isinstance(name, str) and name.strip() else description
    scores = []
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for metric in row.get("metrics", {}).get(key, [])[:2]:
            data = metric.get("cvssData", {})
            if type(data.get("baseScore")) not in {float, int}:
                continue
            scores.append(
                CVEScore(
                    version=data["version"],
                    score=data["baseScore"],
                    vector=data.get("vectorString", ""),
                    source=metric.get("source", "unknown"),
                )
            )
    affected = []

    def conditions(node, depth=0):
        if depth > 10 or len(affected) >= 20:
            return
        if isinstance(node, list):
            for child in node:
                conditions(child, depth + 1)
        elif isinstance(node, dict):
            if "criteria" in node:
                fields = {
                    key: node[key]
                    for key in (
                        "criteria",
                        "vulnerable",
                        "versionStartIncluding",
                        "versionStartExcluding",
                        "versionEndIncluding",
                        "versionEndExcluding",
                    )
                    if key in node
                }
                affected.append(json.dumps(fields, ensure_ascii=False)[:1000])
            for key in ("nodes", "children", "cpeMatch"):
                if key in node:
                    conditions(node[key], depth + 1)

    conditions(row.get("configurations", []))
    weaknesses = [
        entry["value"]
        for weak in row.get("weaknesses", [])
        for entry in weak.get("description", [])
        if entry.get("lang") == "en"
        and isinstance(entry.get("value"), str)
        and len(entry["value"]) <= 100
    ]
    references = [
        entry["url"]
        for entry in row.get("references", [])
        if public_reference(entry.get("url"))
    ]
    return CVECandidate(
        cve_id=identifier,
        title=title[:160],
        description=description[:6000],
        affected=affected[:20],
        scores=scores[:8],
        weaknesses=list(dict.fromkeys(weaknesses))[:20],
        references=list(dict.fromkeys(references))[:20],
        source_url=f"https://nvd.nist.gov/vuln/detail/{identifier}",
        published=row.get("published"),
        modified=row.get("lastModified"),
        retrieved_at=retrieved_at,
        reasons=[
            CVEMatchReason(
                basis=query.basis,
                detail=query.detail,
                scope=query.scope,
                evidence_ids=query.evidence_ids,
            )
        ]
        + query.additional_reasons,
    )


class CVELookupService:
    def __init__(self, client):
        self.client = client
        self.lock = asyncio.Lock()
        self.cache = {}
        self.next_request = 0.0

    async def _fetch(self, query):
        key = tuple(query.params.items())
        cached = self.cache.get(key)
        if cached and time.monotonic() - cached[0] < 86400:
            return cached[1], cached[2]
        await asyncio.sleep(max(0, self.next_request - time.monotonic()))
        self.next_request = time.monotonic() + REQUEST_INTERVAL
        async with asyncio.timeout(15):
            async with self.client.stream(
                "GET",
                NVD_URL,
                params={**query.params, "resultsPerPage": 10},
                timeout=15,
                follow_redirects=False,
            ) as response:
                if response.status_code != 200:
                    raise ValueError("CVE source unavailable")
                body = bytearray()
                async for chunk in response.aiter_bytes(chunk_size=16384):
                    if len(body) + len(chunk) > 1048576:
                        raise ValueError("CVE source response too large")
                    body.extend(chunk)
        data = json.loads(body)
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("vulnerabilities"), list)
            or type(data.get("totalResults")) is not int
        ):
            raise ValueError("Invalid CVE source response")
        retrieved = datetime.now(UTC)
        if len(self.cache) >= 128:
            del self.cache[next(iter(self.cache))]
        self.cache[key] = time.monotonic(), data, retrieved
        return data, retrieved

    async def lookup(self, scan):
        if self.lock.locked():
            raise OperationError(
                409, "cve_lookup_busy", "Another CVE lookup is running.", retryable=True
            )
        async with self.lock:
            queries, warnings = extract_queries(scan)
            result = CVELookup(
                state="completed" if queries else "insufficient_evidence",
                checked_at=datetime.now(UTC),
                warnings=warnings,
            )
            matches = {}
            try:
                async with asyncio.timeout(45):
                    for query in queries:
                        try:
                            data, retrieved = await self._fetch(query)
                            result.queries_completed += 1
                            if data["totalResults"] > 10:
                                warnings.append("source_results_truncated")
                            for entry in data["vulnerabilities"][:10]:
                                try:
                                    item = parse_record(entry["cve"], query, retrieved)
                                except (
                                    ValueError,
                                    TypeError,
                                    KeyError,
                                    AttributeError,
                                    StopIteration,
                                    ValidationError,
                                ):
                                    warnings.append("invalid_source_record_omitted")
                                    continue
                                if item is None:
                                    continue
                                if item.cve_id in matches:
                                    previous = matches[item.cve_id]
                                    previous.reasons = (
                                        previous.reasons + item.reasons
                                    )[:10]
                                elif len(matches) < 20:
                                    matches[item.cve_id] = item
                                else:
                                    warnings.append("match_limit_reached")
                        except (
                            httpx.HTTPError,
                            ValueError,
                            TimeoutError,
                            TypeError,
                            RecursionError,
                        ):
                            warnings.append("cve_source_unavailable")
            except TimeoutError:
                warnings.append("cve_lookup_deadline_reached")
            result.matches = list(matches.values())
            result.warnings = list(dict.fromkeys(warnings))[:20]
            if queries and result.queries_completed == 0:
                result.state = "failed"
            elif warnings:
                result.state = "partial"
            return result
