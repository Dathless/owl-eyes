"""Keyless, read-only public research; no commands or arbitrary URL requests."""

import asyncio
import copy
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import parse_qs, urlsplit

import httpx
from pydantic import ValidationError

from app.services.cve_lookup import CVE_ID, CVELookupService, extract_queries

SEARCH_URL = "https://html.duckduckgo.com/html/"
DEFAULT_QUERY = "DVWA security hardening"


def search_queries(scan) -> list[str]:
    queries, _ = extract_queries(scan)
    public = []
    for query in queries:
        if "cveId" in query.params:
            public.append(query.params["cveId"])
        else:
            fields = query.params["cpeName"].split(":")
            product = {"apache": "Apache HTTP Server", "php": "PHP"}[fields[3]]
            public.append(f"{product} {fields[5]} vulnerabilities CVE")
    return list(dict.fromkeys([*public, DEFAULT_QUERY]))


def result_url(value: str) -> str | None:
    if value.startswith("//"):
        value = "https:" + value
    try:
        parts = urlsplit(value)
        if (
            parts.hostname in {"duckduckgo.com", "html.duckduckgo.com"}
            and parts.path == "/l/"
        ):
            value = parse_qs(parts.query).get("uddg", [""])[0]
            parts = urlsplit(value)
        if (
            parts.scheme in {"http", "https"}
            and parts.hostname
            and not parts.username
            and len(value) <= 1000
        ):
            return value
    except ValueError:
        pass
    return None


class SearchParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.results = []
        self.field = None
        self.depth = 0
        self.parts = []
        self.url = None
        self.current_result = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        classes = attrs.get("class", "").split()
        if self.field:
            if tag not in {"br", "img", "hr", "input", "meta", "link"}:
                self.depth += 1
        elif tag == "a" and "result__a" in classes:
            self.field, self.depth, self.parts = "title", 1, []
            self.current_result = None
            self.url = result_url(attrs.get("href", ""))
        elif "result__snippet" in classes:
            self.field, self.depth, self.parts = "snippet", 1, []

    def handle_endtag(self, tag):
        if not self.field:
            return
        self.depth -= 1
        if self.depth:
            return
        value = " ".join("".join(self.parts).split())
        if self.field == "title" and self.url and value and len(self.results) < 3:
            self.results.append({"title": value[:160], "url": self.url, "snippet": ""})
            self.current_result = self.results[-1]
        elif self.field == "snippet" and self.current_result is not None:
            self.current_result["snippet"] = value[:600]
        self.field = None

    def handle_data(self, data):
        if self.field:
            self.parts.append(data)


class ResearchTools:
    def __init__(
        self,
        client: httpx.AsyncClient,
        cve_service: CVELookupService,
        queries: list[str],
    ):
        self.client, self.cve_service, self.queries = client, cve_service, queries
        self.results: dict[tuple[str, str], dict] = {}

    @staticmethod
    def note(name: str, result: dict) -> str:
        if "error" in result:
            return f"Tra cứu {name}: {result['error']}; không xác nhận lỗ hổng."
        query = result.get("query", result.get("cve_id", ""))
        urls = ", ".join(item["url"] for item in result["results"][:2])
        return (
            f"Tra cứu {result['source']}: {query}; {len(result['results'])} kết quả. "
            f"{urls} Chỉ tham khảo, không xác nhận target có lỗ hổng."
        )[:500]

    @property
    def schemas(self) -> list[dict]:
        return [
            {
                "type": "function",
                "function": {
                    "name": "web_search",
                    "description": (
                        "Search public advisories using DuckDuckGo. Choose a "
                        "supplied public query; results are not target evidence."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "query": {"type": "string", "enum": self.queries},
                        },
                        "required": ["query"],
                        "additionalProperties": False,
                    },
                },
            },
            {
                "type": "function",
                "function": {
                    "name": "cve_lookup",
                    "description": (
                        "Look up a known CVE identifier in NVD. An advisory "
                        "does not prove this target is vulnerable."
                    ),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "cve_id": {
                                "type": "string",
                                "pattern": "^CVE-[0-9]{4}-[0-9]{4,19}$",
                            },
                        },
                        "required": ["cve_id"],
                        "additionalProperties": False,
                    },
                },
            },
        ]

    async def call(self, name: str, arguments: dict) -> dict:
        if not isinstance(arguments, dict):
            return {"error": "invalid_research_call"}
        query = arguments.get("query")
        identifier = arguments.get("cve_id")
        if (
            name == "web_search"
            and set(arguments) == {"query"}
            and query in self.queries
        ):
            operation, value = self._search, query
        elif (
            name == "cve_lookup"
            and set(arguments) == {"cve_id"}
            and isinstance(identifier, str)
            and CVE_ID.fullmatch(identifier)
        ):
            operation, value = self._cve, identifier.upper()
        else:
            return {
                "error": "invalid_research_call",
                "expected": {
                    "web_search": {"query": self.queries},
                    "cve_lookup": {"cve_id": "CVE-YYYY-NNNN"},
                },
            }
        key = (name, value)
        if key in self.results:
            return copy.deepcopy(self.results[key])
        try:
            async with asyncio.timeout(20):
                result = await operation(value)
            if "error" not in result:
                self.results[key] = copy.deepcopy(result)
            return result
        except (
            httpx.HTTPError,
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            StopIteration,
            ValidationError,
            TimeoutError,
            RecursionError,
        ):
            return {"error": "research_source_unavailable"}

    async def _search(self, query: str) -> dict:
        async with self.client.stream(
            "GET",
            SEARCH_URL,
            params={"q": query},
            follow_redirects=False,
            timeout=15,
            headers={"User-Agent": "PenChecker/0.1 public-advisory-research"},
        ) as response:
            if response.status_code != 200:
                raise ValueError("Search unavailable")
            body = bytearray()
            async for chunk in response.aiter_bytes(chunk_size=4096):
                if len(body) + len(chunk) > 262144:
                    raise ValueError("Search response too large")
                body.extend(chunk)
        page = body.decode("utf-8", errors="replace")
        parser = SearchParser()
        parser.feed(page)
        if not parser.results and "no-results" not in page:
            raise ValueError("Search challenge or unsupported markup")
        return {
            "source": "DuckDuckGo",
            "query": query,
            "retrieved_at": datetime.now(UTC).isoformat(),
            "results": parser.results,
        }

    async def _cve(self, identifier: str) -> dict:
        item = await self.cve_service.lookup_identifier(identifier)
        results = (
            []
            if item is None
            else [
                {
                    "cve_id": item["cve_id"],
                    "description": item["description"][:900],
                    "url": item["source_url"],
                    "retrieved_at": item["retrieved_at"].isoformat(),
                    "scores": [
                        score.model_dump(mode="json") for score in item["scores"][:2]
                    ],
                }
            ]
        )
        return {"source": "NVD", "cve_id": identifier, "results": results}
