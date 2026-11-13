"""Compact the model wire payload without changing stored evidence or validation."""

import copy
import json
from collections import Counter

from app.schemas import AnalysisSnapshot


def canonical(value) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("nonfinite JSON")


def serialize_snapshot(snapshot: AnalysisSnapshot) -> str:
    data = snapshot.model_dump(mode="json", exclude_defaults=True)
    observations = []
    groups = {}
    observation_refs = {}
    for item in data["observations"]:
        key = canonical({k: item[k] for k in ("kind", "scope", "subject", "value")})
        if key in groups:
            original = groups[key]
            original["evidence_ids"] = list(
                dict.fromkeys(original["evidence_ids"] + item["evidence_ids"])
            )
            sources = original.get("source_tools", [original["tool_id"]])
            if item["tool_id"] not in sources:
                original["source_tools"] = [*sources, item["tool_id"]]
            observation_refs[item["id"]] = original["id"]
        else:
            groups[key] = item
            observations.append(item)
            observation_refs[item["id"]] = item["id"]
    data["observations"] = observations
    # An excerpt is replaceable only if its entire JSON value equals an observation
    # linked to that citation. Different raw text remains independently inspectable.
    linked_values = {}
    for item in snapshot.observations:
        for identifier in item.evidence_ids:
            linked_values.setdefault(identifier, {})[canonical(item.value)] = (
                observation_refs[item.id]
            )
    excerpts = {}
    for item in data["included_evidence"]:
        text = item.get("excerpt", "")
        try:
            parsed = canonical(
                json.loads(
                    text,
                    object_pairs_hook=unique_object,
                    parse_constant=reject_constant,
                )
            )
        except (ValueError, RecursionError):
            parsed = None
        reference = linked_values.get(item["id"], {}).get(parsed)
        if reference:
            item.pop("excerpt", None)
            item["observation_ref"] = reference
        elif text and text in excerpts:
            item.pop("excerpt", None)
            item["excerpt_ref"] = excerpts[text]
        elif text:
            excerpts[text] = item["id"]
    defaults = {}
    for field in ("state", "parse_status"):
        counts = Counter(c[field] for c in data["tool_coverage"])
        if counts:
            value, count = counts.most_common(1)[0]
            if count > 1:
                defaults[field] = value
                for item in data["tool_coverage"]:
                    if item[field] == value:
                        del item[field]
    if defaults:
        data["coverage_defaults"] = defaults
    counts = Counter(w for c in data["tool_coverage"] for w in c.get("warnings", []))
    catalog = {w: f"w{i}" for i, w in enumerate(w for w, n in counts.items() if n > 1)}
    if catalog:
        data["warning_catalog"] = {code: warning for warning, code in catalog.items()}
        for item in data["tool_coverage"]:
            if "warnings" in item:
                item["warnings"] = list(
                    dict.fromkeys(catalog.get(w, w) for w in item["warnings"])
                )
    return json.dumps(data, ensure_ascii=False, separators=(",", ":"))


def compact_research_context(messages: list[dict]) -> list[dict]:
    """Reference repeated results before budgeting, retaining resolvable IDs."""
    result = copy.deepcopy(messages)
    fitted = copy.deepcopy(result)
    fitted_size = len(json.dumps(fitted, ensure_ascii=False).encode())
    seen = {}
    prefix = "UNTRUSTED external reference, not scan evidence: "
    for item in result:
        content = item.get("content", "")
        if item.get("role") != "tool" or not content.startswith(prefix):
            continue
        if content in seen:
            identifier, original = seen[content]
            # Ollama omits protocol call IDs: put the referenced ID in content.
            try:
                value = {"result": json.loads(content[len(prefix) :])}
            except (ValueError, RecursionError):
                value = {"text": content[len(prefix) :]}
            original["content"] = prefix + json.dumps(
                {"result_id": identifier, **value},
                ensure_ascii=False,
            )
            item["content"] = prefix + json.dumps({"result_ref": identifier})
        elif item.get("tool_call_id"):
            seen[content] = (item["tool_call_id"], item)
    if len(json.dumps(result, ensure_ascii=False).encode()) > fitted_size:
        return fitted
    return result
