"""Postman collection (v2.1) → declarative TestCases.

Same principle as the PoC transpiler: an imported artifact is *data*, converted
into TestCases that the trusted runner executes with full scope validation. The
collection's host is stripped — the runner supplies the approved base URL — so a
collection pointed at some other host cannot re-introduce an off-scope target.
"""

from __future__ import annotations

import json

from app.poc.transpiler import ExtractedRequest, TranspileResult, to_test_cases

__all__ = ["transpile_postman", "postman_to_test_cases"]


def transpile_postman(collection: dict | str) -> TranspileResult:
    if isinstance(collection, str):
        try:
            collection = json.loads(collection)
        except json.JSONDecodeError as exc:
            r = TranspileResult()
            r.unsupported.append(f"invalid JSON: {exc}")
            return r

    result = TranspileResult()
    _walk_items(collection.get("item", []), result)
    if not result.requests:
        result.unsupported.append("no requests found in collection")
    return result


def postman_to_test_cases(collection: dict | str, **kwargs):
    return to_test_cases(transpile_postman(collection), **kwargs)


def _walk_items(items: list, result: TranspileResult) -> None:
    for item in items or []:
        if "item" in item:  # folder → recurse
            _walk_items(item["item"], result)
            continue
        request = item.get("request")
        if not request:
            continue
        req = _extract(request)
        if req:
            result.requests.append(req)


def _extract(request) -> ExtractedRequest | None:
    if isinstance(request, str):  # shorthand: request is just a URL string
        return ExtractedRequest("GET", request)

    method = (request.get("method") or "GET").upper()
    url = _url(request.get("url"))
    if not url:
        return None
    headers = {
        h.get("key", ""): h.get("value", "")
        for h in request.get("header", []) or []
        if not h.get("disabled")
    }
    body = _body(request.get("body"))
    return ExtractedRequest(method=method, url=url, headers=headers, body=body)


def _url(url) -> str:
    if not url:
        return ""
    if isinstance(url, str):
        return url
    raw = url.get("raw")
    if raw:
        return raw
    # assemble from parts
    host = url.get("host")
    host = ".".join(host) if isinstance(host, list) else (host or "")
    path = url.get("path")
    path = "/".join(path) if isinstance(path, list) else (path or "")
    scheme = url.get("protocol", "https")
    q = url.get("query") or []
    query = "&".join(f"{i.get('key')}={i.get('value')}" for i in q if not i.get("disabled"))
    base = f"{scheme}://{host}/{path}"
    return f"{base}?{query}" if query else base


def _body(body) -> object | None:
    if not body:
        return None
    mode = body.get("mode")
    if mode == "raw":
        raw = body.get("raw", "")
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            return raw
    if mode == "urlencoded":
        return {i.get("key"): i.get("value") for i in body.get("urlencoded", []) if not i.get("disabled")}
    if mode == "formdata":
        return {i.get("key"): i.get("value") for i in body.get("formdata", []) if not i.get("disabled")}
    return None
