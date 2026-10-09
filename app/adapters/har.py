"""Endpoints from captured traffic (an HTTP Archive).

A HAR is what a browser's network panel or an intercepting proxy saves: the
requests a real client actually made. It finds the endpoints a ticket never
names and a spec forgot, with the parameters they really carry.

Read as data, never replayed. Only names leave the file: method, a templated
path, parameter and field names, and whether a credential header was present.
Header VALUES, cookies and bodies — which in a HAR include live session tokens —
are never stored. Requests to any host other than the capture's dominant one
(analytics, CDNs, identity providers) are skipped and listed, because the
engagement authorized one target, not everything the browser talked to.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from urllib.parse import parse_qsl, urlparse

from app.schemas.analysis import Endpoint

_STATIC = re.compile(
    r"\.(js|mjs|css|map|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|otf|mp4|webm|mp3|pdf|txt)$",
    re.I,
)
_ID_SEGMENT = re.compile(
    r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})$",
    re.I,
)
# A readable slug: lowercase words joined by - or _ (`notification-settings`).
_SLUG = re.compile(r"^[a-z]+(?:[-_][a-z]+)*$")


def _is_id(part: str) -> bool:
    """True for anything that is a value rather than a route name.

    Errs towards templating: a route segment wrongly turned into `{x_id}` costs
    a slightly odd endpoint name, while a token wrongly kept is a magic-link,
    reset or invite secret written into the analysis, the report, the MCP
    output and every AI prompt.
    """
    if _ID_SEGMENT.match(part):
        return True
    if "@" in part or ("." in part and len(part) >= 16):
        return True  # an email address, a JWT (`a.b.c`), a dotted token
    if len(part) >= 16 and not _SLUG.match(part):
        return True  # long and not a lowercase word-slug: mixed case, digits, ...
    # An unbroken lowercase run that long is a token, not a word; a slug with
    # separators (`notification-settings-overview`) is a route name.
    return len(part) >= 24 and "-" not in part and "_" not in part
_AUTH_HEADERS = {"authorization", "cookie", "x-api-key", "x-auth-token", "proxy-authorization"}
_URL_NAME = re.compile(r"(url|uri|callback|webhook|redirect|return|next|image|avatar|link)", re.I)
_MAX_ENTRIES = 5000


class HarError(ValueError):
    """The document is not a HAR this can read."""


def looks_like_har(text: str) -> bool:
    """Decided by structure, not by substrings: an OpenAPI document can carry a
    tag called "log" and a schema called "entries"."""
    if not (text or "").lstrip().startswith("{"):
        return False
    try:
        document = json.loads(text)
    except (TypeError, ValueError):
        return False
    log = document.get("log") if isinstance(document, dict) else None
    return isinstance(log, dict) and isinstance(log.get("entries"), list) \
        and "paths" not in document


def _template(path: str) -> tuple[str, list[str]]:
    """`/orders/8812/items/3` -> `/orders/{order_id}/items/{item_id}`."""
    out, ids = [], []
    parts = [p for p in path.split("/") if p != ""]
    for i, part in enumerate(parts):
        if _is_id(part):
            prev = parts[i - 1] if i else ""
            stem = re.sub(r"[^A-Za-z0-9]", "_", prev[:-1] if prev.endswith("s") else prev)
            name = f"{stem}_id" if prev and not _is_id(prev) else "id"
            while name in ids:
                name += "_"
            ids.append(name)
            out.append("{" + name + "}")
        else:
            out.append(part)
    return "/" + "/".join(out), ids


def _body_fields(request: dict) -> tuple[list[str], list[str]]:
    """(field names, the ones that hold a URL)."""
    post = request.get("postData") or {}
    if not isinstance(post, dict):
        return [], []
    names: list[str] = []
    url_like: list[str] = []
    mime = str(post.get("mimeType", "")).lower()
    if "json" in mime and post.get("text"):
        try:
            body = json.loads(post["text"])
        except (TypeError, ValueError):
            body = None
        if isinstance(body, dict):
            for key, value in body.items():
                names.append(str(key))
                if isinstance(value, str) and value.startswith(("http://", "https://")):
                    url_like.append(str(key))
    for param in _list(post.get("params")):
        if param.get("name"):
            names.append(str(param["name"]))
    return names, url_like


def _list(value) -> list[dict]:
    """Only the dict items of a list; anything else in a HAR is ignored, not
    allowed to crash the import."""
    return [v for v in value if isinstance(v, dict)] if isinstance(value, list) else []


def parse(text: str) -> tuple[list[Endpoint], dict]:
    try:
        document = json.loads(text)
    except (TypeError, ValueError) as exc:
        raise HarError(f"Not valid JSON: {exc}") from None
    log = document.get("log") if isinstance(document, dict) else None
    entries = log.get("entries") if isinstance(log, dict) else None
    if not isinstance(entries, list):
        raise HarError("No `log.entries` — this does not look like a HAR file.")
    entries = [e for e in entries[:_MAX_ENTRIES]
               if isinstance(e, dict) and isinstance(e.get("request"), dict)]

    hosts = Counter()
    for entry in entries:
        url = str(((entry or {}).get("request") or {}).get("url", ""))
        host = urlparse(url).hostname
        if host and not _STATIC.search(urlparse(url).path):
            hosts[host] += 1
    if not hosts:
        raise HarError("The HAR holds no API requests.")
    target, _ = hosts.most_common(1)[0]

    found: dict[str, Endpoint] = {}
    skipped_hosts: Counter = Counter()
    n_static = 0
    for entry in entries:
        request = (entry or {}).get("request") or {}
        parsed = urlparse(str(request.get("url", "")))
        if parsed.hostname != target:
            if parsed.hostname:
                skipped_hosts[parsed.hostname] += 1
            continue
        if _STATIC.search(parsed.path) or str(request.get("method", "")).upper() == "OPTIONS":
            n_static += 1
            continue
        method = str(request.get("method", "GET")).upper()
        path, ids = _template(parsed.path or "/")
        query = sorted({k for k, _ in parse_qsl(parsed.query, keep_blank_values=True)}
                       | {str(q.get("name")) for q in _list(request.get("queryString"))
                          if q.get("name")})
        header_names = {str(h.get("name", "")).lower() for h in _list(request.get("headers"))}
        body, url_body = _body_fields(request)
        url_fields = sorted({*url_body, *(q for q in query if _URL_NAME.search(q))})
        endpoint = Endpoint(
            method=method, path=path,
            auth_required=bool(header_names & _AUTH_HEADERS),
            object_id_params=ids,
            query_params=query,
            body_fields=sorted(set(body)),
            url_fields=url_fields,
            writes_properties=method in ("POST", "PUT", "PATCH") and bool(body),
        )
        current = found.get(endpoint.signature)
        if current is None:
            found[endpoint.signature] = endpoint
        else:
            found[endpoint.signature] = current.model_copy(update={
                "auth_required": current.auth_required or endpoint.auth_required,
                "query_params": sorted({*current.query_params, *endpoint.query_params}),
                "body_fields": sorted({*current.body_fields, *endpoint.body_fields}),
                "url_fields": sorted({*current.url_fields, *endpoint.url_fields}),
                "writes_properties": current.writes_properties or endpoint.writes_properties,
            })

    summary = {
        "title": f"HAR capture of {target}",
        "version": "",
        "spec_version": "HAR",
        "n_endpoints": len(found),
        "n_public": 0,
        "skipped": [f"{h} ({n} request(s), not the captured target)"
                    for h, n in skipped_hosts.most_common(10)]
                   + ([f"{n_static} static asset/preflight request(s)"] if n_static else []),
        "target_host": target,
    }
    return list(found.values()), summary
