"""OpenAPI / Swagger → the endpoint list everything else is derived from.

The endpoint list is the single input the whole test plan is built from:
`TestDesigner` emits one test set per endpoint, and the OWASP mapping is
computed from their parameters. Until now that list came from a regex over the
prose of a Jira ticket — which misses any endpoint written in a table or an
attachment, marks everything as requiring auth because it cannot tell, and only
finds object ids that appear in a path. A coverage figure of 85% computed over
four endpoints when the service has twelve is not a wrong number; it is a
number about the wrong thing.

A specification is the accurate source. It states the methods, the paths, every
parameter and where it lives, which routes are public, and which bodies exist —
each of which was previously a guess.

**Parsed as data, never executed, and never fetched.** The document is read
from a paste or an upload; this module does not go and get it. A URL in a spec
is a host somebody else chose, and the one thing this platform will not do is
send a request somewhere the engagement did not authorize — `servers:` is read
for information and never becomes a target.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.schemas.analysis import Endpoint

#: Methods that carry a body worth tampering with (API3: mass assignment).
_WRITE_METHODS = {"POST", "PUT", "PATCH"}

#: Every HTTP method an OpenAPI path item may define. `parameters`, `summary`,
#: `$ref` and friends live beside them and are not operations.
_METHODS = ("get", "put", "post", "delete", "patch", "head", "options", "trace")

#: A parameter or property whose name reads like an object identifier — the
#: BOLA/BOPLA surface. Matched on word boundaries so `paid` and `valid` do not
#: qualify as ids.
_ID_NAME = re.compile(r"(^|[_\-.])(id|uuid|guid|key|ref|no|num|number)$", re.IGNORECASE)
_ID_SUFFIX = re.compile(r"[a-z0-9]+(_?id|Id|ID|Uuid|UUID|Guid|GUID)$")

#: A field holding a URL the server will fetch itself (API7: SSRF).
_URL_NAME = re.compile(
    r"url|uri|callback|webhook|redirect|endpoint|link|href|src", re.IGNORECASE
)


class SpecError(ValueError):
    """The document is not a specification this can read."""


def _load(text: str) -> dict:
    """JSON, or YAML when PyYAML is installed.

    `safe_load`, never `load`: the full YAML loader constructs arbitrary Python
    objects, and this parses documents that arrive from outside. A spec is
    data; a spec that can run code is an exploit.
    """
    text = (text or "").strip()
    if not text:
        raise SpecError("The specification is empty.")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    try:
        import yaml
    except ImportError:
        raise SpecError(
            "This looks like YAML, and PyYAML is not installed. Install it "
            "(pip install pyyaml), or paste the JSON form of the spec — most "
            "frameworks serve one at /openapi.json or /swagger.json."
        ) from None
    try:
        loaded = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise SpecError(f"The specification is neither valid JSON nor valid YAML: {exc}") from None
    if not isinstance(loaded, dict):
        raise SpecError("The specification's top level is not an object.")
    return loaded


def _resolve(node: Any, root: dict, _seen: frozenset = frozenset()) -> Any:
    """Follow a local `$ref` one hop at a time.

    Only `#/...` references: a remote `$ref` is a URL, and resolving one would
    mean fetching a document from a host nobody authorized. `_seen` stops a
    reference cycle from recursing forever — self-referential schemas are
    ordinary in real specs (a tree node, a comment with replies).
    """
    if not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return node
    if ref in _seen:
        return {}
    target: Any = root
    for part in ref[2:].split("/"):
        part = part.replace("~1", "/").replace("~0", "~")
        if not isinstance(target, dict) or part not in target:
            return {}
        target = target[part]
    return _resolve(target, root, _seen | {ref})


def _looks_like_id(name: str) -> bool:
    return bool(_ID_NAME.search(name) or _ID_SUFFIX.search(name))


def _body_schema(operation: dict, root: dict) -> dict:
    """The request body's schema, across both spec versions.

    OpenAPI 3 puts it under `requestBody.content.<media>.schema`; Swagger 2 uses
    a parameter with `in: body`.
    """
    body = _resolve(operation.get("requestBody") or {}, root)
    for media in (body.get("content") or {}).values():
        schema = _resolve((media or {}).get("schema") or {}, root)
        if schema:
            return schema
    for param in operation.get("parameters") or []:
        param = _resolve(param, root)
        if param.get("in") == "body":
            return _resolve(param.get("schema") or {}, root)
    return {}


def _property_names(schema: dict, root: dict, depth: int = 0) -> list[str]:
    """Every property name in a body schema, including nested objects.

    Bounded depth: a schema that refers to itself is normal, and the names a
    few levels down are not what a mass-assignment probe aims at anyway.
    """
    if depth > 4 or not isinstance(schema, dict):
        return []
    schema = _resolve(schema, root)
    names: list[str] = []
    for key, prop in (schema.get("properties") or {}).items():
        names.append(key)
        names.extend(_property_names(prop, root, depth + 1))
    for combinator in ("allOf", "anyOf", "oneOf"):
        for sub in schema.get(combinator) or []:
            names.extend(_property_names(sub, root, depth + 1))
    if "items" in schema:
        names.extend(_property_names(schema["items"], root, depth + 1))
    return names


def _is_public(operation: dict, root_security: Any) -> bool:
    """Whether the spec says this route needs no credential.

    `security: []` on an operation is the explicit "this one is public", and it
    overrides a document-wide requirement. This is the fact the prose extractor
    could never know — it marked everything as requiring auth, which turns
    every intentionally public route into a false API2 finding waiting to be
    triaged.
    """
    if "security" in operation:
        return not operation["security"]
    return not root_security


def parse(text: str) -> tuple[list[Endpoint], dict]:
    """Return the endpoints a spec declares, plus what was read about it.

    The second value is for the person reviewing the import: which document
    this was, how many operations it held, and anything skipped — an endpoint
    silently absent from the list is the failure worth preventing, because
    everything downstream is derived from the list.
    """
    document = _load(text)
    paths = document.get("paths")
    if not isinstance(paths, dict):
        raise SpecError(
            "No `paths` object — this does not look like an OpenAPI or Swagger "
            "document. (A Postman collection imports under the PoC field instead.)"
        )

    info = document.get("info") or {}
    root_security = document.get("security")
    # Swagger 2's `basePath` prefixes every route; OpenAPI 3 puts the prefix in
    # `servers[].url`, which is a host we deliberately do not read as a target.
    base_path = (document.get("basePath") or "").rstrip("/")

    endpoints: list[Endpoint] = []
    skipped: list[str] = []
    seen: set[str] = set()

    for raw_path, item in paths.items():
        item = _resolve(item, document)
        if not isinstance(item, dict):
            skipped.append(f"{raw_path} (not an object)")
            continue
        shared_params = item.get("parameters") or []
        for method in _METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            path = f"{base_path}{raw_path}" if base_path else raw_path
            signature = f"{method.upper()} {path}"
            if signature in seen:
                continue
            seen.add(signature)

            params = [_resolve(p, document) for p in (*shared_params, *(operation.get("parameters") or []))]
            object_ids: list[str] = []
            url_fields: list[str] = []
            query_params: list[str] = []
            for param in params:
                name = param.get("name") or ""
                location = param.get("in")
                if not name or location == "body":
                    continue
                if location == "query" and name not in query_params:
                    query_params.append(name)
                if _looks_like_id(name):
                    object_ids.append(name)
                if _URL_NAME.search(name):
                    url_fields.append(name)

            body = _body_schema(operation, document)
            properties = _property_names(body, document)
            for name in properties:
                if _looks_like_id(name) and name not in object_ids:
                    object_ids.append(name)
                if _URL_NAME.search(name) and name not in url_fields:
                    url_fields.append(name)

            endpoints.append(Endpoint(
                method=method.upper(),
                path=path,
                # The spec knows. The prose extractor had to assume.
                auth_required=not _is_public(operation, root_security),
                expected_public=_is_public(operation, root_security),
                object_id_params=object_ids,
                writes_properties=bool(properties) or method.upper() in _WRITE_METHODS,
                url_fields=url_fields,
                # Sorted so a re-import of the same spec is a no-op: `merge()`
                # recombines these as a sorted set, and unsorted insertion order
                # here would make the FIRST import (nothing to merge with yet,
                # so it keeps this order verbatim) disagree with every import
                # after it.
                query_params=sorted(query_params)[:30],
                body_fields=sorted(dict.fromkeys(properties))[:40],
            ))

    if not endpoints:
        raise SpecError("The specification declares no operations.")

    summary = {
        "title": str(info.get("title") or "(untitled)"),
        "version": str(info.get("version") or ""),
        "spec_version": str(document.get("openapi") or document.get("swagger") or "unknown"),
        "n_endpoints": len(endpoints),
        "n_public": sum(1 for e in endpoints if e.expected_public),
        "n_with_object_ids": sum(1 for e in endpoints if e.object_id_params),
        "servers": [
            str((s or {}).get("url", "")) for s in (document.get("servers") or [])
        ][:5],
        "skipped": skipped,
    }
    return endpoints, summary


def merge(existing: list[Endpoint], imported: list[Endpoint]) -> tuple[list[Endpoint], dict]:
    """Add what the spec declares, without discarding what a person entered.

    Additive in the same direction the endpoint editor already is: a
    hand-entered row exists precisely because something else could not find it,
    so an import never removes one. Where both describe the same route the
    spec wins on the facts it actually knows — whether a credential is required,
    and which parameters are object ids — because those were guesses before.
    """
    by_signature = {e.signature: e for e in existing}
    added, enriched = [], []
    for endpoint in imported:
        current = by_signature.get(endpoint.signature)
        if current is None:
            by_signature[endpoint.signature] = endpoint
            added.append(endpoint.signature)
            continue
        merged = current.model_copy(update={
            "auth_required": endpoint.auth_required,
            "expected_public": endpoint.expected_public,
            "object_id_params": sorted({*current.object_id_params, *endpoint.object_id_params}),
            "url_fields": sorted({*current.url_fields, *endpoint.url_fields}),
            "writes_properties": current.writes_properties or endpoint.writes_properties,
            "query_params": sorted({*current.query_params, *endpoint.query_params}),
            "body_fields": sorted({*current.body_fields, *endpoint.body_fields}),
        })
        if merged != current:
            enriched.append(endpoint.signature)
        by_signature[endpoint.signature] = merged
    return list(by_signature.values()), {"added": added, "enriched": enriched}
