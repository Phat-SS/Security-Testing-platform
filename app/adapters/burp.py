"""Burp Suite XML export → declarative TestCases.

Burp's "Save items" produces an XML file where each <item> holds a base64- (or
plain-) encoded raw HTTP request/response. We parse the raw request text into
method/path/headers/body — treating it strictly as data — and reuse the same
`to_test_cases` path (host stripped, scope enforced at run time).
"""

from __future__ import annotations

import base64
from xml.etree.ElementTree import ParseError

from defusedxml.ElementTree import fromstring
from defusedxml.common import DefusedXmlException

from app.poc.transpiler import ExtractedRequest, TranspileResult, to_test_cases

__all__ = ["transpile_burp", "burp_to_test_cases", "parse_raw_http"]


def transpile_burp(xml_text: str) -> TranspileResult:
    result = TranspileResult()
    try:
        root = fromstring(xml_text)
    except ParseError as exc:
        result.unsupported.append(f"invalid Burp XML: {exc}")
        return result
    except DefusedXmlException as exc:
        result.unsupported.append(f"rejected Burp XML (unsafe entity construct): {exc}")
        return result

    for item in root.iter("item"):
        req_el = item.find("request")
        if req_el is None or not (req_el.text or "").strip():
            continue
        raw = _maybe_b64(req_el.get("base64"), req_el.text)
        host = (item.findtext("host") or "").strip()
        proto = (item.findtext("protocol") or "https").strip()
        parsed = parse_raw_http(raw, host=host, scheme=proto)
        if parsed:
            result.requests.append(parsed)

    if not result.requests:
        result.unsupported.append("no requests found in Burp export")
    return result


def burp_to_test_cases(xml_text: str, **kwargs):
    return to_test_cases(transpile_burp(xml_text), **kwargs)


def parse_raw_http(raw: str, host: str = "", scheme: str = "https") -> ExtractedRequest | None:
    """Parse a raw HTTP/1.1 request block into an ExtractedRequest."""
    raw = raw.replace("\r\n", "\n").strip("\n")
    if not raw:
        return None
    head, _, body = raw.partition("\n\n")
    lines = head.split("\n")
    request_line = lines[0].split()
    if len(request_line) < 2:
        return None
    method, target = request_line[0].upper(), request_line[1]

    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, _, v = line.partition(":")
            headers[k.strip()] = v.strip()

    host = host or headers.get("Host", "")
    # Absolute-form target already carries a URL; else build from host+path.
    if target.startswith("http"):
        url = target
    else:
        url = f"{scheme}://{host}{target}" if host else target
    return ExtractedRequest(method=method, url=url, headers=headers,
                            body=body.strip() or None)


def _maybe_b64(flag: str | None, text: str) -> str:
    if flag and flag.lower() == "true":
        try:
            return base64.b64decode(text).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001 - malformed base64 → treat as plain
            return text
    return text
