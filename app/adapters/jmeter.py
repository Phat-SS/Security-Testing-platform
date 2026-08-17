"""JMeter test plan (.jmx) → declarative TestCases.

A .jmx is XML; HTTP calls live in <HTTPSamplerProxy> elements with named
properties (HTTPSampler.domain / .path / .method / .port / .protocol) and an
optional header manager. We extract those into ExtractedRequests. Host is
stripped downstream; scope is enforced at run time.
"""

from __future__ import annotations

from xml.etree.ElementTree import Element, ParseError

from defusedxml.ElementTree import fromstring
from defusedxml.common import DefusedXmlException

from app.poc.transpiler import ExtractedRequest, TranspileResult, to_test_cases

__all__ = ["transpile_jmeter", "jmeter_to_test_cases"]


def transpile_jmeter(xml_text: str) -> TranspileResult:
    result = TranspileResult()
    try:
        root = fromstring(xml_text)
    except ParseError as exc:
        result.unsupported.append(f"invalid JMeter XML: {exc}")
        return result
    except DefusedXmlException as exc:
        result.unsupported.append(f"rejected JMeter XML (unsafe entity construct): {exc}")
        return result

    for sampler in root.iter("HTTPSamplerProxy"):
        req = _extract_sampler(sampler)
        if req:
            result.requests.append(req)

    if not result.requests:
        result.unsupported.append("no HTTP samplers found in JMeter plan")
    return result


def jmeter_to_test_cases(xml_text: str, **kwargs):
    return to_test_cases(transpile_jmeter(xml_text), **kwargs)


def _prop(el: Element, name: str) -> str:
    for p in el.findall("stringProp"):
        if p.get("name") == name:
            return (p.text or "").strip()
    return ""


def _extract_sampler(sampler: Element) -> ExtractedRequest | None:
    domain = _prop(sampler, "HTTPSampler.domain")
    path = _prop(sampler, "HTTPSampler.path") or "/"
    method = (_prop(sampler, "HTTPSampler.method") or "GET").upper()
    protocol = _prop(sampler, "HTTPSampler.protocol") or "https"
    port = _prop(sampler, "HTTPSampler.port")

    if not path:
        return None
    host = domain + (f":{port}" if port and port not in ("80", "443") else "")
    url = f"{protocol}://{host}{path}" if host else path

    # Body: a raw post body sampler stores it as an Argument with empty name.
    body = None
    for coll in sampler.iter("elementProp"):
        for arg in coll.iter("stringProp"):
            if arg.get("name") == "Argument.value" and (arg.text or "").strip():
                body = arg.text.strip()
                break
        if body:
            break

    return ExtractedRequest(method=method, url=url, headers={}, body=body)
