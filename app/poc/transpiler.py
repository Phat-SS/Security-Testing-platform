"""PoC transpiler — turn an untrusted PoC into a declarative TestCase.

This is the heart of the "never execute untrusted code" principle. A PoC file
is treated as *text to analyze*, never as code to run:

  * Python PoCs are parsed with `ast.parse` (which does NOT execute anything)
    and we walk the tree for `requests`/`httpx` calls, pulling out method, URL,
    headers and body.
  * cURL commands are tokenized.

The result is a RequestSpec / TestCase that the trusted runner can execute. If
the PoC contains `os.system`, `eval`, `subprocess`, a network call to an
off-scope host, etc., that code is simply never run — at worst it is reported as
an unsupported construct. Static analysis also flags dangerous calls so a
reviewer sees them.
"""

from __future__ import annotations

import ast
import shlex
from dataclasses import dataclass, field
from urllib.parse import urlparse

from app.schemas.enums import ApprovalStatus, OwaspApiCategory, Severity, TestSource
from app.schemas.testcase import (
    AuthContext,
    ExpectedResult,
    Mutation,
    RequestSpec,
    TestCase,
)

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_DANGEROUS_CALLS = {"system", "popen", "eval", "exec", "compile", "spawn", "call", "run", "check_output"}


@dataclass
class ExtractedRequest:
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: object | None = None

    @property
    def host(self) -> str:
        return urlparse(self.url).hostname or ""

    @property
    def path(self) -> str:
        p = urlparse(self.url)
        return p.path + (f"?{p.query}" if p.query else "")


@dataclass
class TranspileResult:
    requests: list[ExtractedRequest] = field(default_factory=list)
    dangerous_constructs: list[str] = field(default_factory=list)  # flagged, never run
    unsupported: list[str] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        return not self.dangerous_constructs


# -- Python ------------------------------------------------------------------


def transpile_python(source: str) -> TranspileResult:
    """Parse (not execute) a Python PoC and extract HTTP requests."""
    result = TranspileResult()
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        result.unsupported.append(f"syntax error: {exc}")
        return result

    # Pre-pass: collect simple module-level `NAME = "literal"` assignments so
    # `BASE + "/customers/2002"` style URLs resolve. Still pure parsing.
    symbols = _collect_string_symbols(tree)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func

        # Flag dangerous calls (os.system, subprocess.run, eval, ...) — for the
        # reviewer's awareness. They are NEVER executed; we only read the tree.
        name = _call_name(func)
        if name in _DANGEROUS_CALLS:
            result.dangerous_constructs.append(name)
            continue

        # requests.get(...) / httpx.post(...) / session.delete(...)
        if isinstance(func, ast.Attribute) and func.attr.lower() in _HTTP_METHODS:
            req = _extract_http_call(func.attr.lower(), node, symbols)
            if req:
                result.requests.append(req)

    return result


def _collect_string_symbols(tree: ast.Module) -> dict[str, str]:
    symbols: dict[str, str] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant):
            if isinstance(node.value.value, str):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        symbols[target.id] = node.value.value
    return symbols


def _call_name(func) -> str:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _extract_http_call(method: str, node: ast.Call, symbols: dict[str, str]) -> ExtractedRequest | None:
    url = _literal(node.args[0], symbols) if node.args else None
    headers: dict[str, str] = {}
    body: object | None = None

    for kw in node.keywords:
        if kw.arg == "url":
            url = _literal(kw.value, symbols)
        elif kw.arg == "headers":
            headers = _literal(kw.value, symbols) or {}
        elif kw.arg in ("json", "data"):
            body = _literal(kw.value, symbols)

    if not isinstance(url, str):
        return None
    return ExtractedRequest(method=method.upper(), url=url,
                            headers=headers if isinstance(headers, dict) else {}, body=body)


def _literal(node, symbols: dict[str, str] | None = None):
    """Best-effort static value extraction. Only literals + known string
    symbols + '+' concatenation + simple f-strings; anything else returns None
    rather than executing. Nothing here evaluates code."""
    symbols = symbols or {}
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError, TypeError):
        pass

    if isinstance(node, ast.Name):
        return symbols.get(node.id)  # None if unknown → safe
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal(node.left, symbols)
        right = _literal(node.right, symbols)
        if isinstance(left, str) or isinstance(right, str):
            return f"{left or ''}{right or ''}"
        return None
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(str(v.value))
            elif isinstance(v, ast.FormattedValue):
                parts.append("{" + _fmt_name(v.value) + "}")
        return "".join(parts)
    return None


def _fmt_name(node) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return "var"


# -- cURL --------------------------------------------------------------------


def transpile_curl(command: str) -> TranspileResult:
    result = TranspileResult()
    try:
        tokens = shlex.split(command.replace("\\\n", " "))
    except ValueError as exc:
        result.unsupported.append(f"could not tokenize curl: {exc}")
        return result

    method = "GET"
    url = None
    headers: dict[str, str] = {}
    body = None
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("-X", "--request") and i + 1 < len(tokens):
            method = tokens[i + 1].upper()
            i += 2
        elif tok in ("-H", "--header") and i + 1 < len(tokens):
            k, _, v = tokens[i + 1].partition(":")
            headers[k.strip()] = v.strip()
            i += 2
        elif tok in ("-d", "--data", "--data-raw") and i + 1 < len(tokens):
            body = tokens[i + 1]
            if method == "GET":
                method = "POST"
            i += 2
        elif tok == "curl":
            i += 1
        elif tok.startswith("http"):
            url = tok
            i += 1
        else:
            i += 1

    if url:
        result.requests.append(ExtractedRequest(method, url, headers, body))
    else:
        result.unsupported.append("no URL found in curl command")
    return result


# -- PoC → TestCase ----------------------------------------------------------


def to_test_cases(
    result: TranspileResult,
    owasp_category: OwaspApiCategory = OwaspApiCategory.API1,
    attacker: str = "agent_A",
    victim: str = "agent_B",
) -> list[TestCase]:
    """Wrap extracted requests as PoC-sourced test cases (PENDING approval).

    The host is stripped: the runner supplies the approved base URL, so a PoC
    that pointed at some hard-coded host cannot re-introduce an off-scope
    target. Only the path/method/body survive.
    """
    tests: list[TestCase] = []
    for i, req in enumerate(result.requests, start=1):
        cat_num = owasp_category.value.split(":")[0]
        tests.append(
            TestCase(
                test_id=f"POC-{cat_num}-{i:03d}",
                title=f"Transpiled PoC: {req.method} {req.path}",
                objective="Replay of an existing PoC as a controlled, scoped test.",
                owasp_category=owasp_category,
                severity=Severity.MEDIUM,
                auth_context=AuthContext(persona=attacker, target_persona=victim),
                request=RequestSpec(method=req.method, path=_relative(req.path),
                                    headers={k: v for k, v in req.headers.items()
                                             if k.lower() != "host"},
                                    body=req.body),
                attack_mutation=Mutation(kind="swap_object_id", detail={}),
                expected=ExpectedResult(status_in=[403, 404]),
                source=TestSource.POC,
                approval_status=ApprovalStatus.PENDING,
            )
        )
    return tests


def _relative(path: str) -> str:
    return path if path.startswith("/") else f"/{path}"
