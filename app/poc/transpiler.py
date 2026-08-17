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
import copy
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
_MAX_UNROLL = 25  # cap on iterations unrolled from a literal for-loop


class _Unresolved:
    def __repr__(self) -> str:
        return "<unresolved>"


_UNRESOLVED = _Unresolved()  # distinct from a real Python `None` literal value


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
    """Parse (not execute) a Python PoC and extract HTTP requests.

    Nested blocks are followed in source order, tracking simple local state
    (assignments, dict mutation via subscript, an `if` whose test is fully
    literal) and unrolling a `for` loop over a literal tuple/list, so a PoC
    that assembles a request body across a branch or a small parametrized
    loop still yields one test case per real request instead of collapsing
    them into a single unresolved one. This is still pure literal
    evaluation — nothing here calls into the PoC's own code.
    """
    result = TranspileResult()
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        result.unsupported.append(f"syntax error: {exc}")
        return result

    tree.body = _unroll_block(tree.body)
    _walk_block(tree.body, {}, result)
    return result


# -- static traversal of the parse tree (still zero real execution) ----------


def _walk_block(stmts: list, symbols: dict, result: TranspileResult) -> None:
    for stmt in stmts:
        _walk_stmt(stmt, symbols, result)


def _walk_stmt(stmt, symbols: dict, result: TranspileResult) -> None:
    if isinstance(stmt, ast.Assign):
        _apply_assign(stmt, symbols)
        _scan_calls(stmt.value, symbols, result)
    elif isinstance(stmt, ast.Expr):
        _scan_calls(stmt.value, symbols, result)
    elif isinstance(stmt, ast.If):
        # The test expression itself can hide a dangerous call
        # (`if os.system("...") == 0:`) — evaluating it for its literal truth
        # value (below) does not scan it for Call nodes, so that must happen
        # unconditionally, not just when the branch turns out reachable.
        _scan_calls(stmt.test, symbols, result)
        outcome = _eval_bool(stmt.test, symbols)
        if outcome is True:
            _walk_block(stmt.body, symbols, result)
        elif outcome is False:
            _walk_block(stmt.orelse, symbols, result)
        else:
            # Can't decide statically — follow both branches, each against its
            # own copy of the symbol table so one branch's assignments don't
            # leak into the other's requests.
            _walk_block(stmt.body, dict(symbols), result)
            _walk_block(stmt.orelse, dict(symbols), result)
    elif isinstance(stmt, ast.While):
        _scan_calls(stmt.test, symbols, result)
        # Reaches here only when _unroll_block couldn't unroll it (dynamic
        # condition) — best-effort single pass.
        _walk_block(stmt.body, dict(symbols), result)
        _walk_block(stmt.orelse, dict(symbols), result)
    elif isinstance(stmt, ast.For):
        # `for x in os.popen("..."):` hides the dangerous call in the
        # iterable expression, not the loop body.
        _scan_calls(stmt.iter, symbols, result)
        # Reaches here only when _unroll_block couldn't unroll it (dynamic
        # iterable) — best-effort single pass, loop var unresolved.
        _walk_block(stmt.body, dict(symbols), result)
        _walk_block(stmt.orelse, dict(symbols), result)
    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        # `with os.popen("...") as f:` hides the dangerous call in the
        # context-manager expression, not the body.
        for item in stmt.items:
            _scan_calls(item.context_expr, symbols, result)
        _walk_block(stmt.body, symbols, result)
    elif isinstance(stmt, ast.Try):
        _walk_block(stmt.body, dict(symbols), result)
        for handler in stmt.handlers:
            if handler.type is not None:
                _scan_calls(handler.type, symbols, result)
            _walk_block(handler.body, dict(symbols), result)
        _walk_block(stmt.orelse, dict(symbols), result)
        _walk_block(stmt.finalbody, dict(symbols), result)
    elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        _walk_block(stmt.body, dict(symbols), result)
    else:
        _scan_calls(stmt, symbols, result)


def _scan_calls(node, symbols: dict, result: TranspileResult) -> None:
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Call):
            continue
        func = sub.func

        # Flag dangerous calls (os.system, subprocess.run, eval, ...) — for the
        # reviewer's awareness. They are NEVER executed; we only read the tree.
        # Compared lowercased: subprocess.Popen (capital P) is exactly as
        # dangerous as os.popen and must not slip past a case-sensitive check.
        name = _call_name(func)
        if name.lower() in _DANGEROUS_CALLS:
            result.dangerous_constructs.append(name)
            continue

        # requests.get(...) / httpx.post(...) / session.delete(...)
        if isinstance(func, ast.Attribute) and func.attr.lower() in _HTTP_METHODS:
            req = _extract_http_call(func.attr.lower(), sub, symbols)
            if req:
                result.requests.append(req)


def _apply_assign(stmt: ast.Assign, symbols: dict) -> None:
    value = _literal(stmt.value, symbols)
    for target in stmt.targets:
        if isinstance(target, ast.Name):
            symbols[target.id] = value
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            # `some_dict["key"] = value` — update our tracked copy so a body
            # built up across several statements still resolves later.
            base = symbols.get(target.value.id)
            if isinstance(base, dict):
                key = _literal(target.slice, symbols)
                if key is not _UNRESOLVED:
                    updated = dict(base)
                    updated[key] = value
                    symbols[target.value.id] = updated


def _eval_bool(node, symbols: dict) -> bool | None:
    """Best-effort static truth value of an `if` test. True/False only when
    fully literal; None (undecidable) otherwise, so the caller follows both
    branches rather than guess."""
    if isinstance(node, ast.Compare) and len(node.ops) == 1 and len(node.comparators) == 1:
        left = _literal(node.left, symbols)
        right = _literal(node.comparators[0], symbols)
        if left is _UNRESOLVED or right is _UNRESOLVED:
            return None
        op = node.ops[0]
        if isinstance(op, ast.Is):
            return left is right
        if isinstance(op, ast.IsNot):
            return left is not right
        if isinstance(op, ast.Eq):
            return left == right
        if isinstance(op, ast.NotEq):
            return left != right
    return None


# -- unrolling `for x in (literal, tuple):` into repeated, substituted stmts --


class _NameSubstituter(ast.NodeTransformer):
    def __init__(self, name: str, value: object) -> None:
        self._name = name
        self._value = value

    def visit_Name(self, node: ast.Name):
        if node.id == self._name and isinstance(node.ctx, ast.Load):
            return ast.copy_location(ast.Constant(value=self._value), node)
        return node


def _unroll_block(stmts: list) -> list:
    out = []
    for stmt in stmts:
        out.extend(_unroll_stmt(stmt))
    return out


def _unroll_stmt(stmt) -> list:
    for field_name in ("body", "orelse", "finalbody"):
        if hasattr(stmt, field_name):
            setattr(stmt, field_name, _unroll_block(getattr(stmt, field_name)))
    if hasattr(stmt, "handlers"):
        for handler in stmt.handlers:
            handler.body = _unroll_block(handler.body)

    if (
        isinstance(stmt, ast.For)
        and isinstance(stmt.target, ast.Name)
        and isinstance(stmt.iter, (ast.Tuple, ast.List))
    ):
        try:
            items = ast.literal_eval(stmt.iter)
        except (ValueError, SyntaxError, TypeError):
            return [stmt]
        if len(items) > _MAX_UNROLL:
            return [stmt]
        unrolled = []
        for item in items:
            substituter = _NameSubstituter(stmt.target.id, item)
            for body_stmt in stmt.body:
                unrolled.append(substituter.visit(copy.deepcopy(body_stmt)))
        return unrolled
    return [stmt]


def _call_name(func) -> str:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _extract_http_call(method: str, node: ast.Call, symbols: dict) -> ExtractedRequest | None:
    url = _literal(node.args[0], symbols) if node.args else _UNRESOLVED
    headers: dict[str, str] = {}
    body: object | None = None

    for kw in node.keywords:
        if kw.arg == "url":
            url = _literal(kw.value, symbols)
        elif kw.arg == "headers":
            h = _literal(kw.value, symbols)
            if isinstance(h, dict):
                headers = h
        elif kw.arg in ("json", "data"):
            b = _literal(kw.value, symbols)
            body = None if b is _UNRESOLVED else b

    if not isinstance(url, str):
        return None
    return ExtractedRequest(method=method.upper(), url=url,
                            headers=headers if isinstance(headers, dict) else {}, body=body)


def _literal(node, symbols: dict | None = None):
    """Best-effort static value extraction. Only literals + known local
    symbols + '+' concatenation + simple f-strings; anything else returns
    `_UNRESOLVED` rather than executing. Nothing here evaluates code."""
    symbols = symbols or {}
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError, TypeError):
        pass

    if isinstance(node, ast.Name):
        return symbols.get(node.id, _UNRESOLVED)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        left = _literal(node.left, symbols)
        right = _literal(node.right, symbols)
        if left is _UNRESOLVED and right is _UNRESOLVED:
            return _UNRESOLVED
        if isinstance(left, str) or isinstance(right, str):
            left_s = "" if left is _UNRESOLVED else left
            right_s = "" if right is _UNRESOLVED else right
            return f"{left_s}{right_s}"
        return _UNRESOLVED
    if isinstance(node, ast.JoinedStr):
        parts = []
        for v in node.values:
            if isinstance(v, ast.Constant):
                parts.append(str(v.value))
            elif isinstance(v, ast.FormattedValue):
                parts.append("{" + _fmt_name(v.value) + "}")
        return "".join(parts)
    return _UNRESOLVED


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
