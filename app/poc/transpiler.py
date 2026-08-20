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

from app.schemas.enums import ApprovalStatus, OwaspApiCategory, TestSource
from app.schemas.testcase import DESTRUCTIVE_METHODS, AuthContext, Mutation, RequestSpec, TestCase

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}
_DANGEROUS_CALLS = {"system", "popen", "eval", "exec", "compile", "spawn", "call", "run", "check_output"}
_MAX_UNROLL = 25  # cap on iterations unrolled from a literal for-loop
_MAX_CALL_DEPTH = 6  # cap on nested helper-function inlining


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
class _UrllibRequestMarker:
    """What `urllib.request.Request(...)` built, tracked in `symbols` under
    whatever name it was assigned to so a later `urlopen(that_name)` can
    resolve it — the same "track it, resolve later" approach already used for
    dict-building assignments (`_apply_assign`)."""

    method: str
    url: object  # str once resolved, else _UNRESOLVED
    headers: dict
    body: object


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

    A call to a PoC-defined helper function (`def send(method, path, body):
    ...`, called elsewhere as `send("PUT", "/x", body)`) is likewise inlined
    by statically binding the call's literal arguments to the function's
    parameter names — the same kind of substitution the for-loop unroller
    already does, never a real call into the PoC's code. See `_inline_call`.
    """
    result = TranspileResult()
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        result.unsupported.append(f"syntax error: {exc}")
        return result

    tree.body = _unroll_block(tree.body)
    ctx = _Ctx(result=result, functions=_collect_functions(tree.body))
    _walk_block(tree.body, {}, ctx, frozenset())
    return result


@dataclass
class _Ctx:
    result: TranspileResult
    functions: dict  # name -> ast.FunctionDef/AsyncFunctionDef


# -- static traversal of the parse tree (still zero real execution) ----------


def _walk_block(stmts: list, symbols: dict, ctx: _Ctx, in_progress: frozenset) -> None:
    for stmt in stmts:
        _walk_stmt(stmt, symbols, ctx, in_progress)


def _walk_stmt(stmt, symbols: dict, ctx: _Ctx, in_progress: frozenset) -> None:
    if isinstance(stmt, ast.Assign):
        _apply_assign(stmt, symbols)
        _scan_calls(stmt.value, symbols, ctx, in_progress)
    elif isinstance(stmt, ast.Expr):
        _apply_dict_update(stmt.value, symbols)
        _scan_calls(stmt.value, symbols, ctx, in_progress)
    elif isinstance(stmt, ast.If):
        # The test expression itself can hide a dangerous call
        # (`if os.system("...") == 0:`) — evaluating it for its literal truth
        # value (below) does not scan it for Call nodes, so that must happen
        # unconditionally, not just when the branch turns out reachable.
        _scan_calls(stmt.test, symbols, ctx, in_progress)
        outcome = _eval_bool(stmt.test, symbols)
        if outcome is True:
            _walk_block(stmt.body, symbols, ctx, in_progress)
        elif outcome is False:
            _walk_block(stmt.orelse, symbols, ctx, in_progress)
        else:
            # Can't decide statically — follow both branches, each against its
            # own copy of the symbol table so one branch's assignments don't
            # leak into the other's requests.
            _walk_block(stmt.body, dict(symbols), ctx, in_progress)
            _walk_block(stmt.orelse, dict(symbols), ctx, in_progress)
    elif isinstance(stmt, ast.While):
        _scan_calls(stmt.test, symbols, ctx, in_progress)
        # Reaches here only when _unroll_block couldn't unroll it (dynamic
        # condition) — best-effort single pass.
        _walk_block(stmt.body, dict(symbols), ctx, in_progress)
        _walk_block(stmt.orelse, dict(symbols), ctx, in_progress)
    elif isinstance(stmt, ast.For):
        # `for x in os.popen("..."):` hides the dangerous call in the
        # iterable expression, not the loop body.
        _scan_calls(stmt.iter, symbols, ctx, in_progress)
        # Reaches here only when _unroll_block couldn't unroll it (dynamic
        # iterable) — best-effort single pass, loop var unresolved.
        _walk_block(stmt.body, dict(symbols), ctx, in_progress)
        _walk_block(stmt.orelse, dict(symbols), ctx, in_progress)
    elif isinstance(stmt, (ast.With, ast.AsyncWith)):
        # `with os.popen("...") as f:` hides the dangerous call in the
        # context-manager expression, not the body.
        for item in stmt.items:
            _scan_calls(item.context_expr, symbols, ctx, in_progress)
        _walk_block(stmt.body, symbols, ctx, in_progress)
    elif isinstance(stmt, ast.Try):
        _walk_block(stmt.body, dict(symbols), ctx, in_progress)
        for handler in stmt.handlers:
            if handler.type is not None:
                _scan_calls(handler.type, symbols, ctx, in_progress)
            _walk_block(handler.body, dict(symbols), ctx, in_progress)
        _walk_block(stmt.orelse, dict(symbols), ctx, in_progress)
        _walk_block(stmt.finalbody, dict(symbols), ctx, in_progress)
    elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
        # Never walked here for request extraction: with unbound parameters
        # (method/path/body-shaped names) that would resolve to _UNRESOLVED
        # and extract nothing — but a zero-argument helper would extract
        # successfully here AND AGAIN at its call site, double-counting one
        # real request as two. Requests come only from a call site with
        # arguments bound (_inline_call, via _scan_calls below). Dangerous
        # constructs are still flagged unconditionally, called or not — a
        # reviewer needs to know that code exists regardless of whether the
        # flow that reaches it is exercised.
        _flag_dangerous_only(stmt.body, ctx.result)
    else:
        _scan_calls(stmt, symbols, ctx, in_progress)


def _scan_calls(node, symbols: dict, ctx: _Ctx, in_progress: frozenset) -> None:
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
            ctx.result.dangerous_constructs.append(name)
            continue

        # requests.get(...) / httpx.post(...) / session.delete(...)
        if isinstance(func, ast.Attribute) and func.attr.lower() in _HTTP_METHODS:
            req = _extract_http_call(func.attr.lower(), sub, symbols)
            if req:
                ctx.result.requests.append(req)
            else:
                ctx.result.unsupported.append(
                    f"unresolved {func.attr}(...) call at line {getattr(sub, 'lineno', '?')}")
            continue

        # requests.request(method, url, ...) / session.request(method=..., url=...)
        # — same shape as .get/.post/... but with the verb passed as an argument
        # instead of baked into the attribute name, so it needs its own extractor.
        if isinstance(func, ast.Attribute) and func.attr.lower() == "request":
            req = _extract_generic_request_call(sub, symbols)
            if req:
                ctx.result.requests.append(req)
            else:
                ctx.result.unsupported.append(
                    f"unresolved request(...) call at line {getattr(sub, 'lineno', '?')}")
            continue

        # urllib.request.urlopen(...) — either a bare URL, an inline
        # Request(...), or a variable holding one tracked in `symbols`.
        if name == "urlopen":
            req = _extract_urlopen_call(sub, symbols)
            if req:
                ctx.result.requests.append(req)
            else:
                ctx.result.unsupported.append(
                    f"unresolved urlopen(...) call at line {getattr(sub, 'lineno', '?')}")
            continue

        # A call to a PoC-defined helper — inline it with this call site's
        # own literal arguments bound to the function's parameters. Guarded
        # against cycles (in_progress) and unbounded nesting (_MAX_CALL_DEPTH);
        # both degrade to "no extra requests from this branch", never a hang.
        if (name in ctx.functions and name not in in_progress
                and len(in_progress) < _MAX_CALL_DEPTH):
            _inline_call(sub, name, symbols, ctx, in_progress)


def _flag_dangerous_only(stmts: list, result: TranspileResult) -> None:
    """Scan a function body for dangerous constructs without attempting any
    symbol resolution or request extraction — used for a FunctionDef's body,
    which only ever gets *walked* (for requests) at an inlined call site, but
    must be scanned for dangerous calls unconditionally, called or not."""
    for stmt in stmts:
        for node in ast.walk(stmt):
            if not isinstance(node, ast.Call):
                continue
            name = _call_name(node.func)
            if name.lower() in _DANGEROUS_CALLS:
                result.dangerous_constructs.append(name)


def _collect_functions(stmts: list) -> dict:
    """Top-level (module-scope) function definitions by name, recursing
    through if/try/with the same way `_unroll_block` does — but never into a
    function's own body, so a helper nested inside another isn't mistaken for
    one callable from outside it."""
    functions: dict = {}
    for stmt in stmts:
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
            functions[stmt.name] = stmt
            continue
        for field_name in ("body", "orelse", "finalbody"):
            if hasattr(stmt, field_name):
                functions.update(_collect_functions(getattr(stmt, field_name)))
        if hasattr(stmt, "handlers"):
            for handler in stmt.handlers:
                functions.update(_collect_functions(handler.body))
    return functions


def _bind_arguments(args: ast.arguments, call: ast.Call, symbols: dict) -> dict | None:
    """Static positional/keyword argument binding for an inlined call.

    Plain positional-or-keyword parameters, plus a trailing `**kwargs`
    catch-all (a common shape for a PoC's own "send with overrides" helper):
    any keyword at the call site that doesn't match a named parameter is
    collected into a dict bound to the `**kwargs` name, so a body that does
    `overrides_dict.update(kwargs_name)` (see `_apply_dict_update`) still
    resolves. `*args`/positional-only/keyword-only parameters, a `**spread`
    at the call site, or a required parameter the call site never supplies,
    still return None — the caller skips the inline entirely rather than
    guessing at a binding that might be wrong.
    """
    if args.vararg or args.posonlyargs or args.kwonlyargs:
        return None
    params = [a.arg for a in args.args]
    if len(call.args) > len(params):
        return None

    bound: dict = {}
    extra_kwargs: dict = {}
    for param, arg_node in zip(params, call.args):
        bound[param] = _literal(arg_node, symbols)
    for kw in call.keywords:
        if kw.arg is None:  # **spread at the call site — can't resolve generically
            return None
        if kw.arg in params:
            bound[kw.arg] = _literal(kw.value, symbols)
        elif args.kwarg:
            extra_kwargs[kw.arg] = _literal(kw.value, symbols)
        else:
            return None  # unknown keyword and no **kwargs to catch it

    n_defaults = len(args.defaults)
    default_for = dict(zip(params[len(params) - n_defaults:], args.defaults)) if n_defaults else {}
    for param in params:
        if param in bound:
            continue
        if param in default_for:
            bound[param] = _literal(default_for[param], symbols)
        else:
            return None  # required parameter never supplied

    if args.kwarg:
        bound[args.kwarg.arg] = extra_kwargs
    return bound


def _apply_dict_update(node, symbols: dict) -> None:
    """`some_dict.update(other)` — merge into our tracked copy, same spirit as
    `_apply_assign`'s subscript-assignment tracking. Needed for the common
    `body.update(overrides)` pattern where `overrides` is a `**kwargs` dict
    bound by `_bind_arguments`."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "update" and isinstance(node.func.value, ast.Name)):
        return
    if len(node.args) != 1 or node.keywords:
        return
    base = symbols.get(node.func.value.id)
    if not isinstance(base, dict):
        return
    other = _literal(node.args[0], symbols)
    if isinstance(other, dict):
        symbols[node.func.value.id] = {**base, **other}


def _inline_call(call: ast.Call, name: str, symbols: dict, ctx: _Ctx, in_progress: frozenset) -> None:
    bound = _bind_arguments(ctx.functions[name].args, call, symbols)
    if bound is None:
        ctx.result.unsupported.append(
            f"could not inline helper '{name}(...)' call at line {getattr(call, 'lineno', '?')}")
        return
    inner_symbols = {**symbols, **bound}
    _walk_block(ctx.functions[name].body, inner_symbols, ctx, in_progress | {name})


def _apply_assign(stmt: ast.Assign, symbols: dict) -> None:
    if isinstance(stmt.value, ast.Call) and _call_name(stmt.value.func) == "Request":
        # `req = urllib.request.Request(...)` — tracked as a marker, not a
        # plain literal, so a later `urlopen(req)` can resolve it.
        value = _build_request_marker(stmt.value, symbols)
    else:
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


def _extract_generic_request_call(node: ast.Call, symbols: dict) -> ExtractedRequest | None:
    """`requests.request(method, url, ...)` / `session.request(method=..., url=...)`
    — same shape as `requests.get/post/...` but the verb is passed as an
    argument instead of baked into the attribute name, so method/url come
    from the first two positional args (or `method=`/`url=` keywords) rather
    than a fixed position."""
    positional = list(node.args)
    method = _literal(positional.pop(0), symbols) if positional else _UNRESOLVED
    url = _literal(positional.pop(0), symbols) if positional else _UNRESOLVED
    headers: dict[str, str] = {}
    body: object | None = None

    for kw in node.keywords:
        if kw.arg == "method":
            method = _literal(kw.value, symbols)
        elif kw.arg == "url":
            url = _literal(kw.value, symbols)
        elif kw.arg == "headers":
            h = _literal(kw.value, symbols)
            if isinstance(h, dict):
                headers = h
        elif kw.arg in ("json", "data"):
            b = _literal(kw.value, symbols)
            body = None if b is _UNRESOLVED else b

    if not isinstance(method, str) or not isinstance(url, str):
        return None
    return ExtractedRequest(method=method.upper(), url=url,
                            headers=headers if isinstance(headers, dict) else {}, body=body)


def _build_request_marker(call: ast.Call, symbols: dict) -> _UrllibRequestMarker:
    """`urllib.request.Request(url, data=..., headers=..., method=...)`.

    `method` defaults the same way the real class does: unset with no `data`
    is GET; unset with `data` is POST. An explicit `method=` always wins.
    """
    url = _literal(call.args[0], symbols) if call.args else _UNRESOLVED
    headers: dict = {}
    body: object | None = None
    method: str | None = None

    for kw in call.keywords:
        if kw.arg == "url":
            url = _literal(kw.value, symbols)
        elif kw.arg == "headers":
            h = _literal(kw.value, symbols)
            if isinstance(h, dict):
                headers = h
        elif kw.arg == "data":
            b = _literal(kw.value, symbols)
            body = None if b is _UNRESOLVED else b
        elif kw.arg == "method":
            m = _literal(kw.value, symbols)
            if isinstance(m, str):
                method = m

    if method is None:
        method = "POST" if body is not None else "GET"
    return _UrllibRequestMarker(method=method.upper(), url=url,
                                headers=headers if isinstance(headers, dict) else {}, body=body)


def _extract_urlopen_call(call: ast.Call, symbols: dict) -> ExtractedRequest | None:
    """`urllib.request.urlopen(x, ...)` — `x` is a `Request(...)` built
    inline, a variable holding one (tracked in `symbols` by `_apply_assign`),
    or a bare URL string (a plain GET, same as `Request` with no method)."""
    if not call.args:
        return None
    target = call.args[0]

    if isinstance(target, ast.Call) and _call_name(target.func) == "Request":
        marker = _build_request_marker(target, symbols)
    elif isinstance(target, ast.Name):
        candidate = symbols.get(target.id, _UNRESOLVED)
        if isinstance(candidate, _UrllibRequestMarker):
            marker = candidate
        elif isinstance(candidate, str):
            marker = _UrllibRequestMarker(method="GET", url=candidate, headers={}, body=None)
        else:
            return None
    else:
        url = _literal(target, symbols)
        if not isinstance(url, str):
            return None
        marker = _UrllibRequestMarker(method="GET", url=url, headers={}, body=None)

    if not isinstance(marker.url, str):
        return None
    return ExtractedRequest(method=marker.method, url=marker.url,
                            headers=marker.headers if isinstance(marker.headers, dict) else {},
                            body=marker.body)


def _literal(node, symbols: dict | None = None):
    """Best-effort static value extraction. Only literals + known local
    symbols + '+' concatenation + simple f-strings + a couple of
    value-preserving call shapes (`x.encode()`, `json.dumps(x)`); anything
    else returns `_UNRESOLVED` rather than executing. Nothing here evaluates
    code — these are AST shape matches, not real calls."""
    symbols = symbols or {}
    try:
        return ast.literal_eval(node)
    except (ValueError, SyntaxError, TypeError):
        pass

    if isinstance(node, ast.Name):
        return symbols.get(node.id, _UNRESOLVED)
    if isinstance(node, ast.Dict):
        # Values referencing a known symbol (`{"User-Agent": UA}`) aren't
        # `ast.literal_eval`-able at all — resolve what we can, key by key,
        # and drop only the individual pairs that don't resolve rather than
        # discarding the whole dict.
        out = {}
        for k, v in zip(node.keys, node.values):
            if k is None:  # a `**spread` entry — not resolvable generically
                continue
            key, val = _literal(k, symbols), _literal(v, symbols)
            if key is not _UNRESOLVED and val is not _UNRESOLVED:
                out[key] = val
        return out
    if isinstance(node, ast.IfExp):
        # `X if TEST else Y` — reuse the same literal-truth evaluator the
        # `if` STATEMENT walker already uses; only decide when TEST is fully
        # literal, same "unresolved rather than guessed" discipline.
        outcome = _eval_bool(node.test, symbols)
        if outcome is True:
            return _literal(node.body, symbols)
        if outcome is False:
            return _literal(node.orelse, symbols)
        return _UNRESOLVED
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
                # A known symbol (e.g. a literal id bound earlier in the same
                # PoC) resolves to its real value; only a genuinely unknown
                # one falls back to a `{name}` template placeholder for the
                # runner's own resolve() to fill in at execution time.
                resolved = _literal(v.value, symbols)
                parts.append(str(resolved) if resolved is not _UNRESOLVED
                             else "{" + _fmt_name(v.value) + "}")
        return "".join(parts)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        # `<expr>.encode(...)` / `<expr>.decode(...)`: byte/text encoding is
        # value-preserving for our purposes — unwrap to the inner value.
        # `json.dumps(x)`: recovers the original object `x` rather than its
        # JSON text, matching how `requests.post(url, json=x)` already stores
        # `x` itself as the body.
        attr = node.func.attr
        if attr in ("encode", "decode"):
            return _literal(node.func.value, symbols)
        if attr == "dumps" and node.args:
            return _literal(node.args[0], symbols)
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
    owasp_category: OwaspApiCategory | None = None,
    attacker: str = "agent_A",
    victim: str = "agent_B",
    verbatim: bool = False,
) -> list[TestCase]:
    """Wrap extracted requests as PoC-sourced test cases (PENDING approval).

    The host is stripped: the runner supplies the approved base URL, so a PoC
    that pointed at some hard-coded host cannot re-introduce an off-scope
    target. Only the path/method/body survive.

    Each request is classified by its own shape (see `app.poc.classify`) rather
    than being labelled API1/BOLA wholesale. Pass `owasp_category` to override
    when the caller genuinely knows better; leaving it None is the right choice
    for bulk imports, where a Burp export of forty assorted requests is exactly
    the case the old fixed label got wrong.

    `verbatim=True` (ticket_poc mode): the request is sent exactly as
    extracted — literal path (never `classify()`'s `{victim_id}`-parameterised
    rewrite, which needs a mutation to fill it back in), original body
    untouched (never `classify()`'s guessed mutation, e.g. `inject_property`
    injecting `role`/`is_admin` into it), and no verification read-back
    (classify()'s verification step proves *its own* mutation's effect, which
    never runs here). `classify()` still runs and still supplies the
    category/severity/expected/reason used for labelling and coverage — only
    the request actually sent, and the mutation recorded against it, change.
    A ticket's embedded PoC is already a complete, working exploit; the point
    is to reproduce exactly what it proved, not attack it a second time with a
    generic mutation guessed from its shape.
    """
    from app.poc.classify import classify

    tests: list[TestCase] = []
    counters: dict[str, int] = {}
    for req in result.requests:
        path = _relative(req.path)
        headers = {k: v for k, v in req.headers.items() if k.lower() != "host"}
        verdict = classify(req.method, path, headers, req.body)

        category = owasp_category or verdict.category
        cat_num = category.value.split(":")[0]
        counters[cat_num] = counters.get(cat_num, 0) + 1
        # A parameterised path is what makes an id substitutable at all: a
        # recorded request contains a literal id, and there is nothing to
        # replace in a literal. Not for verbatim mode: nothing resolves the
        # placeholder back, since no mutation runs to fill it in.
        effective_path = path if verbatim else (verdict.parameterised_path or path)

        objective = (
            f"Replay of an existing PoC as a controlled, scoped test. Classified as "
            f"{cat_num} ({verdict.confidence} confidence) because {verdict.reason}."
        )
        if verbatim:
            objective += " Sent exactly as extracted — no mutation applied."
        elif verdict.confidence == "LOW":
            objective += (
                " Review this classification before approving — the platform could not "
                "infer the PoC's intent from the request alone."
            )

        tests.append(
            TestCase(
                test_id=f"POC-{cat_num}-{counters[cat_num]:03d}",
                title=f"Transpiled PoC: {req.method} {effective_path}",
                objective=objective,
                owasp_category=category,
                severity=verdict.severity,
                auth_context=AuthContext(
                    persona=attacker,
                    # Only claim a victim identity when the probe actually
                    # attacks one; a spurious target_persona makes an unrelated
                    # test look like a cross-identity check in the report.
                    # Never for verbatim mode: verbatim_replay attacks nothing.
                    target_persona=(victim if not verbatim and verdict.needs_target_persona
                                    else None),
                ),
                request=RequestSpec(method=req.method, path=effective_path,
                                    headers=headers, body=req.body),
                # detail["headers"] is what makes this a true no-op: the
                # runner otherwise merges the attacker persona's own
                # auth_headers into every request before any mutation runs,
                # which would silently hand a credential to a request the PoC
                # proved needs none. verbatim_replay's handler forces the
                # wire headers back to exactly this dict.
                attack_mutation=(Mutation(kind="verbatim_replay", detail={"headers": headers})
                                if verbatim else verdict.mutation),
                verification=None if verbatim else verdict.verification,
                expected=verdict.expected,
                # A recorded request is not a positive control: we do not know
                # which identity recorded it, so we cannot assert who is
                # entitled to it. The tester adds a baseline when approving.
                source=TestSource.POC,
                approval_status=ApprovalStatus.PENDING,
                # Classified by method, same rule test_designer/attack_planner
                # use — never by whether this particular id looks safe. A PoC
                # deliberately aimed at a non-existent id (so replaying it
                # touches nothing real) is still a PUT/POST/PATCH/DELETE by
                # shape, and the destructive-confirmation gate exists for the
                # method, not for what today's target happens to contain.
                is_destructive=req.method.upper() in DESTRUCTIVE_METHODS,
            )
        )
    return tests


def _relative(path: str) -> str:
    return path if path.startswith("/") else f"/{path}"
