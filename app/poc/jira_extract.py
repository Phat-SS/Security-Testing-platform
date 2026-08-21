"""Pull PoC scripts out of a Jira issue — all of them, wherever they are.

Some intake workflows (an automated bounty-hunter tool, a pentester writing the
ticket by hand) attach the PoC to the ticket rather than to a person. This scans
for it so the platform can feed it straight into the existing PoC transpiler
instead of somebody copying it out of Jira by hand. Pure text parsing — nothing
here executes anything; the result is handed to `transpile_python`, which only
ever reads the AST.

**One ticket, several scripts.** That is the normal case, not the edge case: a
finding that needs an unauthenticated reach *and* a cross-tenant write is two
files, and a ticket that files one of them and drops the other has thrown away
half the report. Three things were losing scripts:

1. **Only the description was read.** A PoC posted as a follow-up comment ("here
   is the second script") was invisible. Comments are read now, and so are
   attachment bodies when the connector can supply them.
2. **Only markdown fences were recognised.** Jira Cloud's native code block is
   an ADF `codeBlock` node with no backticks anywhere in it, and its wiki markup
   is `{code:python}`. Both are recognised now; `app/mcp/adf.py` renders a
   `codeBlock` as a real fenced block on the way in so this scanner sees it.
3. **A block with no ``python`` tag was skipped.** Plenty of tickets fence the
   PoC bare. An untagged block is now kept when it actually parses as Python and
   mentions an HTTP call — a check that keeps the JSON payload blocks, log dumps
   and shell snippets that share a ticket with a PoC from being transpiled as
   one.

**Scripts stay separate.** `combined_poc_source` still exists (it is what a
textarea holds) but it is a *presentation*, and the banner it writes is
machine-readable so `split_combined_source` can take it apart again. The
transpiler tracks assignments in source order with one symbol table, so
concatenating two files that each define `BASE = "https://..."` — or, worse, each
define their own `def send(...)` — silently resolves one file's requests against
the other file's constants. Transpiling per file is the only way two independent
PoCs both come out as what they actually are.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass

# Markdown fence, language optional. Non-greedy so consecutive blocks do not
# collapse into one.
_FENCE_RE = re.compile(r"```([A-Za-z0-9_+\-]*)[ \t]*\r?\n(.*?)```", re.DOTALL)
# Jira wiki markup: {code:python}, {code:title=poc.py|language=python}, {code}.
_WIKI_CODE_RE = re.compile(
    r"\{code(?::([^}]*))?\}[ \t]*\r?\n?(.*?)\{code\}", re.DOTALL | re.IGNORECASE
)
_NOFORMAT_RE = re.compile(
    r"\{noformat(?::[^}]*)?\}[ \t]*\r?\n?(.*?)\{noformat\}", re.DOTALL | re.IGNORECASE
)

_FILENAME_RE = re.compile(r"^[\w][\w.\-]*\.py$")
# The decoration a filename picks up when a human writes it above a code block:
# bold, italics, inline code, a Jira heading, a list bullet, a label, an
# attachment link. Stripped before the filename test so `**01_reach.py**` and
# `h3. 01_reach.py` are recognised as the same thing as a bare line.
_DECORATION = re.compile(
    r"""^(?:h[1-6]\.\s*|[-*+•]\s*|\d+[.)]\s*|>\s*)?      # heading / bullet / quote
         (?:\*{1,2}|_{1,2}|`|\[\^?|\{\{)*                # bold/italic/code/link open
         (?:(?:poc|script|file|attachment|exploit)\s*
            (?:\#?\d+)?\s*[:\-–]\s*)?                    # "PoC 2:" / "File -"
         (?P<name>[\w][\w.\-]*\.py)
         (?:\*{1,2}|_{1,2}|`|\]|\}\})*\s*[:\-–]?\s*$     # closers, trailing colon
      """,
    re.IGNORECASE | re.VERBOSE,
)
# `# 01_reach.py` as the script's own first line — how a generated PoC usually
# names itself.
_SELF_NAME_RE = re.compile(r"^\s*#\s*(?:file\s*[:=]\s*)?([\w][\w.\-]*\.py)\s*$", re.IGNORECASE)
# {code:title=01_reach.py|language=python}
_TITLE_PARAM_RE = re.compile(r"title\s*=\s*([^|}]+)", re.IGNORECASE)
_LANGUAGE_PARAM_RE = re.compile(r"language\s*=\s*([^|}]+)", re.IGNORECASE)

_PYTHON_LANGUAGES = {"python", "py", "py3", "python3", "python2"}
# Markers that make an untagged block a plausible Python PoC rather than a JSON
# payload, a log excerpt or a curl line. An expression like `{"a": 1}` is valid
# Python, so parseability alone is not enough to tell them apart.
_PYTHON_MARKERS = (
    "import ", "from ", "def ", "requests.", "httpx.", "urlopen", "urllib",
    "session.", "client.", "print(", "aiohttp",
)
# The banner `combined_poc_source` writes and `split_combined_source` reads.
_BANNER = "# --- {filename} ---"
_BANNER_RE = re.compile(r"^#\s*-{3}\s*([\w][\w.\-]*\.py)\s*-{3}\s*$")


@dataclass(frozen=True)
class PocScript:
    """One PoC script found in a ticket, and where it was found.

    `origin` is carried all the way onto the generated test cases
    (`TestCase.source_ref`) because "which of the ticket's two PoCs produced this
    test" is the first question a reviewer asks of a plan built from a
    multi-script ticket, and reconstructing it from a merged blob is guesswork.
    """

    filename: str
    code: str
    origin: str = "description"
    language: str = "python"
    # True when the block carried no language tag and was accepted because it
    # parses as Python and calls an HTTP library. Surfaced so a reviewer can
    # give the inferred ones a harder look before approving anything.
    inferred: bool = False

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.code.encode("utf-8", "replace")).hexdigest()[:12]

    @property
    def label(self) -> str:
        return f"{self.filename} ({self.origin})"


@dataclass(frozen=True)
class PocExtraction:
    """Everything a ticket had to offer, and what could not be reached.

    `unreachable` is the part that matters as much as `scripts`: a ticket whose
    second PoC is a `.py` attachment the connector cannot download must say so.
    Reporting one script and staying silent about the other reads as "this ticket
    has one PoC", which is the exact failure this module exists to fix.
    """

    scripts: tuple[PocScript, ...] = ()
    unreachable: tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.scripts)

    @property
    def filenames(self) -> list[str]:
        return [s.filename for s in self.scripts]


# -- block scanning -----------------------------------------------------------


def looks_like_python(code: str) -> bool:
    """Would this untagged block plausibly be a Python PoC?

    Both halves are load-bearing. Without the marker check, a JSON request body
    in a fenced block is valid Python (a dict literal) and gets transpiled as a
    PoC with no requests in it. Without the parse check, a shell transcript that
    happens to contain the word `import` does the same.
    """
    if not any(marker in code for marker in _PYTHON_MARKERS):
        return False
    try:
        ast.parse(code)
    except (SyntaxError, ValueError):
        return False
    return True


def _clean_filename(name: str) -> str:
    name = name.strip().strip("`*_ \t")
    return name if _FILENAME_RE.fullmatch(name) else ""


def _preceding_filename(text: str, block_start: int) -> str:
    """The filename on the last non-blank line before a code block, if any."""
    before = text[:block_start]
    for line in reversed(before.splitlines()[-4:]):
        stripped = line.strip()
        if not stripped:
            continue
        match = _DECORATION.match(stripped)
        if match:
            return _clean_filename(match.group("name"))
        # A non-blank line that is not a filename ends the search: a filename
        # label sits immediately above its block, and scanning further up finds
        # the *previous* script's name.
        return ""
    return ""


def _self_name(code: str) -> str:
    for line in code.splitlines()[:3]:
        if not line.strip():
            continue
        match = _SELF_NAME_RE.match(line)
        if match:
            return _clean_filename(match.group(1))
        if not line.lstrip().startswith("#"):
            break
    return ""


@dataclass
class _Block:
    code: str
    language: str
    start: int
    title: str = ""


def _blocks(text: str) -> list[_Block]:
    """Every code block in a piece of text, in source order, across all syntaxes.

    Markdown fences and Jira wiki blocks are collected separately and merged by
    position, so a ticket that mixes both (a description pasted from markdown
    with a `{code}` block added later in the editor) yields both in the order a
    reader sees them.
    """
    found: list[_Block] = []
    for match in _FENCE_RE.finditer(text):
        found.append(_Block(code=match.group(2), language=match.group(1).lower(),
                            start=match.start()))
    for match in _WIKI_CODE_RE.finditer(text):
        params = match.group(1) or ""
        language = ""
        title = ""
        if params:
            language_match = _LANGUAGE_PARAM_RE.search(params)
            title_match = _TITLE_PARAM_RE.search(params)
            language = (language_match.group(1) if language_match else "").strip().lower()
            title = (title_match.group(1) if title_match else "").strip()
            if not language and "=" not in params:
                # `{code:python}` — the whole parameter is the language.
                language = params.strip().lower()
        found.append(_Block(code=match.group(2), language=language,
                            start=match.start(), title=title))
    for match in _NOFORMAT_RE.finditer(text):
        found.append(_Block(code=match.group(1), language="", start=match.start()))
    found.sort(key=lambda b: b.start)
    return found


def _scripts_in(text: str, origin: str, counter: list[int]) -> list[PocScript]:
    """Every PoC script in one piece of text. `counter` numbers the unnamed ones
    across the whole ticket, so a script from a comment cannot collide with a
    generated name already used in the description."""
    scripts: list[PocScript] = []
    for block in _blocks(text):
        code = block.code.strip("\r\n").rstrip()
        if not code.strip():
            continue
        tagged = block.language in _PYTHON_LANGUAGES
        if not tagged:
            if block.language and block.language not in ("", "text", "none", "plain"):
                # An explicitly non-Python block (```json, ```bash) is not a
                # Python PoC and guessing otherwise is how a request body ends
                # up transpiled as an exploit.
                continue
            if not looks_like_python(code):
                continue
        filename = (
            _clean_filename(block.title)
            or _preceding_filename(text, block.start)
            or _self_name(code)
        )
        if not filename:
            counter[0] += 1
            filename = f"poc_{counter[0]}.py"
        scripts.append(PocScript(
            filename=filename, code=code, origin=origin,
            language="python", inferred=not tagged,
        ))
    return scripts


def _dedupe(scripts: list[PocScript]) -> list[PocScript]:
    """Drop a script that is byte-identical to one already found.

    The same PoC pasted into the description and then again into a comment is one
    script, and transpiling it twice produces two identical test cases that a
    reviewer has to approve separately and a report counts as two probes. The
    first occurrence wins, so the description's copy keeps its name.
    """
    seen: set[str] = set()
    unique: list[PocScript] = []
    for script in scripts:
        if script.digest in seen:
            continue
        seen.add(script.digest)
        unique.append(script)
    return unique


# -- public API ---------------------------------------------------------------


def extract_poc_scripts(description: str) -> list[tuple[str, str]]:
    """[(filename, code), ...] for every PoC block in a piece of text.

    Kept as tuples: this is what the existing callers and tests read, and the
    structured form is `extract_scripts` below.
    """
    return [(s.filename, s.code) for s in extract_scripts(description)]


def extract_scripts(text: str, origin: str = "description") -> list[PocScript]:
    """Every PoC script in one piece of text, structured, in source order."""
    return _dedupe(_scripts_in(text or "", origin, [0]))


def extract_from_issue(issue, attachment_bodies: list[bytes] | None = None) -> PocExtraction:
    """Every PoC script anywhere in a ticket: description, comments, attachments.

    Comments are scanned because "the second script" arriving as a follow-up
    comment is how a real ticket grows, and a scanner that only reads the
    description silently halves such a ticket's PoC.

    `attachment_bodies` is positional-by-index against `issue.attachments`,
    which is the only pairing the connector interface offers
    (`JiraMCPClient.get_attachments` returns bare bytes). A `.py` attachment
    whose body could not be fetched is reported in `unreachable` rather than
    ignored: the tester can then paste it in by hand, which is strictly better
    than a plan that quietly covers one of the ticket's two PoCs.
    """
    counter = [0]
    scripts: list[PocScript] = []
    unreachable: list[str] = []

    scripts += _scripts_in(getattr(issue, "description", "") or "", "description", counter)

    for index, comment in enumerate(getattr(issue, "comments", None) or [], start=1):
        scripts += _scripts_in(comment or "", f"comment #{index}", counter)

    names = list(getattr(issue, "attachments", None) or [])
    bodies = list(attachment_bodies or [])
    for index, name in enumerate(names):
        if not str(name).lower().endswith(".py"):
            continue
        raw = bodies[index] if index < len(bodies) else None
        if not raw:
            unreachable.append(str(name))
            continue
        code = _decode(raw).strip()
        if not code:
            unreachable.append(str(name))
            continue
        filename = _clean_filename(str(name)) or f"attachment_{index + 1}.py"
        # An attachment is a whole file, not a block inside prose, so it is taken
        # as-is rather than run through `looks_like_python` — the ticket author
        # attached a `.py` file and that is the statement of intent. The
        # transpiler reports a syntax error if it is not one.
        scripts.append(PocScript(filename=filename, code=code,
                                 origin=f"attachment: {name}", language="python"))

    return PocExtraction(scripts=tuple(_dedupe(scripts)), unreachable=tuple(unreachable))


def _decode(raw: bytes) -> str:
    for encoding in ("utf-8", "utf-8-sig", "latin-1"):
        try:
            return raw.decode(encoding)
        except (UnicodeDecodeError, AttributeError):
            continue
    return ""


def render_combined(scripts) -> str:
    """Banner-separated blob from an already-extracted script list.

    The single definition of the banner format, so what the textarea holds and
    what `split_combined_source` parses can never drift apart. Both `PocScript`
    and the persisted `DetectedPocScript` satisfy it (filename + code).
    """
    return "\n\n".join(
        f"{_BANNER.format(filename=s.filename)}\n{s.code}" for s in scripts
    )


def combined_poc_source(description: str) -> str:
    """Every script in one blob, banner-separated — the *presentation* form.

    This is what fills the Design step's textarea, so a tester sees both files at
    once and can edit either. It is not the form the transpiler should see:
    `split_combined_source` takes it apart again, and `Orchestrator.design`
    transpiles the parts separately. Concatenating first and transpiling once
    lets two files' constants and helper definitions overwrite each other in one
    symbol table, which silently resolves one PoC's requests against the other
    PoC's `BASE`.
    """
    return render_combined(extract_scripts(description))


def split_combined_source(source: str) -> list[PocScript]:
    """Take a banner-separated blob apart again.

    The inverse of `combined_poc_source`, and the reason its banner is a
    machine-readable shape rather than decoration: what comes back out of the
    textarea — possibly hand-edited — has to be transpilable per file, and the
    only record of where one file ends and the next begins is that banner.

    Text with no banner is one script, which is exactly right for a tester who
    pasted a single PoC in by hand.
    """
    text = source or ""
    if not text.strip():
        return []
    lines = text.splitlines()
    marks: list[tuple[int, str]] = [
        (index, match.group(1))
        for index, line in enumerate(lines)
        if (match := _BANNER_RE.match(line.strip()))
    ]
    if not marks:
        return [PocScript(filename="poc_1.py", code=text.strip("\r\n").rstrip(),
                          origin="pasted")]
    scripts: list[PocScript] = []
    for position, (index, filename) in enumerate(marks):
        end = marks[position + 1][0] if position + 1 < len(marks) else len(lines)
        code = "\n".join(lines[index + 1:end]).strip("\r\n").rstrip()
        if not code.strip():
            continue
        scripts.append(PocScript(filename=filename, code=code, origin="pasted"))
    # Anything above the first banner is still somebody's code.
    preamble = "\n".join(lines[:marks[0][0]]).strip()
    if preamble:
        scripts.insert(0, PocScript(filename="poc_0.py", code=preamble, origin="pasted"))
    return scripts
