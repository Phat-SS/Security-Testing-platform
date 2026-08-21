"""Two PoC scripts in one ticket, and both of them arriving intact.

A ticket that files an unauthenticated-reach script *and* a cross-tenant-write
script is describing one finding in two steps, and a plan built from only the
first covers half of it. Three separate things were dropping the second script,
and each has its own section below: where the scanner looked, what syntax it
recognised, and what the transpiler did with the pair once it had them.

The last one is the least obvious and the most damaging. `transpile_python`
walks a single symbol table in source order, so concatenating two files that
each open with `BASE = "https://..."` resolves the *second* file's constant into
the *first* file's requests — quietly, with no error, producing test cases that
point at the wrong host or path. Two scripts, two transpiles.
"""

import asyncio

from app.analysis.plan_reviewer import PlanReviewer
from app.database.models import init_db, make_engine, make_session_factory
from app.database.repository import Repository
from app.mcp.adf import adf_to_text
from app.mcp.jira import NormalizedIssue
from app.orchestrator import Orchestrator
from app.poc.jira_extract import (
    combined_poc_source,
    extract_from_issue,
    extract_scripts,
    split_combined_source,
)

TWO_SCRIPTS = '''
Cross-tenant ownership change. Two steps to reproduce.

01_unauth_reach.py

```python
import requests
BASE = "https://staging.example.com"
requests.get(BASE + "/api/v1/vehicles/8801")
```

02_change_ownership.py

```python
import requests
BASE = "https://staging.example.com/internal"
requests.put(BASE + "/api/v1/vehicles/8801/change-ownership",
             json={"owner_id": 4711})
```
'''


def _issue(description="", comments=(), attachments=()):
    return NormalizedIssue(
        issue_key="CRM-9001", project_key="CRM", summary="Ownership change",
        description=description, comments=list(comments), attachments=list(attachments),
    )


# -- where the scanner looks --------------------------------------------------


def test_both_scripts_come_out_of_one_description_with_their_own_names():
    scripts = extract_scripts(TWO_SCRIPTS)
    assert [s.filename for s in scripts] == ["01_unauth_reach.py", "02_change_ownership.py"]
    assert "requests.get" in scripts[0].code
    assert "change-ownership" in scripts[1].code


def test_a_script_posted_as_a_follow_up_comment_is_found_too():
    """How a real ticket grows: the reach script in the description, the write
    script added later as a comment. Reading only the description halves it."""
    comment = "Second half:\n\n02_change_ownership.py\n\n```python\nimport requests\nrequests.put('https://x/v/1/change-ownership')\n```"
    extraction = extract_from_issue(_issue(description=TWO_SCRIPTS, comments=[comment]))
    origins = {s.origin for s in extraction.scripts}
    assert "description" in origins
    assert "comment #1" in origins
    assert len(extraction.scripts) == 3


def test_the_same_script_pasted_twice_is_one_script():
    """Description plus a comment repeating it is one PoC, not two test cases a
    reviewer has to approve separately."""
    block = "\n```python\nimport requests\nrequests.get('https://x/a')\n```\n"
    extraction = extract_from_issue(_issue(description=block, comments=[block]))
    assert len(extraction.scripts) == 1


def test_a_py_attachment_is_read_when_the_connector_can_supply_it():
    extraction = extract_from_issue(
        _issue(attachments=["02_change_ownership.py"]),
        [b"import requests\nrequests.put('https://x/v/1/change-ownership')\n"],
    )
    assert [s.filename for s in extraction.scripts] == ["02_change_ownership.py"]
    assert extraction.scripts[0].origin.startswith("attachment:")
    assert extraction.unreachable == ()


def test_an_attachment_the_connector_cannot_download_is_reported_not_dropped():
    """The failure this whole module exists to prevent: a ticket with two PoCs
    reported as a ticket with one. Naming the gap is the minimum."""
    extraction = extract_from_issue(
        _issue(description=TWO_SCRIPTS, attachments=["03_race_window.py"]), []
    )
    assert len(extraction.scripts) == 2
    assert extraction.unreachable == ("03_race_window.py",)


def test_a_non_python_attachment_is_not_reported_as_a_missing_poc():
    extraction = extract_from_issue(_issue(attachments=["screenshot.png", "har.json"]), [])
    assert extraction.unreachable == ()


# -- what syntax it recognises ------------------------------------------------


def test_a_native_jira_code_block_is_visible_at_all():
    """Jira Cloud's own code block is an ADF `codeBlock` with no backticks
    anywhere in it. Flattened to bare text, every PoC filed through the Jira
    editor was invisible to a scanner looking for fences."""
    doc = {"type": "doc", "content": [
        {"type": "paragraph", "content": [{"type": "text", "text": "01_reach.py"}]},
        {"type": "codeBlock", "attrs": {"language": "python"},
         "content": [{"type": "text",
                      "text": "import requests\nrequests.get('https://x/a')"}]},
        {"type": "paragraph", "content": [{"type": "text", "text": "02_write.py"}]},
        {"type": "codeBlock", "attrs": {"language": "python"},
         "content": [{"type": "text",
                      "text": "import requests\nrequests.put('https://x/b')"}]},
    ]}
    scripts = extract_scripts(adf_to_text(doc))
    assert [s.filename for s in scripts] == ["01_reach.py", "02_write.py"]


def test_jira_wiki_code_markup_is_recognised_including_its_title():
    text = ("{code:title=01_reach.py|language=python}\n"
            "import requests\nrequests.get('https://x/a')\n{code}\n"
            "{code:python}\nimport requests\nrequests.put('https://x/b')\n{code}")
    scripts = extract_scripts(text)
    assert len(scripts) == 2
    assert scripts[0].filename == "01_reach.py"


def test_an_untagged_block_that_is_really_python_is_kept():
    text = "poc.py\n\n```\nimport requests\nrequests.get('https://x/a')\n```"
    scripts = extract_scripts(text)
    assert len(scripts) == 1
    assert scripts[0].inferred is True, "flagged for a closer look, since nothing said python"


def test_a_json_payload_in_a_bare_fence_is_not_transpiled_as_a_poc():
    """`{"owner_id": 4711}` is valid Python. Parseability alone would turn every
    request body in the ticket into a PoC with no requests in it."""
    text = "Request body:\n\n```\n{\"owner_id\": 4711, \"role\": \"admin\"}\n```"
    assert extract_scripts(text) == []


def test_a_curl_line_is_not_mistaken_for_a_python_script():
    text = "```\ncurl -X PUT https://x/v/1/change-ownership -d '{\"a\":1}'\n```"
    assert extract_scripts(text) == []


def test_an_explicitly_non_python_block_is_left_alone():
    text = "```json\n{\"owner_id\": 4711}\n```"
    assert extract_scripts(text) == []


def test_a_filename_written_with_decoration_is_still_a_filename():
    for label in ("**01_reach.py**", "`01_reach.py`", "h3. 01_reach.py",
                  "- 01_reach.py", "PoC 1: 01_reach.py", "File: 01_reach.py"):
        text = f"{label}\n\n```python\nimport requests\nrequests.get('https://x/a')\n```"
        scripts = extract_scripts(text)
        assert scripts and scripts[0].filename == "01_reach.py", label


def test_a_script_that_names_itself_in_its_first_line_keeps_that_name():
    text = "```python\n# 02_change_ownership.py\nimport requests\nrequests.put('https://x/b')\n```"
    assert extract_scripts(text)[0].filename == "02_change_ownership.py"


def test_an_unnamed_block_gets_a_generated_name_that_does_not_collide():
    text = ("```python\nimport requests\nrequests.get('https://x/a')\n```\n"
            "```python\nimport requests\nrequests.get('https://x/b')\n```")
    assert [s.filename for s in extract_scripts(text)] == ["poc_1.py", "poc_2.py"]


# -- the blob, and taking it apart again --------------------------------------


def test_the_combined_blob_round_trips_back_into_separate_files():
    """The textarea holds one blob; the transpiler must still see two files. The
    banner is the only record of where one ends, so it is parsed, not decorative."""
    blob = combined_poc_source(TWO_SCRIPTS)
    parts = split_combined_source(blob)
    assert [p.filename for p in parts] == ["01_unauth_reach.py", "02_change_ownership.py"]
    assert "change-ownership" in parts[1].code
    assert "change-ownership" not in parts[0].code


def test_a_hand_pasted_script_with_no_banner_is_one_file():
    parts = split_combined_source("import requests\nrequests.get('https://x/a')")
    assert len(parts) == 1
    assert "requests.get" in parts[0].code


# -- the transpile, per file --------------------------------------------------


def _setup():
    engine = make_engine("sqlite:///:memory:")
    init_db(engine)
    repo = Repository(make_session_factory(engine))

    class _Jira:
        async def get_issue(self, key):
            return _issue(description=TWO_SCRIPTS)

        async def get_attachments(self, key):
            return []

        def browse_url(self, key):
            return None

    return repo, Orchestrator(repo, _Jira(), reviewer=PlanReviewer(None))


def test_the_ticket_reports_both_scripts_at_import():
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-9001"))
    analysis = orch.get_analysis(aid)
    assert [s.filename for s in analysis.detected_poc_scripts] == [
        "01_unauth_reach.py", "02_change_ownership.py"
    ]
    detail = [a.detail for a in repo.get_audit(aid) if a.action == "poc_detected"]
    assert detail and "01_unauth_reach.py" in detail[0] and "02_change_ownership.py" in detail[0]


def test_each_script_is_transpiled_on_its_own_so_neither_borrows_the_others_base():
    """The silent bug. Both scripts define `BASE`; concatenated, the second
    definition wins for everything after it, and the first script's request goes
    to `/internal/...` — a host and path nobody wrote."""
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-9001"))
    analysis = orch.get_analysis(aid)
    tests = orch.design(aid, poc_python=analysis.detected_poc_source,
                        use_planner=False, use_rule_engine=False, verbatim=True)

    poc_tests = [t for t in tests if t.source.value == "poc"]
    paths = {t.request.path for t in poc_tests}
    assert "/api/v1/vehicles/8801" in paths, "the reach script kept its own BASE"
    assert "/internal/api/v1/vehicles/8801/change-ownership" in paths


def test_every_test_names_the_script_it_came_from():
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-9001"))
    analysis = orch.get_analysis(aid)
    tests = orch.design(aid, poc_python=analysis.detected_poc_source,
                        use_planner=False, use_rule_engine=False, verbatim=True)
    refs = {t.source_ref for t in tests if t.source.value == "poc"}
    assert refs == {"PoC 01_unauth_reach.py", "PoC 02_change_ownership.py"}


def test_two_scripts_never_produce_two_tests_with_the_same_id():
    """Approval, edit and re-run all look a test up by id with `.one_or_none()`,
    so a duplicate id is not cosmetic — it raises on the next click."""
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-9001"))
    analysis = orch.get_analysis(aid)
    tests = orch.design(aid, poc_python=analysis.detected_poc_source,
                        use_planner=False, use_rule_engine=False, verbatim=True)
    ids = [t.test_id for t in tests]
    assert len(ids) == len(set(ids))


def test_a_broken_second_script_does_not_take_the_working_first_one_with_it():
    """Concatenated, one syntax error loses both scripts to a single parse
    failure. Per file, the working one still produces its tests and the broken
    one is named in the audit trail."""
    repo, orch = _setup()
    aid = asyncio.run(orch.import_and_analyze("CRM-9001"))
    blob = (
        "# --- 01_ok.py ---\n"
        "import requests\nrequests.get('https://x/api/v1/a')\n\n"
        "# --- 02_broken.py ---\n"
        "import requests\nrequests.put('https://x/api/v1/b'\n"
    )
    tests = orch.design(aid, poc_python=blob, use_planner=False,
                        use_rule_engine=False, verbatim=True)
    paths = {t.request.path for t in tests if t.source.value == "poc"}
    assert "/api/v1/a" in paths
    unsupported = [a.detail for a in repo.get_audit(aid) if a.action == "poc_unsupported"]
    assert unsupported and "02_broken.py" in unsupported[0]


def test_running_only_the_tickets_poc_runs_both_of_its_scripts():
    repo, orch = _setup()
    aid, _review, found = asyncio.run(orch.import_and_run_poc_plan("CRM-9001"))
    assert found is True
    refs = {t.source_ref for t in repo.get_test_cases(aid)}
    assert refs == {"PoC 01_unauth_reach.py", "PoC 02_change_ownership.py"}
