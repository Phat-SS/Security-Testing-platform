"""One test case, in full: its request, its mutation, and what it expects.
"""

from __future__ import annotations

import json


from .shell import _APPROVAL_CLASS, _SEV_CLASS, _e, page
from app.core.i18n import tt as _t
from app.database.models import Assessment
from app.schemas.testcase import TestCase

# Pill color class per severity / coverage state / approval status. Coverage
# states and approval statuses reuse the same 5-color vocabulary as severity
# (crit/high/med/low/info) so a reader only has to learn one palette.

def test_detail_page(assessment: Assessment, test: TestCase, flash: str = "") -> str:
    aid = assessment.id
    flash_html = f"<div class='card pad flash'>{_e(_t(flash))}</div>" if flash else ""

    headers_text = "\n".join(f"{k}: {v}" for k, v in test.request.headers.items())
    query_text = "\n".join(f"{k}={v}" for k, v in test.request.query.items())
    body = test.request.body
    if isinstance(body, (dict, list)):
        body_text = json.dumps(body, indent=2)
    elif body is None:
        body_text = ""
    else:
        body_text = str(body)

    sev_c = _SEV_CLASS.get(test.severity.value, "info")
    appr_c = _APPROVAL_CLASS.get(test.approval_status.value, "info")
    dest = "<span class='destr'>DESTRUCTIVE</span>" if test.is_destructive else ""
    persona_line = _e(test.auth_context.persona)
    if test.auth_context.target_persona:
        persona_line += f" → {_e(test.auth_context.target_persona)}"
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE"]
    method_options = "".join(
        f"<option value='{m}' {'selected' if test.request.method.upper() == m else ''}>{m}</option>"
        for m in methods
    )

    return page(f"{test.test_id} — {assessment.issue_key}", f"""
{flash_html}
<div class="pagehead">
<div>
<h1>{_e(test.test_id)}
<span class="pill {sev_c}">{_e(test.severity.value)}</span>
<span class="pill {appr_c}">{_e(test.approval_status.value)}</span> {dest}</h1>
<p class="sub" style="margin:2px 0 0">{_e(test.title)}</p>
</div>
<a href="/assessment/{_e(aid)}" class="btn ghost">← Back to {_e(assessment.issue_key)}</a>
</div>

<div class="card pad" style="margin-bottom:18px">
<div class="row" style="gap:28px;flex-wrap:wrap">
<div><div class="glabel" style="margin:0 0 3px">OWASP</div><div>{_e(test.owasp_category.value)}</div></div>
<div><div class="glabel" style="margin:0 0 3px">Mutation</div><div class="mono">{_e(test.attack_mutation.kind)}</div></div>
<div><div class="glabel" style="margin:0 0 3px">Persona</div><div class="mono">{persona_line}</div></div>
<div><div class="glabel" style="margin:0 0 3px">Expected status</div>
<div class="mono">{_e(', '.join(str(s) for s in test.expected.status_in))}</div></div>
</div>
<p class="muted" style="margin:14px 0 0">{_e(test.objective)}</p>
</div>

<div class="card pad">
<p class="muted" style="margin:0 0 16px">Saving resets this test's approval to <b>PENDING</b> — review
and re-approve it on the assessment page before it can run.</p>
<form method="post" action="/assessment/{_e(aid)}/test/{_e(test.test_id)}">
<div class="row" style="gap:10px;align-items:flex-end;margin-bottom:14px">
<label class="field" style="max-width:130px"><span>Method</span>
<select name="method">{method_options}</select></label>
<label class="field" style="flex:1"><span>Path / URL</span>
<input name="path" value="{_e(test.request.path)}" class="mono" required></label>
</div>
<label class="field" style="margin-bottom:14px"><span>Headers — one per line, "Key: Value"</span>
<textarea name="headers_text" rows="4" class="mono" placeholder="Authorization: Bearer {{token}}">{_e(headers_text)}</textarea></label>
<label class="field" style="margin-bottom:14px"><span>Query params — one per line, "key=value"</span>
<textarea name="query_text" rows="3" class="mono" placeholder="limit=10">{_e(query_text)}</textarea></label>
<label class="field" style="margin-bottom:16px"><span>Body / payload — JSON or raw text</span>
<textarea name="body_text" rows="10" class="mono">{_e(body_text)}</textarea></label>
<button class="btn">Save changes</button>
<a href="/assessment/{_e(aid)}" class="btn sec">Cancel</a>
</form>
</div>
""", active="assessment")
