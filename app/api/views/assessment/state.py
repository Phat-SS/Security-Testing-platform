"""Where the assessment is, and the vocabulary every phase shares.

`TIP` lives here because the endpoints table, the coverage table and the plan
all explain the same terms, and a reader should meet one definition of
`swap_object_id`, not three.
"""

from __future__ import annotations


from app.core.i18n import VI, tt as _t

class _TipDict(dict):
    """Translates on access instead of at module-load time — TIP's values are
    looked up per-request (`TIP["auth"]`), same as every other UI string here,
    but keeping them in one place under their original short names is worth
    more than saving a `_t()` at each of the ~20 call sites below."""

    def __getitem__(self, key):
        return _t(super().__getitem__(key))

# -- column and control explanations ---------------------------------------
#
# Every one of these was a term a reader had to open the source to understand.
# They live together so the vocabulary stays consistent between the endpoints
# table, the coverage table and the plan.

TIP = _TipDict({
    "auth": "Needs a credential. Public endpoints skip API2 auth probes.",
    "expected_public": "Public by design: a 200 without credentials is correct, not a finding.",
    "object_ids": "Parameters naming an object. Each one gets a BOLA id-swap test.",
    "writes": "Body fields that could be tampered with (API3).",
    "url_fields": "Fields holding a URL the server fetches (API7 SSRF).",
    "manual": "Edited by hand. Kept when the ticket is re-analyzed.",
    "category": "OWASP API Top 10 (2023). Only applicable categories show by default.",
    "state": "Covered · Partial · Missing · Not Applicable.",
    "from_poc": "Share of tests that came from your PoC. Not a security score.",
    "tests": "PoC = from your proof-of-concept. Gen = added by rules or AI.",
    "severity": "Severity if this control breaks.",
    "approval": "Only Approved tests run. Editing a test resets it to Pending.",
    "mutation": "The one security change made to a legitimate request.",
    "destructive": "Sends a real write. Needs a separate confirmation.",
    "source": "PoC, rule engine or AI planner. All need the same approval.",
    "coverage_kpi": "Applicable categories covered (Partial counts half).",
    "requirement": "One security requirement read from the ticket.",
    "req_state": "Covered · Partial · Not Covered · Not Tested.",
    "req_digest": "Each requirement restated as a checkable behaviour (AI reviewer).",
    "review": "AI reading of an undecided result. Never changes the sealed verdict.",
    "gap": "Something the plan does not test yet.",
    "verdict": "Fail · Pass · Inconclusive (control not reached) · Blocked (by scope) · Error.",
})

VI.update({
    "Needs a credential. Public endpoints skip API2 auth probes.":
        "Cần thông tin xác thực. Endpoint công khai bỏ qua test API2.",
    "Public by design: a 200 without credentials is correct, not a finding.":
        "Công khai có chủ đích: 200 không cần xác thực là đúng, không phải lỗi.",
    "Parameters naming an object. Each one gets a BOLA id-swap test.":
        "Tham số chỉ định đối tượng. Mỗi tham số có một test đổi id (BOLA).",
    "Body fields that could be tampered with (API3).":
        "Trường body có thể bị sửa đổi (API3).",
    "Fields holding a URL the server fetches (API7 SSRF).":
        "Trường chứa URL mà server tự gọi tới (API7 SSRF).",
    "Edited by hand. Kept when the ticket is re-analyzed.":
        "Sửa thủ công. Được giữ lại khi phân tích lại ticket.",
    "OWASP API Top 10 (2023). Only applicable categories show by default.":
        "OWASP API Top 10 (2023). Mặc định chỉ hiện danh mục áp dụng được.",
    "Covered · Partial · Missing · Not Applicable.":
        "Đã phủ · Một phần · Còn thiếu · Không áp dụng.",
    "Share of tests that came from your PoC. Not a security score.":
        "Tỷ lệ test đến từ PoC của bạn. Không phải điểm bảo mật.",
    "PoC = from your proof-of-concept. Gen = added by rules or AI.":
        "PoC = từ proof-of-concept của bạn. Gen = do rule hoặc AI bổ sung.",
    "Severity if this control breaks.":
        "Mức độ nghiêm trọng nếu control này bị phá vỡ.",
    "Only Approved tests run. Editing a test resets it to Pending.":
        "Chỉ test đã duyệt mới chạy. Sửa test sẽ đưa về Chờ duyệt.",
    "The one security change made to a legitimate request.":
        "Thay đổi bảo mật duy nhất áp lên một request hợp lệ.",
    "Sends a real write. Needs a separate confirmation.":
        "Gửi thao tác ghi thật. Cần xác nhận riêng.",
    "PoC, rule engine or AI planner. All need the same approval.":
        "PoC, rule engine hoặc AI planner. Tất cả đều cần duyệt như nhau.",
    "Applicable categories covered (Partial counts half).":
        "Số danh mục áp dụng đã phủ (Một phần tính nửa).",
    "One security requirement read from the ticket.":
        "Một yêu cầu bảo mật đọc từ ticket.",
    "Covered · Partial · Not Covered · Not Tested.":
        "Đã phủ · Một phần · Chưa phủ · Chưa test.",
    "Each requirement restated as a checkable behaviour (AI reviewer).":
        "Mỗi yêu cầu được diễn đạt lại thành hành vi kiểm chứng được (AI reviewer).",
    "AI reading of an undecided result. Never changes the sealed verdict.":
        "Đánh giá của AI cho kết quả chưa rõ. Không thay đổi kết luận đã niêm phong.",
    "Something the plan does not test yet.":
        "Điều kế hoạch chưa kiểm thử.",
    "Fail · Pass · Inconclusive (control not reached) · Blocked (by scope) · Error.":
        "Lỗi · Đạt · Chưa rõ (chưa chạm control) · Bị chặn (do scope) · Lỗi hệ thống.",
})


# -- readiness --------------------------------------------------------------


#: The four phases, in the order the work is done. One phase renders at a time:
#: six stacked collapsibles meant a 300-test plan buried the run button under a
#: screen of folded headings, and every section paid the cost of every other
#: section being on the page.
PHASES = (
    ("scope", "Scope"),
    ("plan", "Plan"),
    ("run", "Run"),
    ("results", "Results"),
)
PHASES_BY_KEY = dict(PHASES)

#: The section anchors that used to be the navigation. Reports, the coverage
#: table and older bookmarks link to them, so each one resolves to the phase
#: that absorbed it rather than 404ing into the default.
PHASE_FOR_ANCHOR = {
    "s-endpoints": "scope",
    "s-coverage": "scope",
    "s-design": "plan",
    "s-plan": "plan",
    "s-execute": "run",
    "s-results": "results",
}

VI.update({"Scope": "Phạm vi", "Plan": "Kế hoạch", "Run": "Chạy", "Results": "Kết quả"})


def resolve_phase(requested: str, st: "_State") -> str:
    """The phase to render. An unknown or empty value falls back to where the
    assessment actually is, so a stale link still lands somewhere useful."""
    requested = (requested or "").strip().lstrip("#")
    requested = PHASE_FOR_ANCHOR.get(requested, requested)
    return requested if requested in PHASES_BY_KEY else st.default_phase


class _State:
    """Where the assessment is, computed once and consulted by every section.

    Which sections open by default, which step the nav marks current and which
    empty state is shown all follow from the same three counts, so they are
    derived in one place rather than re-inferred per section.
    """

    def __init__(self, n_endpoints: int, plan_meta: dict, n_executions: int) -> None:
        # Taken from the plan-wide counts the repository computes during the same
        # scan the filter facets need — the page must not have to load and
        # validate every test in a 400-test plan just to say how many are
        # approved.
        self.n_endpoints = n_endpoints
        self.n_tests = int(plan_meta.get("total", 0))
        self.n_approved = int(plan_meta.get("approved", 0))
        self.n_rejected = int(plan_meta.get("rejected", 0))
        self.n_destructive_approved = int(plan_meta.get("approved_destructive", 0))
        self.n_executions = n_executions

    @property
    def stage(self) -> str:
        if not self.n_tests:
            return "design"
        if not self.n_approved:
            return "approve"
        if not self.n_executions:
            return "execute"
        return "report"

    @property
    def default_phase(self) -> str:
        """Where to land when no phase was asked for.

        The endpoint list is the single input the whole plan is derived from,
        so a ticket with no plan yet opens on Scope — correcting the surface
        after generating means regenerating. Everything after that follows the
        work: a plan to approve opens Plan, an approved plan opens Run, and a
        run that has happened opens Results.
        """
        return {
            "design": "scope",
            "approve": "plan",
            "execute": "run",
            "report": "results",
        }[self.stage]

    def phase_state(self) -> dict[str, str]:
        """"done" / "current" / "todo" per phase, for the rail."""
        done = {
            "scope": self.n_endpoints > 0,
            "plan": self.n_approved > 0,
            "run": self.n_executions > 0,
            "results": self.n_executions > 0,
        }
        current = self.default_phase
        return {
            key: "current" if key == current else ("done" if done[key] else "todo")
            for key in PHASES_BY_KEY
        }


# -- step nav ---------------------------------------------------------------


def _is_stale(analysis: dict) -> bool:
    """True when the stored plan fingerprint no longer matches the endpoints."""
    from app.schemas.analysis import IssueAnalysis

    try:
        return IssueAnalysis.model_validate(analysis).plan_is_stale()
    except Exception:
        # A malformed analysis blob is not worth a 500 on a page whose job is to
        # let a tester fix exactly that kind of problem.
        return False
