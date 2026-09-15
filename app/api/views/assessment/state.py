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
    "auth": "Whether the endpoint requires a credential. Drives the API2 "
            "(broken authentication) probes: a public endpoint has no "
            "credential to drop, so those tests are pointless there.",
    "expected_public": "This endpoint is intentionally public — a 200 without a "
                       "credential is the correct, expected result, not a finding. "
                       "Generates a confirmation test instead of a vulnerability "
                       "probe; a 401/403 there would flag a regression.",
    "object_ids": "Path, query or body parameters that name an object — the "
                  "BOLA/BOPLA surface. Each one becomes an id the attacker "
                  "persona swaps for the victim's. Miss one here and the whole "
                  "category goes untested.",
    "writes": "The request carries a body whose properties could be tampered "
              "with. Drives API3 (mass assignment / excessive data exposure).",
    "url_fields": "Body or query fields holding a URL the server fetches "
                  "itself. Drives API7 (SSRF) — without one, there is nothing "
                  "for the server to be coerced into requesting.",
    "manual": "Added or edited by hand rather than extracted from the ticket. "
              "Re-analyzing the ticket keeps these rows.",
    "category": "OWASP API Security Top 10 (2023). Only categories the "
                "analyzer judged applicable to this ticket are shown by "
                "default — the rest are listed under the disclosure below.",
    "state": "COVERED — your imported PoC already tests this and the designer "
             "found no gap. PARTIAL — the PoC touches it but the designer "
             "added tests for what it missed. MISSING — applicable, and "
             "nothing tests it yet. NOT APPLICABLE — the analyzer found no "
             "signal for this category in this ticket.",
    "from_poc": "How much of this category's coverage came from the PoC you "
                "imported, as PoC tests / (PoC + generated). It is NOT a "
                "measure of how secure the endpoint is — it says where the "
                "tests came from.",
    "tests": "PoC = transpiled from the proof-of-concept you imported. "
             "gen = written by the rule engine and the AI planner to fill the "
             "gaps the PoC left.",
    "severity": "The severity a confirmed break of this control would carry, "
                "taken from the OWASP control's default and the endpoint's "
                "exposure. Not a measure of how likely the test is to pass.",
    "approval": "Nothing runs until it is APPROVED. Editing a test's request, "
                "or regenerating a plan in a way that changes what a test "
                "does, resets it to PENDING — an approval means you read what "
                "the test does.",
    "mutation": "The one security-relevant change made to an otherwise "
                "legitimate request. It is what classifies a result: a finding "
                "is described by what was changed, not guessed from a status "
                "code.",
    "destructive": "Sends a real POST/PUT/PATCH/DELETE. Excluded from an "
                   "ordinary run and gated behind a separate confirmation, "
                   "because a broken control means the write actually "
                   "happened.",
    "source": "Where the test came from: the PoC you imported, the "
              "deterministic rule engine, or the AI planner. AI-proposed tests "
              "go through the same approval gate as every other test.",
    "coverage_kpi": "Applicable categories that are covered, counting a "
                    "PARTIAL as a half. A low number here means the plan has "
                    "gaps, not that the API is safe.",
    "requirement": "One discrete thing the ticket asks for, read out of its "
                   "acceptance criteria and security-relevant bullets. This list is "
                   "the denominator of the coverage percentage, so an item missing "
                   "here is a percentage that flatters the run.",
    "req_state": "COVERED — a test for this item ran and reached a decisive result. "
                 "PARTIAL — a test ran but decided nothing. NOT COVERED — a test "
                 "exists but has not run. NOT TESTED — nothing in the plan "
                 "addresses it. An item with no security-relevant reading is "
                 "excluded from the score rather than counted against it.",
    "req_digest": "The AI reviewer's restatement of each security-relevant "
                  "requirement as the concrete behaviour a test result can be "
                  "checked against — a specific status code, who may act, what "
                  "must never happen — rather than the ticket's own, often "
                  "vaguer, wording. Only appears when the AI reviewer ran.",
    "review": "What the reviewing agent made of a result the runner left "
              "undecided. It never overwrites the sealed verdict. Only a named "
              "measurement or challenged HIGH-confidence consensus may create a "
              "separate derived finding.",
    "gap": "Something the reviewing agent says the plan does not cover. A "
           "blocking gap is a security-relevant requirement with no test at all. "
           "Gaps are fed back to the planner for a bounded revision round; what "
           "is left is listed for you.",
    "verdict": "FAIL — the control broke and the response disclosed it. PASS — "
               "the control held. INCONCLUSIVE — the test never exercised the "
               "control (a stale object id, say), which is honest rather than "
               "useful. BLOCKED — refused by scope before anything was sent. "
               "ERROR — the test itself could not run.",
})

VI.update({
    "Whether the endpoint requires a credential. Drives the API2 "
    "(broken authentication) probes: a public endpoint has no "
    "credential to drop, so those tests are pointless there.":
        "Endpoint có yêu cầu thông tin xác thực hay không. Quyết định các test API2 "
        "(broken authentication): endpoint công khai không có credential để bỏ đi, nên "
        "các test đó vô nghĩa ở đấy.",
    "Path, query or body parameters that name an object — the "
    "BOLA/BOPLA surface. Each one becomes an id the attacker "
    "persona swaps for the victim's. Miss one here and the whole "
    "category goes untested.":
        "Tham số path, query hoặc body định danh một object — bề mặt BOLA/BOPLA. Mỗi "
        "cái sẽ trở thành một id mà persona kẻ tấn công đổi sang của nạn nhân. Bỏ sót "
        "một cái ở đây là cả danh mục không được test.",
    "The request carries a body whose properties could be tampered "
    "with. Drives API3 (mass assignment / excessive data exposure).":
        "Request mang theo body có các thuộc tính có thể bị can thiệp. Quyết định "
        "API3 (mass assignment / lộ dữ liệu thừa).",
    "Body or query fields holding a URL the server fetches "
    "itself. Drives API7 (SSRF) — without one, there is nothing "
    "for the server to be coerced into requesting.":
        "Trường body hoặc query chứa URL mà server tự gọi tới. Quyết định API7 (SSRF) "
        "— không có trường này thì không có gì để ép server phải gọi tới.",
    "Added or edited by hand rather than extracted from the ticket. "
    "Re-analyzing the ticket keeps these rows.":
        "Được thêm hoặc sửa bằng tay thay vì trích xuất từ ticket. Phân tích lại "
        "ticket vẫn giữ nguyên các dòng này.",
    "OWASP API Security Top 10 (2023). Only categories the "
    "analyzer judged applicable to this ticket are shown by "
    "default — the rest are listed under the disclosure below.":
        "OWASP API Security Top 10 (2023). Mặc định chỉ hiện các danh mục mà bộ phân "
        "tích cho là áp dụng được với ticket này — phần còn lại nằm trong mục mở rộng "
        "bên dưới.",
    "COVERED — your imported PoC already tests this and the designer "
    "found no gap. PARTIAL — the PoC touches it but the designer "
    "added tests for what it missed. MISSING — applicable, and "
    "nothing tests it yet. NOT APPLICABLE — the analyzer found no "
    "signal for this category in this ticket.":
        "ĐÃ PHỦ — PoC bạn nhập đã test cái này và designer không thấy lỗ hổng nào. "
        "MỘT PHẦN — PoC có chạm tới nhưng designer đã thêm test cho phần còn thiếu. "
        "THIẾU — áp dụng được, nhưng chưa có gì test. KHÔNG ÁP DỤNG — bộ phân tích "
        "không thấy dấu hiệu nào của danh mục này trong ticket.",
    "How much of this category's coverage came from the PoC you "
    "imported, as PoC tests / (PoC + generated). It is NOT a "
    "measure of how secure the endpoint is — it says where the "
    "tests came from.":
        "Bao nhiêu phần độ phủ của danh mục này đến từ PoC bạn nhập, dạng test PoC / "
        "(PoC + đã tạo). Đây KHÔNG phải thước đo độ an toàn của endpoint — chỉ nói "
        "test đến từ đâu.",
    "PoC = transpiled from the proof-of-concept you imported. "
    "gen = written by the rule engine and the AI planner to fill the "
    "gaps the PoC left.":
        "PoC = được chuyển đổi từ proof-of-concept bạn nhập. gen = do rule engine và "
        "AI planner viết để lấp lỗ hổng PoC còn để lại.",
    "The severity a confirmed break of this control would carry, "
    "taken from the OWASP control's default and the endpoint's "
    "exposure. Not a measure of how likely the test is to pass.":
        "Mức độ nghiêm trọng nếu control này thực sự bị phá vỡ, lấy theo mặc định của "
        "control OWASP và mức độ phơi nhiễm của endpoint. Không phải thước đo khả năng "
        "test sẽ đạt.",
    "Nothing runs until it is APPROVED. Editing a test's request, "
    "or regenerating a plan in a way that changes what a test "
    "does, resets it to PENDING — an approval means you read what "
    "the test does.":
        "Không có gì chạy cho tới khi được DUYỆT. Sửa request của test, hoặc tạo lại "
        "kế hoạch theo cách làm thay đổi hành vi của test, sẽ đưa nó về PENDING — một "
        "lượt duyệt nghĩa là bạn đã đọc test đó làm gì.",
    "The one security-relevant change made to an otherwise "
    "legitimate request. It is what classifies a result: a finding "
    "is described by what was changed, not guessed from a status "
    "code.":
        "Thay đổi duy nhất liên quan bảo mật được áp vào một request vốn hợp lệ. Đây "
        "là thứ phân loại kết quả: một finding được mô tả bằng thứ đã bị thay đổi, "
        "không phải đoán từ mã trạng thái.",
    "Sends a real POST/PUT/PATCH/DELETE. Excluded from an "
    "ordinary run and gated behind a separate confirmation, "
    "because a broken control means the write actually "
    "happened.":
        "Gửi một POST/PUT/PATCH/DELETE thật. Bị loại khỏi lượt chạy thông thường và "
        "cần một xác nhận riêng, vì control bị phá vỡ nghĩa là dữ liệu đã thực sự bị "
        "ghi đè.",
    "Where the test came from: the PoC you imported, the "
    "deterministic rule engine, or the AI planner. AI-proposed tests "
    "go through the same approval gate as every other test.":
        "Test đến từ đâu: PoC bạn nhập, rule engine tất định, hay AI planner. Test do "
        "AI đề xuất đi qua đúng cổng duyệt như mọi test khác.",
    "Applicable categories that are covered, counting a "
    "PARTIAL as a half. A low number here means the plan has "
    "gaps, not that the API is safe.":
        "Số danh mục áp dụng được đã phủ, tính MỘT PHẦN là nửa điểm. Số thấp ở đây "
        "nghĩa là kế hoạch còn lỗ hổng, không phải API an toàn.",
    "One discrete thing the ticket asks for, read out of its "
    "acceptance criteria and security-relevant bullets. This list is "
    "the denominator of the coverage percentage, so an item missing "
    "here is a percentage that flatters the run.":
        "Một điều cụ thể ticket yêu cầu, đọc ra từ acceptance criteria và các gạch "
        "đầu dòng liên quan bảo mật. Danh sách này là mẫu số của tỷ lệ phủ, nên thiếu "
        "một mục ở đây là tỷ lệ đang tâng bốc lượt chạy.",
    "COVERED — a test for this item ran and reached a decisive result. "
    "PARTIAL — a test ran but decided nothing. NOT COVERED — a test "
    "exists but has not run. NOT TESTED — nothing in the plan "
    "addresses it. An item with no security-relevant reading is "
    "excluded from the score rather than counted against it.":
        "ĐÃ PHỦ — có test cho mục này và đã ra kết quả dứt khoát. MỘT PHẦN — có test "
        "chạy nhưng không quyết được gì. CHƯA PHỦ — có test nhưng chưa chạy. CHƯA "
        "TEST — không có gì trong kế hoạch đề cập tới. Mục không mang ý nghĩa bảo mật "
        "được loại khỏi điểm số thay vì bị tính là điểm trừ.",
    "What the reviewing agent made of a result the runner left "
    "undecided. Advisory: it never overwrites the sealed verdict and "
    "never creates a finding — it tells you whether you still have to "
    "read this one yourself.":
        "Agent đánh giá nghĩ gì về một kết quả mà runner để ngỏ. Chỉ mang tính tham "
        "khảo: không bao giờ ghi đè kết luận đã niêm phong và không tạo finding — nó "
        "chỉ cho bạn biết bạn có còn phải tự đọc cái này không.",
    "Something the reviewing agent says the plan does not cover. A "
    "blocking gap is a security-relevant requirement with no test at all. "
    "Gaps are fed back to the planner for a bounded revision round; what "
    "is left is listed for you.":
        "Điều mà agent đánh giá nói kế hoạch chưa phủ. Một lỗ hổng chặn là yêu cầu "
        "liên quan bảo mật mà không có test nào cả. Lỗ hổng được đưa lại cho planner "
        "trong một vòng chỉnh sửa có giới hạn; phần còn lại được liệt kê cho bạn.",
    "FAIL — the control broke and the response disclosed it. PASS — "
    "the control held. INCONCLUSIVE — the test never exercised the "
    "control (a stale object id, say), which is honest rather than "
    "useful. BLOCKED — refused by scope before anything was sent. "
    "ERROR — the test itself could not run.":
        "LỖI — control bị phá vỡ và phản hồi để lộ điều đó. ĐẠT — control đứng vững. "
        "CHƯA RÕ — test chưa thực sự chạm vào control (ví dụ object id đã cũ), trung "
        "thực hơn là hữu ích. BỊ CHẶN — bị scope từ chối trước khi gửi đi. LỖI HỆ "
        "THỐNG — bản thân test không chạy được.",
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
