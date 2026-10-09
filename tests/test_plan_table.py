"""Reviewing a large test plan.

An aggressive design over a handful of endpoints is a hundred-plus tests, and
the plan used to render every one of them into a single table with no search,
filter, sort or paging — and with a checkbox that looked like a two-way toggle
but only ever approved: unchecking a box did nothing, and there was no way to
withdraw an approval or reject anything from the list at all.
"""

import pytest
from starlette.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path/'plan.db'}")
    monkeypatch.delenv("ENGAGEMENT_CONFIG", raising=False)
    from app.api.main import app

    with TestClient(app) as c:
        yield c


def _repo():
    import app.api.main as main

    return main.state.repo


@pytest.fixture()
def big_plan(client):
    """A plan large enough that paging and filtering are load-bearing."""
    aid = client.post("/import", data={"issue_key": "MOCK-345"},
                      follow_redirects=True).url.path.rsplit("/", 1)[-1]
    client.post(f"/assessment/{aid}/design", data={"depth": "aggressive"},
                follow_redirects=True)
    assert len(_repo().get_test_cases(aid)) > 40, "expected aggressive depth to be large"
    return aid


def _statuses(aid) -> dict[str, str]:
    return {t.test_id: t.approval_status.value for t in _repo().get_test_cases(aid)}


def _n(aid, status) -> int:
    return sum(1 for v in _statuses(aid).values() if v == status)


# -- paging -----------------------------------------------------------------


def test_the_plan_is_paged_not_dumped(client, big_plan):
    total = len(_repo().get_test_cases(big_plan))

    page = client.get(f"/assessment/{big_plan}?per=25").text

    assert page.count('class="tsel" name="test_ids"') == 25
    assert 'class="pager"' in page
    assert f"{total} tests" in page


def test_a_later_page_shows_different_tests(client, big_plan):
    first = client.get(f"/assessment/{big_plan}?per=10&page=1").text
    second = client.get(f"/assessment/{big_plan}?per=10&page=2").text

    def ids(html):
        return set(part.split('"')[0]
                   for part in html.split('name="test_ids" value="')[1:])

    assert ids(first) and ids(second)
    assert not (ids(first) & ids(second)), "page 2 repeated page 1"


def test_an_out_of_range_page_clamps_instead_of_erroring(client, big_plan):
    r = client.get(f"/assessment/{big_plan}?per=25&page=9999")

    assert r.status_code == 200
    assert 'name="test_ids"' in r.text


# -- filtering --------------------------------------------------------------


def test_filter_by_category(client, big_plan):
    expected = _repo().query_test_cases(big_plan, cat="API1:2023", per=500)["total"]
    assert expected

    page = client.get(f"/assessment/{big_plan}?cat=API1:2023&per=500").text

    assert page.count('class="tsel" name="test_ids"') == expected
    ids = [part.split('"')[0] for part in page.split('name="test_ids" value="')[1:]]
    assert ids and all(i.startswith("API1-") for i in ids), (
        f"the filtered plan still lists other categories: {ids[:5]}"
    )


def test_filter_by_search_text_matches_the_mutation_kind(client, big_plan):
    result = _repo().query_test_cases(big_plan, q="drop_auth", per=500)

    assert result["total"], "expected the plan to contain drop_auth probes"
    for t in result["tests"]:
        assert "drop_auth" in t.attack_mutation.kind


def test_filter_by_destructive_splits_reads_from_writes(client, big_plan):
    writes = _repo().query_test_cases(big_plan, dest="yes", per=500)
    reads = _repo().query_test_cases(big_plan, dest="no", per=500)

    assert writes["total"] and reads["total"]
    assert writes["total"] + reads["total"] == writes["unfiltered_total"]
    assert all(t.is_destructive for t in writes["tests"])
    assert not any(t.is_destructive for t in reads["tests"])


def test_facets_only_offer_values_the_plan_contains(client, big_plan):
    facets = _repo().query_test_cases(big_plan, per=1)["facets"]

    present = {t.owasp_category.value for t in _repo().get_test_cases(big_plan)}
    assert set(facets["cat"]) == present
    assert sum(facets["cat"].values()) == len(_repo().get_test_cases(big_plan))


def test_sort_by_severity_puts_the_worst_first(client, big_plan):
    tests = _repo().query_test_cases(big_plan, sort="sev", per=500)["tests"]

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    ranks = [order.index(t.severity.value) for t in tests]
    assert ranks == sorted(ranks)


def test_the_filter_survives_into_the_page_controls(client, big_plan):
    page = client.get(f"/assessment/{big_plan}?q=drop_auth&cat=API2:2023&sort=sev").text

    assert 'value="drop_auth"' in page
    assert '<option value="API2:2023" selected>' in page
    assert '<option value="sev" selected>' in page


# -- bulk decisions ---------------------------------------------------------


def test_approve_only_the_selected_rows(client, big_plan):
    ids = [t.test_id for t in _repo().get_test_cases(big_plan)][:3]

    client.post(f"/assessment/{big_plan}/plan",
                data={"action": "approve", "test_ids": ids}, follow_redirects=True)

    assert _n(big_plan, "APPROVED") == 3
    assert all(_statuses(big_plan)[i] == "APPROVED" for i in ids)


def test_approve_everything_matching_the_filter_not_just_the_page(client, big_plan):
    """The point of resolving "all matching" server-side: the page showed 25 rows,
    and the tester asked for the 27 the filter describes."""
    expected = _repo().query_test_cases(big_plan, cat="API1:2023", per=500)["total"]
    assert expected > 25, "need more matches than fit on a page for this to mean anything"

    r = client.post(f"/assessment/{big_plan}/plan", follow_redirects=True,
                    data={"action": "approve", "select_all": "true", "cat": "API1:2023",
                          "per": "25"})

    assert _n(big_plan, "APPROVED") == expected
    assert "matching the current filter" in r.text


def test_reject_is_available_from_the_list(client, big_plan):
    ids = [t.test_id for t in _repo().get_test_cases(big_plan)][:2]

    client.post(f"/assessment/{big_plan}/plan",
                data={"action": "reject", "test_ids": ids}, follow_redirects=True)

    assert _n(big_plan, "REJECTED") == 2


def test_reset_withdraws_an_approval(client, big_plan):
    """Unchecking a box never did this — the handler only read ticked boxes, so an
    approval could be given and never taken back."""
    ids = [t.test_id for t in _repo().get_test_cases(big_plan)][:4]
    client.post(f"/assessment/{big_plan}/plan",
                data={"action": "approve", "test_ids": ids}, follow_redirects=True)
    assert _n(big_plan, "APPROVED") == 4

    client.post(f"/assessment/{big_plan}/plan",
                data={"action": "reset", "test_ids": ids[:2]}, follow_redirects=True)

    assert _n(big_plan, "APPROVED") == 2
    assert _n(big_plan, "PENDING") == len(_repo().get_test_cases(big_plan)) - 2


def test_a_bulk_action_keeps_the_filter_across_the_redirect(client, big_plan):
    r = client.post(f"/assessment/{big_plan}/plan", follow_redirects=True,
                    data={"action": "approve", "test_ids": [], "cat": "API1:2023",
                          "q": "swap"})

    assert "Nothing selected" in r.text


def test_an_unknown_action_is_refused_rather_than_guessed(client, big_plan):
    ids = [t.test_id for t in _repo().get_test_cases(big_plan)][:1]

    r = client.post(f"/assessment/{big_plan}/plan", follow_redirects=True,
                    data={"action": "delete_everything", "test_ids": ids})

    assert "Unknown action" in r.text
    assert _n(big_plan, "APPROVED") == 0


def test_a_bulk_decision_records_which_tests_it_touched(client, big_plan):
    ids = [t.test_id for t in _repo().get_test_cases(big_plan)][:3]

    client.post(f"/assessment/{big_plan}/plan",
                data={"action": "approve", "test_ids": ids}, follow_redirects=True)

    audit = [a for a in _repo().get_audit(big_plan) if a.action == "approve"]
    assert audit
    assert all(i in audit[-1].detail for i in ids), (
        '"3 tests approved" is not an answer to "which 3?"'
    )


def test_a_large_bulk_decision_summarises_instead_of_logging_every_id(client, big_plan):
    ids = [t.test_id for t in _repo().get_test_cases(big_plan)]
    assert len(ids) > 12

    client.post(f"/assessment/{big_plan}/plan",
                data={"action": "approve", "test_ids": ids}, follow_redirects=True)

    detail = [a for a in _repo().get_audit(big_plan) if a.action == "approve"][-1].detail
    assert f"{len(ids)} test(s)" in detail
    assert detail.endswith("...")


# -- coverage links into the plan -------------------------------------------


def test_the_coverage_table_links_into_a_filtered_plan(client, big_plan):
    page = client.get(f"/assessment/{big_plan}?phase=scope").text

    # The coverage table lives on Scope and links across to a filtered Plan,
    # so the destination carries the phase as well as the filter.
    assert ("?cat=API1%3A2023&phase=plan" in page
            or "?cat=API1:2023&phase=plan" in page)
