"""Extraction of PoC scripts embedded directly in a Jira description."""

from app.poc.jira_extract import combined_poc_source, extract_poc_scripts

DESCRIPTION_WITH_POC = '''
Some finding summary.

PoC scripts:

01_unauth_change_ownership_reach.py

```python
import requests
requests.get("https://api.example.com/customers/2002")
```

Notes: filed by the bounty-hunter tool.
'''

DESCRIPTION_WITHOUT_POC = "PoC: python poc_customer.py --env staging\nNo fenced code here."


def test_extracts_filename_and_code():
    scripts = extract_poc_scripts(DESCRIPTION_WITH_POC)
    assert len(scripts) == 1
    filename, code = scripts[0]
    assert filename == "01_unauth_change_ownership_reach.py"
    assert "requests.get" in code


def test_no_fenced_block_returns_nothing():
    assert extract_poc_scripts(DESCRIPTION_WITHOUT_POC) == []
    assert combined_poc_source(DESCRIPTION_WITHOUT_POC) == ""


def test_multiple_scripts_are_concatenated_in_order():
    description = '''
01_first.py
```python
import requests
requests.get("https://api.example.com/a")
```

02_second.py
```python
import requests
requests.get("https://api.example.com/b")
```
'''
    scripts = extract_poc_scripts(description)
    assert [f for f, _ in scripts] == ["01_first.py", "02_second.py"]
    source = combined_poc_source(description)
    assert source.index("01_first.py") < source.index("/a") < source.index("02_second.py") < source.index("/b")


def test_unlabeled_block_gets_generated_name():
    description = "```python\nimport requests\nrequests.get('https://x/y')\n```"
    scripts = extract_poc_scripts(description)
    assert scripts[0][0] == "poc_1.py"
