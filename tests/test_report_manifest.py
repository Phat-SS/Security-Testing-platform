from app.reporting.manifest import build_manifest, verify_manifest
from app.reporting.quality import ReportVerification


def test_report_manifest_signature_detects_tampering(monkeypatch):
    monkeypatch.setenv("REPORT_SIGNING_KEY", "a-long-secret-held-outside-the-database")
    manifest = build_manifest(
        "A-1", "CRM-1", {"digest": "abc"}, [], [], [],
        ReportVerification(ok=True, checked_findings=0, checked_references=0), [],
    )

    assert manifest.signed is True
    assert verify_manifest(manifest) is True
    manifest.issue_key = "TAMPERED-1"
    assert verify_manifest(manifest) is False


def test_manifest_fails_closed_when_no_signing_key(monkeypatch):
    monkeypatch.delenv("REPORT_SIGNING_KEY", raising=False)
    manifest = build_manifest(
        "A-1", "CRM-1", {}, [], [], [],
        ReportVerification(ok=True, checked_findings=0, checked_references=0), [],
    )
    assert manifest.signed is False
    assert verify_manifest(manifest) is False
