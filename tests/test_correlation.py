from app.execution.correlation import correlate_bodies


def test_hmac_correlation_proves_shared_owner_values_without_storing_them(monkeypatch):
    monkeypatch.setenv("EVIDENCE_FINGERPRINT_KEY", "0123456789abcdef0123456789abcdef")
    owner = '{"id":2002,"name":"Victim Person","email":"victim@example.test"}'
    attacker = (
        '{"id":2002,"name":"Victim Person","email":"victim@example.test",'
        '"requestId":"different-request"}'
    )

    result = correlate_bodies(owner, attacker)

    assert result is not None and result.decisive
    assert len(result.shared_fingerprints) == 3
    assert all("Victim" not in digest and "victim@" not in digest
               for digest in result.shared_fingerprints)


def test_correlation_fails_closed_without_a_key(monkeypatch):
    monkeypatch.delenv("EVIDENCE_FINGERPRINT_KEY", raising=False)

    assert correlate_bodies('{"id":2002}', '{"id":2002}') is None


def test_one_coincidental_value_is_not_decisive(monkeypatch):
    monkeypatch.setenv("EVIDENCE_FINGERPRINT_KEY", "0123456789abcdef")

    result = correlate_bodies('{"id":2002}', '{"id":2002}')

    assert result is not None
    assert not result.decisive


def test_shared_transport_metadata_is_not_treated_as_identity_disclosure(monkeypatch):
    monkeypatch.setenv("EVIDENCE_FINGERPRINT_KEY", "0123456789abcdef")
    common = '{"requestId":"same-request","version":"2026.1.0","status":"pending"}'

    assert correlate_bodies(common, common) is None
