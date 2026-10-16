"""Per-detector positives, validators, and negative cases."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pii_redactor.detectors import pattern_matches
from pii_redactor import find_findings, scrub


def ids(text):
    return sorted(m.detector for m in pattern_matches(text))


def test_email_positive():
    assert ids("mail priya.sharma@helioshome.test now") == ["PAT-EMAIL"]


def test_email_rejects_bad_tld():
    assert ids("user@localhost") == []


def test_phone_parens():
    assert ids("call (214) 555-0182") == ["PAT-PHONE"]


def test_phone_separators():
    assert ids("call 214-555-0182") == ["PAT-PHONE"]
    assert ids("call 214.555.0182") == ["PAT-PHONE"]
    assert ids("call +1 214 555 0182") == ["PAT-PHONE"]


def test_phone_rejects_bare_ten_digits():
    # order numbers must not match: separators (or parens/country) required
    assert ids("order 2145550182 shipped") == []


def test_phone_rejects_seven_digits():
    assert ids("call 555-0100") == []


def test_card_luhn_valid():
    assert ids("card 4532015112830366") == ["PAT-CARD"]


def test_card_with_separators():
    assert ids("card 4532 0151 1283 0366") == ["PAT-CARD"]
    assert ids("card 4532-0151-1283-0366") == ["PAT-CARD"]


def test_card_rejects_luhn_invalid():
    assert ids("order 91827364509187 shipped") == []


def test_card_rejects_repeated_digits():
    assert ids("pin 0000000000000000") == []


def test_card_span_excludes_edge_separators():
    ms = pattern_matches("card 4532015112830366, ok")
    assert len(ms) == 1
    assert ms[0].detector == "PAT-CARD"


def test_ssn_valid():
    assert ids("ssn 219-09-9999") == ["PAT-SSN"]


def test_ssn_rejects_invalid_areas():
    assert ids("ssn 000-12-3456") == []
    assert ids("ssn 666-12-3456") == []
    assert ids("ssn 900-12-3456") == []


def test_ssn_rejects_zero_group_serial():
    assert ids("ssn 219-00-9999") == []
    assert ids("ssn 219-09-0000") == []


def test_aws_key():
    assert ids("key AKIAW3X9Q2K7M4N6P1AB here") == ["PAT-AWS-KEY"]


def test_github_token():
    assert ids("tok ghp_aBcDeFgHiJkLmNoPqRsT0123 end") == ["PAT-GITHUB-TOKEN"]


def test_stripe_key():
    assert ids("k sk_live_51FictionalKeyValue99 end") == ["PAT-STRIPE-KEY"]


def test_jwt():
    jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
           "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    assert ids("bearer " + jwt) == ["PAT-JWT"]


def test_url_credentials_redacts_userinfo_only():
    from pii_redactor import find_findings
    text = "db https://admin:s3cr3t@db.internal:5432/x"
    findings = find_findings(text)
    # the URL-credentials detector (specific) beats the email-shaped
    # phantom inside it ("s3cr3t@db.internal", generic)
    assert len(findings) == 1
    f = findings[0]
    assert f.detector == "PAT-URL-CREDS"
    assert text[f.start:f.end] == "admin:s3cr3t"
    redacted, _ = scrub(text)
    assert redacted == "db https://[REDACTED:credentials]@db.internal:5432/x"


def test_specificity_beats_length():
    # card (priority 70) beats a phone-shaped substring even when shorter
    from pii_redactor import find_findings
    findings = find_findings("x 4532015112830366 y")
    assert len(findings) == 1
    assert findings[0].category == "card"


def test_private_key_block():
    key = ("-----BEGIN RSA PRIVATE KEY-----\n"
           "QUJD\n"
           "-----END RSA PRIVATE KEY-----")
    ms = pattern_matches("k: " + key)
    assert len(ms) == 1 and ms[0].detector == "PAT-PRIVATE-KEY"


def test_clean_text_has_no_matches():
    assert pattern_matches("the quick brown fox jumps over the lazy dog") == []
