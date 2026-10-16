"""Scrubber: overlap resolution, redaction format, determinism, SPAN pins."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pii_redactor import find_findings, scrub
from pii_redactor.scrubber import SPAN_CHARS


def test_redaction_format():
    redacted, findings = scrub("mail priya.sharma@helioshome.test")
    assert len(findings) == 1
    assert findings[0].redaction == "[REDACTED:email]"
    assert redacted == "mail [REDACTED:email]"


def test_specific_detector_wins_overlap():
    # a Luhn-valid card run: the specific card detector beats any
    # phone-shaped substring (specificity first, length second)
    text = "x 4532015112830366 y"
    findings = find_findings(text)
    assert len(findings) == 1
    assert findings[0].category == "card"


def test_jwt_beats_entropy_submatch():
    jwt = ("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
           "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
    findings = find_findings("t " + jwt)
    assert len(findings) == 1
    assert findings[0].detector == "PAT-JWT"


def test_findings_in_document_order():
    findings = find_findings("a@b.co then 219-09-9999")
    assert [f.category for f in findings] == ["email", "ssn"]
    assert findings[0].start < findings[1].start


def test_deterministic_across_runs():
    text = open(os.path.join(os.path.dirname(__file__), "..",
                             "fixtures", "tool_trace.jsonl")).read()
    assert scrub(text)[0] == scrub(text)[0]
    assert [ (f.start, f.end, f.category) for f in find_findings(text) ] == \
           [ (f.start, f.end, f.category) for f in find_findings(text) ]


def test_no_findings_returns_input_unchanged():
    text = "nothing sensitive here"
    redacted, findings = scrub(text)
    assert redacted == text and findings == []


def test_span_contains_tricky_chars():
    # every char below can appear inside some detector match; if any were
    # missing from SPAN, the streaming safe-cut proof would break
    for ch in "\\\n\t '\"()+%@:/=;.-_":
        assert ch in SPAN_CHARS, repr(ch)
    for ch in "aZ09":
        assert ch in SPAN_CHARS


def test_empty_input():
    assert scrub("") == ("", [])


def test_adjacent_findings():
    findings = find_findings("a@b.co,c@d.co")
    assert len(findings) == 2
    redacted, _ = scrub("a@b.co,c@d.co")
    assert redacted == "[REDACTED:email],[REDACTED:email]"
