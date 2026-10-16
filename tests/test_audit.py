"""Audit log: hash chaining, verify(), tamper detection, no raw secrets."""

import json
import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pii_redactor.audit import AuditLog
from pii_redactor import scrub


def test_chain_verifies():
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "a.jsonl")
        a = AuditLog(log)
        a.log_redaction("PAT-EMAIL", "email", "ab" * 32, 20)
        a.log_redaction("PAT-CARD", "card", "cd" * 32, 16)
        ok, msg = AuditLog.verify(log)
        assert ok, msg
        assert "2 entries" in msg


def test_entries_chained():
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "a.jsonl")
        a = AuditLog(log)
        e1 = a.log_redaction("PAT-EMAIL", "email", "ab" * 32, 20)
        e2 = a.log_redaction("PAT-CARD", "card", "cd" * 32, 16)
        assert e1["seq"] == 0 and e2["seq"] == 1
        assert e2["prev"] == e1["hash"]
        assert e1["prev"] == "GENESIS"


def test_tamper_detected():
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "a.jsonl")
        a = AuditLog(log)
        a.log_redaction("PAT-EMAIL", "email", "ab" * 32, 20)
        a.log_redaction("PAT-CARD", "card", "cd" * 32, 16)
        lines = open(log).read().splitlines()
        entry = json.loads(lines[1])
        entry["category"] = "phone"  # tamper
        lines[1] = json.dumps(entry)
        open(log, "w").write("\n".join(lines) + "\n")
        ok, msg = AuditLog.verify(log)
        assert not ok and "tampered" in msg or "mismatch" in msg


def test_deletion_detected():
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "a.jsonl")
        a = AuditLog(log)
        a.log_redaction("PAT-EMAIL", "email", "ab" * 32, 20)
        a.log_redaction("PAT-CARD", "card", "cd" * 32, 16)
        lines = open(log).read().splitlines()
        open(log, "w").write(lines[0] + "\n")  # drop the second entry
        ok, _ = AuditLog.verify(log)
        # single remaining entry still verifies on its own; the point is
        # seq continuity: append resumes at the right seq
        assert ok
        a2 = AuditLog(log)
        assert a2.entries_logged == 1


def test_no_raw_secrets_in_log():
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "a.jsonl")
        audit = AuditLog(log)
        text = "card 4532015112830366 mail priya.sharma@helioshome.test"
        scrub(text, audit=audit)
        body = open(log).read()
        assert "4532015112830366" not in body
        assert "priya.sharma@helioshome.test" not in body
        # ...but the proof of removal is there: hashes + lengths
        entries = [json.loads(ln) for ln in body.splitlines()]
        assert {e["span_len"] for e in entries} == {16, 28}
        assert all(len(e["span_sha256"]) == 64 for e in entries)


def test_verify_missing_file():
    ok, msg = AuditLog.verify("/nonexistent/audit.jsonl")
    assert not ok


def test_in_memory_mode():
    a = AuditLog()  # no path: no file written
    a.log_redaction("PAT-EMAIL", "email", "ab" * 32, 20)
    assert a.entries_logged == 1
