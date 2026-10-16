"""CLI: exit codes, scrub output, audit verify."""

import contextlib
import io
import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pii_redactor.cli import main


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(argv)
    return code, out.getvalue(), err.getvalue()


def _tmp(content, suffix=".txt"):
    fh = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    fh.write(content)
    fh.close()
    return fh.name


def test_check_clean_exits_zero():
    path = _tmp("nothing sensitive here")
    code, _, _ = _run(["check", path])
    assert code == 0
    os.unlink(path)


def test_check_findings_exit_one():
    path = _tmp("mail priya.sharma@helioshome.test")
    code, _, err = _run(["check", path])
    assert code == 1
    assert "PAT-EMAIL" in err
    os.unlink(path)


def test_check_bad_allowlist_exit_two():
    bad = _tmp("{not json", ".json")
    path = _tmp("clean")
    code, _, _ = _run(["check", path, "--allowlist", bad])
    assert code == 2
    os.unlink(bad)
    os.unlink(path)


def test_scrub_writes_redacted_stdout():
    path = _tmp("mail priya.sharma@helioshome.test")
    code, out, _ = _run(["scrub", path])
    assert code == 0
    assert out == "mail [REDACTED:email]"
    os.unlink(path)


def test_scrub_stream_matches_oneshot():
    text = "a@b.co " + "x" * 900 + " 219-09-9999 end"
    path = _tmp(text)
    code, streamed, _ = _run(["scrub", path, "--stream", "--chunk-size", "7"])
    assert code == 0
    code, oneshot, _ = _run(["scrub", path])
    assert code == 0
    assert streamed == oneshot
    os.unlink(path)


def test_audit_verify_command():
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "a.jsonl")
        from pii_redactor import AuditLog
        AuditLog(log).log_redaction("PAT-EMAIL", "email", "ab" * 32, 20)
        code, out, _ = _run(["audit", "--verify", log])
        assert code == 0
        assert "chain valid" in out
