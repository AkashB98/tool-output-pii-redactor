"""Streaming: byte-identical to one-shot scrub for ANY chunking.

This is the core safety property: a secret split across a chunk boundary
must still be redacted exactly as in the one-shot scrub — no leaks, no
divergence, no double redaction.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pii_redactor import StreamingScrubber, scrub
from pii_redactor.audit import AuditLog

FIX = os.path.join(os.path.dirname(__file__), "..", "fixtures")


def chunked(text, sizes):
    s = StreamingScrubber()
    out = []
    for i in range(0, len(text), sizes):
        out.append(s.feed(text[i:i + sizes]))
    out.append(s.flush())
    return "".join(out)


def test_grid_splits_tool_trace():
    text = open(os.path.join(FIX, "tool_trace.jsonl")).read()
    whole = scrub(text)[0]
    # split at every 32nd byte: secrets land on both sides of boundaries
    for split in range(0, len(text), 32):
        s = StreamingScrubber()
        out = s.feed(text[:split]) + s.feed(text[split:]) + s.flush()
        assert out == whole, f"diverged at split {split}"


def test_grid_splits_private_key():
    text = open(os.path.join(FIX, "streaming_key.jsonl")).read()
    whole = scrub(text)[0]
    assert "[REDACTED:secret]" in whole
    for split in range(0, len(text), 32):
        s = StreamingScrubber()
        out = s.feed(text[:split]) + s.feed(text[split:]) + s.flush()
        assert out == whole, f"diverged at split {split}"


def test_chunk_size_one():
    text = open(os.path.join(FIX, "tool_trace.jsonl")).read()
    assert chunked(text, 1) == scrub(text)[0]


def test_chunk_sizes_sweep():
    text = open(os.path.join(FIX, "streaming_key.jsonl")).read()
    whole = scrub(text)[0]
    for size in (2, 3, 5, 7, 13, 64, 100, 1000):
        assert chunked(text, size) == whole, f"size {size}"


def test_split_inside_every_secret():
    text = open(os.path.join(FIX, "tool_trace.jsonl")).read()
    whole, findings = scrub(text)
    assert findings, "fixture should have findings"
    for f in findings:
        for off in range(f.start, f.end):
            s = StreamingScrubber()
            out = s.feed(text[:off]) + s.feed(text[off:]) + s.flush()
            assert out == whole, f"split inside finding at {off}"


def test_entropy_context_split_across_boundary():
    # the secret keyword lands in chunk 1, the token in chunk 2
    text = 'config api_key = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b" done'
    whole = scrub(text)[0]
    assert "[REDACTED:secret]" in whole
    for split in range(1, len(text)):
        s = StreamingScrubber()
        out = s.feed(text[:split]) + s.feed(text[split:]) + s.flush()
        assert out == whole, f"diverged at split {split}"


def test_private_key_split_mid_base64():
    body = "QUJD" * 200
    key = ("-----BEGIN RSA PRIVATE KEY-----\n" + body +
           "\n-----END RSA PRIVATE KEY-----")
    text = "prefix " + key + " suffix"
    whole = scrub(text)[0]
    assert whole == "prefix [REDACTED:secret] suffix"
    for split in (7, 40, 100, 400, 800):
        s = StreamingScrubber()
        out = s.feed(text[:split]) + s.feed(text[split:]) + s.flush()
        assert out == whole, f"diverged at split {split}"


def test_unterminated_key_emitted_at_flush():
    # BEGIN with no END: nothing to match; emitted as-is at flush
    text = "x -----BEGIN RSA PRIVATE KEY-----\\nQUJD y"
    s = StreamingScrubber()
    out = s.feed(text) + s.flush()
    assert out == text


def test_streaming_audit_counts_match():
    import tempfile
    text = open(os.path.join(FIX, "tool_trace.jsonl")).read()
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "a.jsonl")
        s = StreamingScrubber(audit=AuditLog(log))
        for i in range(0, len(text), 64):
            s.feed(text[i:i + 64])
        s.flush()
        ok, msg = AuditLog.verify(log)
        assert ok, msg
        assert sum(1 for _ in open(log)) == 10


def test_custom_window_still_deterministic():
    text = open(os.path.join(FIX, "tool_trace.jsonl")).read()
    whole = scrub(text)[0]
    for window in (64, 768, 4096):
        s = StreamingScrubber(window=window)
        out = "".join(s.feed(text[i:i + 17]) for i in range(0, len(text), 17))
        out += s.flush()
        assert out == whole, f"window {window}"
