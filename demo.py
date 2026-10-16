"""Asserted end-to-end demo: scrub a tool-output transcript, stream it,
audit it. Run with `python demo.py` or `pii-redactor demo`."""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pii_redactor import AuditLog, StreamingScrubber, find_findings, scrub  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def run() -> None:
    trace = open(os.path.join(HERE, "fixtures", "tool_trace.jsonl")).read()

    # 1. one-shot scrub -----------------------------------------------------
    redacted, findings = scrub(trace)
    assert len(findings) == 10, f"expected 10 findings, got {len(findings)}"
    cats = sorted(f.category for f in findings)
    assert cats == ["card", "credentials", "email", "phone", "secret",
                    "secret", "secret", "secret", "secret", "ssn"], cats
    for secret in ("priya.sharma@helioshome.test", "(214) 555-0182",
                   "4532015112830366", "219-09-9999",
                   "sk_live_51FictionalKeyValue99"):
        assert secret not in redacted, f"leaked: {secret}"
    assert redacted.count("[REDACTED:secret]") == 5
    assert "[REDACTED:email]" in redacted and "[REDACTED:card]" in redacted
    print(f"1. scrub: 10 findings redacted "
          f"({', '.join(sorted(set(cats)))})")

    # 2. streaming determinism (adversarial chunk sizes) --------------------
    key_doc = open(os.path.join(HERE, "fixtures", "streaming_key.jsonl")).read()
    whole, _ = scrub(key_doc)
    assert "[REDACTED:secret]" in whole  # the private-key block is gone
    for size in (1, 7, 64, 1000):
        s = StreamingScrubber()
        out = "".join(s.feed(key_doc[i:i + size])
                      for i in range(0, len(key_doc), size))
        out += s.flush()
        assert out == whole, f"streaming diverged at chunk size {size}"
    print("2. streaming: chunk sizes 1/7/64/1000 byte-identical to one-shot "
          "(incl. splits inside the private-key block)")

    # 3. false-positive traps stay clean ------------------------------------
    traps = open(os.path.join(HERE, "fixtures", "fp_traps.txt")).read()
    assert find_findings(traps) == [], "FP trap fired"
    print("3. fp traps: 0 findings across 11 trap lines "
          "(example.com, doc keys, test cards, santa, uuids, shas)")

    # 4. audit chain ---------------------------------------------------------
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "audit.jsonl")
        audit = AuditLog(log)
        scrub(trace, audit=audit)
        assert audit.entries_logged == 10
        ok, msg = AuditLog.verify(log)
        assert ok, msg
        # the log proves what was removed without storing it
        assert "4532015112830366" not in open(log).read()
    print("4. audit: 10 hash-chained entries, verify() ok, "
          "no raw secrets in the log")

    print("\ndemo ok: firewall blocks attacks inbound, "
          "this scrubber stops leaks outbound.")


if __name__ == "__main__":
    run()
