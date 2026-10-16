"""Golden evals: pinned detector behavior on fixtures.

Each case pins exact expected findings (detector, category, span). The
report at evals/eval_report.json must be byte-identical across runs
(determinism is itself an eval). Exit 0 = all pass.

Golden spans were verified by hand against the fixtures on 2026-10-16;
they are pinned here, not captured blindly.
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from pii_redactor import (  # noqa: E402
    Allowlist,
    AuditLog,
    StreamingScrubber,
    find_findings,
    scrub,
)

HERE = os.path.dirname(os.path.abspath(__file__))
GOLDEN = os.path.join(HERE, "golden")
FIX = os.path.join(HERE, "..", "fixtures")


def _md5(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def _load(name: str) -> str:
    with open(os.path.join(FIX, name), encoding="utf-8") as fh:
        return fh.read()


def _golden(name: str):
    with open(os.path.join(GOLDEN, name), encoding="utf-8") as fh:
        return json.load(fh)


def case_fixture_findings() -> dict:
    text = _load("tool_trace.jsonl")
    findings = find_findings(text)
    got = [(f.detector, f.category, f.start, f.end) for f in findings]
    want = [tuple(x) for x in _golden("tool_trace_findings.json")]
    return {"pass": got == want, "got": got, "want": want}


def case_fixture_redacted_md5() -> dict:
    text = _load("tool_trace.jsonl")
    redacted, _ = scrub(text)
    got = _md5(redacted)
    want = _golden("tool_trace_redacted_md5.json")["md5"]
    return {"pass": got == want, "got": got, "want": want}


def case_fp_traps_clean() -> dict:
    findings = find_findings(_load("fp_traps.txt"))
    got = [(f.detector, f.category, f.start, f.end) for f in findings]
    return {"pass": got == [], "got": got, "want": []}


def case_private_key_fixture() -> dict:
    text = _load("streaming_key.jsonl")
    findings = find_findings(text)
    got = [[f.detector, f.category] for f in findings]
    want = [["PAT-PRIVATE-KEY", "secret"]]
    redacted, _ = scrub(text)
    md_ok = _md5(redacted) == _golden("streaming_key_md5.json")["md5"]
    return {"pass": got == want and md_ok, "got": got, "want": want,
            "md5_ok": md_ok}


def case_streaming_determinism() -> dict:
    results = []
    for name in ("tool_trace.jsonl", "streaming_key.jsonl"):
        text = _load(name)
        whole = scrub(text)[0]
        for size in (1, 7, 64, 1000):
            s = StreamingScrubber()
            out = "".join(s.feed(text[i:i + size])
                          for i in range(0, len(text), size))
            out += s.flush()
            results.append(out == whole)
    return {"pass": all(results), "chunk_runs": len(results)}


def case_allowlist_custom() -> dict:
    a = Allowlist.from_dict({"exact": ["ops@helioshome.test"], "regex": []})
    findings = find_findings("mail ops@helioshome.test and a@b.co", a)
    got = [[f.detector, f.category] for f in findings]
    want = [["PAT-EMAIL", "email"]]
    return {"pass": got == want, "got": got, "want": want}


def case_audit_chain() -> dict:
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        log = os.path.join(tmp, "audit.jsonl")
        audit = AuditLog(log)
        scrub(_load("tool_trace.jsonl"), audit=audit)
        ok, msg = AuditLog.verify(log)
        body = open(log).read()
        no_raw = "4532015112830366" not in body
        return {"pass": ok and no_raw and audit.entries_logged == 10,
                "verify": msg, "entries": audit.entries_logged}


CASES = [
    ("fixture_findings", case_fixture_findings),
    ("fixture_redacted_md5", case_fixture_redacted_md5),
    ("fp_traps_clean", case_fp_traps_clean),
    ("private_key_fixture", case_private_key_fixture),
    ("streaming_determinism", case_streaming_determinism),
    ("allowlist_custom", case_allowlist_custom),
    ("audit_chain", case_audit_chain),
]


def main() -> int:
    results = {}
    all_pass = True
    for name, fn in CASES:
        try:
            r = fn()
        except Exception as exc:  # noqa: BLE001
            r = {"pass": False, "error": repr(exc)}
        results[name] = r
        all_pass = all_pass and bool(r["pass"])
        print(("PASS " if r["pass"] else "FAIL ") + name)
    report = {"cases": results, "all_pass": all_pass,
              "n_cases": len(CASES)}
    # audit_chain embeds timestamps -> normalize for determinism check
    norm = json.loads(json.dumps(report))
    norm["cases"]["audit_chain"].pop("verify", None)
    path = os.path.join(HERE, "eval_report.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(norm, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"\nreport: {path}  md5={_md5(open(path).read())}")
    return 0 if all_pass else 1


if __name__ == "__main__":
    raise SystemExit(main())
