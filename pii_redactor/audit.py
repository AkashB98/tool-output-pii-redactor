"""Hash-chained audit log for redactions.

Every redaction appends one JSONL entry:
    seq, ts, detector, category, span_sha256, span_len, prev, hash

The log stores the SHA-256 of the redacted span, never the span itself —
proof of *what* was removed (length + hash) without retaining the secret.
Each entry's hash chains to the previous entry's hash, so tampering with or
deleting entries is detectable via verify().

Same chaining discipline as the sibling tool-approval-gate's audit log.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class AuditLog:
    def __init__(self, path: str | None = None):
        self.path = path
        self._seq = 0
        self._prev = "GENESIS"
        if path:
            self._load_tail()

    def _load_tail(self) -> None:
        assert self.path is not None
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                lines = [ln for ln in fh if ln.strip()]
        except FileNotFoundError:
            return
        if not lines:
            return
        last = json.loads(lines[-1])
        self._seq = int(last["seq"]) + 1
        self._prev = last["hash"]

    @staticmethod
    def _entry_hash(entry: dict) -> str:
        canonical = json.dumps(entry, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def log_redaction(self, detector: str, category: str,
                      span_sha256: str, span_len: int) -> dict:
        entry = {
            "seq": self._seq,
            "ts": _utcnow(),
            "detector": detector,
            "category": category,
            "span_sha256": span_sha256,
            "span_len": span_len,
            "prev": self._prev,
        }
        entry["hash"] = self._entry_hash(entry)
        self._prev = entry["hash"]
        self._seq += 1
        if self.path:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, sort_keys=True) + "\n")
        return entry

    @property
    def entries_logged(self) -> int:
        return self._seq

    @staticmethod
    def verify(path: str) -> tuple[bool, str]:
        """Recompute the chain. Returns (ok, message)."""
        try:
            with open(path, "r", encoding="utf-8") as fh:
                lines = [ln for ln in fh if ln.strip()]
        except FileNotFoundError:
            return False, "audit log not found"
        prev = "GENESIS"
        for i, ln in enumerate(lines):
            try:
                entry = json.loads(ln)
            except json.JSONDecodeError:
                return False, f"line {i}: not valid JSON"
            if entry.get("seq") != i:
                return False, f"line {i}: seq {entry.get('seq')} != {i}"
            if entry.get("prev") != prev:
                return False, f"line {i}: chain break (prev mismatch)"
            body = {k: v for k, v in entry.items() if k != "hash"}
            if AuditLog._entry_hash(body) != entry.get("hash"):
                return False, f"line {i}: hash mismatch (tampered entry)"
            # the log must never contain a raw secret: spans are hashes only
            for k, v in entry.items():
                if k == "span_sha256":
                    if not isinstance(v, str) or len(v) != 64:
                        return False, f"line {i}: span_sha256 malformed"
            prev = entry["hash"]
        return True, f"chain valid, {len(lines)} entries"
