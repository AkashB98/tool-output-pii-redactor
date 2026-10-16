"""Scrubbing: find findings, redact them, and stream safely across chunks.

The key design problem for a *streaming* scrubber: a secret can be split
across a chunk boundary ("AKIA" in chunk 1, "IOSFODNN7EXAMPLE" in chunk 2).
Emitting chunk 1's text as-is would leak half the secret.

StreamingScrubber solves it with a provably-safe emission cut. Every
detector pattern only ever matches characters from the SPAN set below (no
detector matches quotes, commas, brackets, etc.). The scrubber emits input
only up to the last character *outside* SPAN within the emit window. No
detector match can span that cut point: a spanning match would have to
contain the cut character, which is not in SPAN. So emitted text is final —
later chunks can never complete a secret inside it.

Consequences:
  * scrub(whole) is byte-identical to feed(chunk1) + feed(chunk2) + ... +
    flush(), for ANY chunking. Pinned by tests/test_streaming.py, which
    splits fixtures at every 32nd byte (plus adversarial splits inside
    secrets and inside the private-key block).
  * Emission granularity is "up to the last non-SPAN char": in JSON-ish tool
    output (quotes, commas, brackets everywhere) this is every few dozen
    characters. In prose without punctuation, emission waits for flush.
    That tradeoff is documented, not hidden.
"""

from __future__ import annotations

import re
import string
from dataclasses import dataclass

from .allowlist import Allowlist
from .audit import AuditLog
from .detectors import DETECTORS, RawMatch, all_raw_matches

# SPAN_CHARS: every character any detector pattern can match in the
# realistic case. The streaming safe-cut never emits past a character
# outside SPAN, so no detector match is ever split across an emission
# boundary. Conservative: extra chars here only reduce emission
# granularity, never safety. '\\' is included because tool outputs often
# carry JSON-escaped key blocks ("...\\n..."). The private-key detector is
# additionally protected by the dangling-BEGIN hold in scrubber.py, which
# does not depend on SPAN at all.
SPAN_CHARS = frozenset(
    string.ascii_letters
    + string.digits
    + "-_.+%@:/=;() \t\n'\"\\"
)

REDACTION_TEMPLATE = "[REDACTED:{category}]"

# detector id -> priority, for overlap resolution
_PRIORITY = {d["id"]: d["priority"] for d in DETECTORS}
_PRIORITY["ENT-SECRET"] = 200
_PRIORITY["ENT-SECRET-CTX"] = 210


@dataclass(frozen=True)
class Finding:
    detector: str
    category: str
    start: int
    end: int
    redaction: str


def _resolve_overlaps(matches: list[RawMatch]) -> list[RawMatch]:
    """Specific detectors beat generic ones; length breaks remaining ties.

    Priority encodes specificity: a URL-credentials match (PAT-URL-CREDS)
    beats the email-shaped phantom inside it ("s3cr3t@db.internal"), a JWT
    beats an entropy sub-match, a Luhn-valid card beats a phone-shaped
    substring. Length is only the tie-break within equal priority.
    """
    ordered = sorted(
        matches, key=lambda m: (m.start, _PRIORITY[m.detector], -(m.end - m.start))
    )
    accepted: list[RawMatch] = []
    occupied_until = -1
    for m in ordered:
        if m.start >= occupied_until:
            accepted.append(m)
            occupied_until = m.end
        # else: overlaps an accepted (more specific or longer) match
    return accepted


def find_findings(text: str, allowlist: Allowlist | None = None) -> list[Finding]:
    """All findings in text, in document order, allowlist applied."""
    allow = allowlist or Allowlist.default()
    findings: list[Finding] = []
    for m in _resolve_overlaps(all_raw_matches(text)):
        value = text[m.start:m.end]
        if allow.is_allowed(value):
            continue  # allowlist-safe: exempt values are never redacted
        findings.append(
            Finding(
                detector=m.detector,
                category=m.category,
                start=m.start,
                end=m.end,
                redaction=REDACTION_TEMPLATE.format(category=m.category),
            )
        )
    return findings


def scrub(text: str, allowlist: Allowlist | None = None,
          audit: AuditLog | None = None) -> tuple[str, list[Finding]]:
    """Redact text. Returns (redacted_text, findings). Deterministic."""
    findings = find_findings(text, allowlist)
    if not findings:
        return text, []
    parts: list[str] = []
    pos = 0
    for f in findings:
        parts.append(text[pos:f.start])
        parts.append(f.redaction)
        pos = f.end
    parts.append(text[pos:])
    redacted = "".join(parts)
    if audit is not None:
        for f in findings:
            audit.log_redaction(
                detector=f.detector,
                category=f.category,
                span_sha256=_span_hash(text[f.start:f.end]),
                span_len=f.end - f.start,
            )
    return redacted, findings


def _span_hash(span: str) -> str:
    import hashlib
    return hashlib.sha256(span.encode("utf-8")).hexdigest()


def _safe_cut(text: str, max_emit: int) -> int:
    """Largest cut <= max_emit with text[cut-1] not in SPAN (or 0).

    No detector match can span the cut: spanning it would require the
    cut character to be inside a match, hence in SPAN. The cut therefore
    never splits a match — complete or still-incomplete.
    """
    limit = min(max_emit, len(text))
    for i in range(limit - 1, -1, -1):
        if text[i] not in SPAN_CHARS:
            return i + 1
    return 0


_BEGIN_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
_END_RE = re.compile(r"-----END [A-Z0-9 ]*PRIVATE KEY-----")


def _dangling_begin_hold(buf: str, cut: int) -> int:
    """Hold emission at a private-key BEGIN whose END hasn't arrived.

    The private-key pattern is the only unbounded DOTALL detector, so it
    is the only one whose match can be *incomplete* in the current buffer
    while its BEGIN is already behind the cut. Holding at the BEGIN keeps
    the whole block pending until the END arrives (or flush), so a key is
    never half-emitted. Belt-and-braces on top of the SPAN cut.
    """
    for bm in _BEGIN_RE.finditer(buf):
        if bm.start() >= cut:
            break  # beyond the emit region: already held in pending
        if not _END_RE.search(buf, bm.end()):
            return bm.start()
    return cut


class StreamingScrubber:
    """Chunk-wise scrubber with byte-identical output to scrub(whole).

    Three mechanisms keep every chunking byte-identical to the one-shot
    scrub:

    1. SPAN safe-cut: emission stops at the last non-SPAN character, so no
       detector match (complete or partial) is ever split by an emission
       boundary.
    2. Finding-aware cut-back: after detection, the cut is pulled back to
       the start of any real finding that would span it (independent of
       the SPAN heuristic).
    3. Dangling-BEGIN hold: a private-key BEGIN without its END yet holds
       emission at the BEGIN, so a key split across chunks is never
       half-emitted.
    4. Context carry: the entropy detector's 80-char lookback sees the
       true preceding text (last 80 emitted chars), in feed() and flush().

    The default lag window (768) exceeds the longest bounded match
    (512-char entropy candidate) plus the 80-char context lookback, so an
    incomplete candidate can never reach back into already-emitted text.
    The private key is the only unbounded detector and is fenced by the
    dangling-BEGIN hold instead.

    Usage:
        s = StreamingScrubber()
        out = s.feed(chunk1) + s.feed(chunk2)
        out += s.flush()
        assert out == scrub(chunk1 + chunk2)[0]
    """

    def __init__(self, allowlist: Allowlist | None = None,
                 audit: AuditLog | None = None, window: int = 768):
        self._allowlist = allowlist or Allowlist.default()
        self._audit = audit
        self._window = window
        self._pending = ""   # raw input received but not yet emitted
        self._ctx = ""       # last <=80 raw chars already emitted
        self._emitted = 0    # chars of original input fully processed

    def _detect(self, scan: str) -> list[RawMatch]:
        return _resolve_overlaps(all_raw_matches(scan))

    def _apply(self, scan: str, ctx_len: int, cut: int) -> str:
        """Redact findings fully inside the emit region [ctx_len, ctx_len+cut).

        Findings starting inside the carried context were decided when
        that text was emitted; findings ending past the cut stay pending.
        """
        matches = self._detect(scan)
        parts: list[str] = []
        pos = ctx_len
        for m in matches:
            s, e = m.start, m.end
            if s < ctx_len:
                continue  # decided in an earlier feed
            if e > ctx_len + cut:
                break  # sorted by start, non-overlapping: rest are later
            value = scan[s:e]
            parts.append(scan[pos:s])
            if self._allowlist.is_allowed(value):
                parts.append(value)  # exempt: emit verbatim
            else:
                redaction = REDACTION_TEMPLATE.format(category=m.category)
                parts.append(redaction)
                if self._audit is not None:
                    self._audit.log_redaction(
                        detector=m.detector,
                        category=m.category,
                        span_sha256=_span_hash(value),
                        span_len=e - s,
                    )
            pos = e
        parts.append(scan[pos:ctx_len + cut])
        return "".join(parts)

    def _process(self, buf: str, is_flush: bool) -> str:
        scan = self._ctx + buf
        ctx_len = len(self._ctx)
        if is_flush:
            cut = len(buf)
        else:
            cut = _safe_cut(buf, len(buf) - self._window)
            cut = _dangling_begin_hold(buf, cut)
            # never split a real finding across the cut
            for m in self._detect(scan):
                s, e = m.start - ctx_len, m.end - ctx_len
                if s < cut < e:
                    cut = max(0, s)
        redacted = self._apply(scan, ctx_len, cut)
        emitted_raw = buf[:cut]
        self._pending = buf[cut:]
        # carry true context for the next feed's entropy lookback
        self._ctx = (self._ctx + emitted_raw)[-80:]
        self._emitted += len(emitted_raw)
        return redacted

    def feed(self, chunk: str) -> str:
        return self._process(self._pending + chunk, is_flush=False)

    def flush(self) -> str:
        return self._process(self._pending, is_flush=True)

    @property
    def buffered(self) -> int:
        return len(self._pending)
