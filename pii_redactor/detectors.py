"""Pattern + entropy detectors for the PII/secret scrubber.

Each detector is a dict with:
    id        - stable rule id, e.g. "PAT-EMAIL"
    category  - redaction label suffix, e.g. "email" -> [REDACTED:email]
    pattern   - compiled regex with a single match span
    validate  - fn(match) -> bool, extra semantic checks (Luhn, SSN rules, ...)
    priority  - lower wins when two detectors match the same span

Overlap resolution (in scrubber.find_findings): all detectors run over the
whole text; matches are sorted by (start, -length, priority) and greedily
accepted when they don't overlap an accepted match. Longest match wins ties,
then priority. The allowlist is checked *before* a match becomes a finding,
so allowlisted values are never redacted even when they match a pattern.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class RawMatch:
    detector: str
    category: str
    start: int
    end: int


# ---------------------------------------------------------------------------
# validators
# ---------------------------------------------------------------------------

def _luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = ord(ch) - 48
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _valid_card(m: re.Match) -> bool:
    digits = re.sub(r"\D", "", m.group(0))
    if not 13 <= len(digits) <= 19:
        return False
    if len(set(digits)) == 1:  # 0000... / 1111... runs are not cards
        return False
    return _luhn_ok(digits)


def _valid_ssn(m: re.Match) -> bool:
    area, group, serial = m.group(1), m.group(2), m.group(3)
    if area in ("000", "666") or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    return True


def _valid_phone(m: re.Match) -> bool:
    digits = re.sub(r"\D", "", m.group(0))
    # 10 digits, or 11 starting with a leading 1 (US country code)
    if len(digits) == 10:
        return True
    return len(digits) == 11 and digits.startswith("1")


def _always(_m: re.Match) -> bool:
    return True


# ---------------------------------------------------------------------------
# detector table
# ---------------------------------------------------------------------------

DETECTORS = [
    {
        "id": "PAT-PRIVATE-KEY",
        "category": "secret",
        "pattern": re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "validate": _always,
        "priority": 10,
    },
    {
        "id": "PAT-JWT",
        "category": "secret",
        "pattern": re.compile(
            r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"
            r"(?![A-Za-z0-9_-])"
        ),
        "validate": _always,
        "priority": 20,
    },
    {
        "id": "PAT-URL-CREDS",
        "category": "credentials",
        # redact only the userinfo part of scheme://user:pass@host
        # (span_group=2: the scheme itself is not sensitive)
        "pattern": re.compile(
            r"\b([a-zA-Z][a-zA-Z0-9+.-]*://)([^/\s:@?#]+:[^/\s@?#]+)(?=@)"
        ),
        "span_group": 2,
        "validate": _always,
        "priority": 30,
    },
    {
        "id": "PAT-AWS-KEY",
        "category": "secret",
        "pattern": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
        "validate": _always,
        "priority": 40,
    },
    {
        "id": "PAT-GITHUB-TOKEN",
        "category": "secret",
        "pattern": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
        "validate": _always,
        "priority": 50,
    },
    {
        "id": "PAT-STRIPE-KEY",
        "category": "secret",
        "pattern": re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b"),
        "validate": _always,
        "priority": 60,
    },
    {
        "id": "PAT-CARD",
        "category": "card",
        # digits with optional internal separators; the match always starts
        # and ends on a digit so edge separators never join the span
        # (an edge separator would break exact allowlist matching)
        "pattern": re.compile(r"(?<!\d)(?:\d[ \-. ]?){12,18}\d(?!\d)"),
        "validate": _valid_card,
        "priority": 70,
    },
    {
        "id": "PAT-SSN",
        "category": "ssn",
        "pattern": re.compile(r"(?<!\d)(\d{3})-(\d{2})-(\d{4})(?!\d)"),
        "validate": _valid_ssn,
        "priority": 80,
    },
    {
        "id": "PAT-PHONE",
        "category": "phone",
        # requires a separator, parens, or country code after the area code,
        # so bare 10-digit order numbers do not match
        "pattern": re.compile(
            r"(?<!\d)(?:\+\d{1,3}[-. ]?)?(?:\(\d{3}\)[-. ]?|\d{3}[-. ])"
            r"\d{3}[-. ]?\d{4}(?!\d)"
        ),
        "validate": _valid_phone,
        "priority": 90,
    },
    {
        "id": "PAT-EMAIL",
        "category": "email",
        "pattern": re.compile(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}"
        ),
        "validate": _always,
        "priority": 100,
    },
]


# ---------------------------------------------------------------------------
# entropy detector (unlabeled high-entropy tokens)
# ---------------------------------------------------------------------------

_CANDIDATE_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,512}")
_CONTEXT_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|passwd|password|bearer|auth|credential)"
    r"|[:=]\s*[\"']?$"
)
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

#: Shannon entropy (bits/char) at or above which a token-shaped candidate is
#: treated as a secret on shape alone. Calibrated in tests/test_entropy.py
#: against random base64url tokens (~5.9), hex digests (~3.97) and UUIDs (~3.9).
ENTROPY_THRESHOLD = 4.0
#: Long tokens only need secret-ish context (not high entropy) to be redacted.
#: UUID-shaped values are exempt — they are identifiers, not secrets.
LONG_TOKEN_MIN_LEN = 32
CONTEXT_WINDOW = 80


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _char_classes(text: str) -> int:
    classes = 0
    if re.search(r"[a-z]", text) or re.search(r"[A-Z]", text):
        classes += 1
    if re.search(r"\d", text):
        classes += 1
    if re.search(r"[^A-Za-z0-9]", text):
        classes += 1
    return classes


def _has_secret_context(text: str, start: int) -> bool:
    window = text[max(0, start - CONTEXT_WINDOW):start]
    return bool(_CONTEXT_RE.search(window))


def entropy_matches(text: str) -> list[RawMatch]:
    """Find unlabeled high-entropy tokens that look like leaked secrets."""
    out: list[RawMatch] = []
    for m in _CANDIDATE_RE.finditer(text):
        cand = m.group(0)
        if _UUID_RE.match(cand):
            continue  # identifiers, not secrets
        if _char_classes(cand) < 2:
            continue  # "aaaaaaaaaaaaaaaaaaaa" is not a secret
        ctx = _has_secret_context(text, m.start())
        if shannon_entropy(cand) >= ENTROPY_THRESHOLD:
            out.append(RawMatch("ENT-SECRET", "secret", m.start(), m.end()))
        elif ctx and len(cand) >= LONG_TOKEN_MIN_LEN:
            # long structured token (e.g. 64-hex API key) next to a
            # key/token/secret keyword — redact on context, not entropy
            out.append(RawMatch("ENT-SECRET-CTX", "secret", m.start(), m.end()))
    return out


def pattern_matches(text: str) -> list[RawMatch]:
    out: list[RawMatch] = []
    for det in DETECTORS:
        group = det.get("span_group", 0)
        for m in det["pattern"].finditer(text):
            if det["validate"](m):
                out.append(
                    RawMatch(det["id"], det["category"],
                             m.start(group), m.end(group))
                )
    return out


def all_raw_matches(text: str) -> list[RawMatch]:
    return pattern_matches(text) + entropy_matches(text)
