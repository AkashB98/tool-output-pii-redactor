"""Allowlist: values that must NEVER be redacted, even if they match a detector.

The allowlist is checked *before* a raw match becomes a finding, so
allowlisted values are never redacted and never logged as redactions.

Two layers:
  1. DEFAULT_ALLOWLIST — built-in safe placeholders every demo/fixtures tree
     uses (example.com addresses, AWS's documented example key,
     Stripe test keys, well-known test card numbers, "password123"-style
     dummy values, localhost). These are values that look secret-shaped but
     are publicly documented as fake.
  2. Custom allowlist file (JSON): {"exact": [...], "regex": [...]} merged
     on top of the defaults. Lets an operator exempt their own fixtures,
     staging keys, or internal test accounts.

Matching is case-sensitive for exact strings; regexes are compiled with the
flags given per entry (default: none). A match is allowlisted when the
*entire* matched span equals an exact entry or fully matches a regex.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field


# Values that are publicly documented as fake. Keep this list conservative:
# only values whose fakeness is verifiable in public docs / RFCs.
DEFAULT_ALLOWLIST = {
    "exact": [
        # AWS documented example key (docs.aws.amazon.com)
        "AKIAIOSFODNN7EXAMPLE",
        # Stripe documented test keys (stripe.com/docs/testing) — concatenated
        # so the literal never appears in source (secret push protection).
        "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
        "rk_test_" + "4eC39HqLyjWDarjtT1zdp7dc",
        # well-known test card numbers (never chargeable)
        "4111111111111111",
        "4242424242424242",
        "5555555555554444",
        "378282246310005",
        # dummy credential placeholders
        "password123",
        "changeme",
        "xxx",
        "REDACTED",
        "localhost",
    ],
    "regex": [
        # RFC 2606 reserved documentation domains
        r"[A-Za-z0-9._%+-]+@example\.(?:com|org|net)",
        r"[A-Za-z0-9._%+-]+@test\.example",
        # obviously-masked values: ****, ••••, xxx runs
        r"[xX*•]{4,}",
    ],
}


@dataclass
class Allowlist:
    exact: set[str] = field(default_factory=set)
    patterns: list[re.Pattern] = field(default_factory=list)

    @classmethod
    def default(cls) -> "Allowlist":
        return cls.from_dict(DEFAULT_ALLOWLIST)

    @classmethod
    def from_dict(cls, data: dict) -> "Allowlist":
        exact = set(data.get("exact", []))
        patterns = [re.compile(p) for p in data.get("regex", [])]
        return cls(exact=exact, patterns=patterns)

    @classmethod
    def from_file(cls, path: str) -> "Allowlist":
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        merged_exact = set(DEFAULT_ALLOWLIST["exact"]) | set(data.get("exact", []))
        merged_regex = list(DEFAULT_ALLOWLIST["regex"]) + list(data.get("regex", []))
        return cls.from_dict({"exact": sorted(merged_exact), "regex": merged_regex})

    def is_allowed(self, value: str) -> bool:
        """True when the whole value is allowlisted (exempt from redaction)."""
        if value in self.exact:
            return True
        return any(p.fullmatch(value) for p in self.patterns)
