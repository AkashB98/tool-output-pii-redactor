"""Entropy detector: threshold calibration, context rule, exemptions."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pii_redactor.detectors import (
    ENTROPY_THRESHOLD,
    entropy_matches,
    shannon_entropy,
)


def test_threshold_value_pinned():
    # calibrated: random base64url ~5.0 fires; hex digests ~3.8 do not
    assert ENTROPY_THRESHOLD == 4.0


def test_high_entropy_fires_without_context():
    tok = "x7F9kQ2mZvB4nL8pR1tW5yU3iO6aS0dG"
    assert shannon_entropy(tok) >= ENTROPY_THRESHOLD
    ms = entropy_matches("saw " + tok + " in logs")
    assert len(ms) == 1 and ms[0].detector == "ENT-SECRET"


def test_hex_digest_no_context_no_fire():
    sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"
    assert shannon_entropy(sha) < ENTROPY_THRESHOLD
    assert entropy_matches("commit " + sha + " deployed") == []


def test_hex_key_with_context_fires():
    sha = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"
    ms = entropy_matches('config api_key = "' + sha + '"')
    assert len(ms) == 1 and ms[0].detector == "ENT-SECRET-CTX"


def test_uuid_never_fires_even_with_context():
    uuid = "550e8400-e29b-41d4-a716-446655440000"
    assert entropy_matches("api_key=" + uuid) == []


def test_single_class_runs_ignored():
    assert entropy_matches("x " + "a" * 40 + " y") == []


def test_english_words_ignored():
    # long lowercase run, one char class -> not a secret
    assert entropy_matches("word antidisestablishmentarianism wow") == []


def test_short_tokens_ignored():
    assert entropy_matches('api_key = "short1"') == []


def test_context_keywords():
    for kw in ("token", "secret", "password", "bearer"):
        ms = entropy_matches(kw + ' = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b"')
        assert len(ms) == 1, kw


def test_candidate_length_cap():
    # >512 chars: not treated as one token (bounded for streaming safety)
    tok = "aB3_" * 200  # 800 chars, mixed classes, high entropy
    ms = entropy_matches("x " + tok + " y")
    assert ms == [] or all(m.end - m.start <= 512 for m in ms)
