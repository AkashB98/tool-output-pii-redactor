"""Allowlist: defaults, custom files, merge semantics."""

import json
import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pii_redactor.allowlist import Allowlist
from pii_redactor import find_findings


def test_default_allowlists_documented_fakes():
    a = Allowlist.default()
    assert a.is_allowed("AKIAIOSFODNN7EXAMPLE")
    assert a.is_allowed("sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc")
    assert a.is_allowed("4111111111111111")
    assert a.is_allowed("support@example.com")
    assert a.is_allowed("*****")


def test_default_does_not_allow_real_shaped_values():
    a = Allowlist.default()
    assert not a.is_allowed("AKIAW3X9Q2K7M4N6P1AB")
    assert not a.is_allowed("sk_live_51FictionalKeyValue99")
    assert not a.is_allowed("priya.sharma@helioshome.test")


def test_custom_file_merges_with_defaults():
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"exact": ["STAGING-KEY-99"],
                   "regex": [r"staging-[a-z]+@helioshome\.test"]}, fh)
        path = fh.name
    a = Allowlist.from_file(path)
    assert a.is_allowed("STAGING-KEY-99")          # custom exact
    assert a.is_allowed("staging-db@helioshome.test")  # custom regex
    assert a.is_allowed("AKIAIOSFODNN7EXAMPLE")    # defaults still apply
    os.unlink(path)


def test_allowlist_applied_before_redaction():
    text = "use AKIAIOSFODNN7EXAMPLE in the tutorial"
    assert find_findings(text) == []


def test_custom_allowlist_exempts_matching_span():
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
        json.dump({"exact": ["ops@helioshome.test"], "regex": []}, fh)
        path = fh.name
    a = Allowlist.from_file(path)
    assert find_findings("mail ops@helioshome.test", a) == []
    # ...but other values still fire
    assert len(find_findings("mail ops@helioshome.test and a@b.co", a)) == 1
    os.unlink(path)


def test_allowlist_is_case_sensitive():
    a = Allowlist.default()
    assert not a.is_allowed("akiaiosfodnn7example")
