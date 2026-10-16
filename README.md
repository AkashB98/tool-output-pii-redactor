# tool-output-pii-redactor

The egress filter every agent team ships: a streaming scrubber that redacts
secrets and PII from agent **tool outputs** before they reach the model.

The portfolio story so far: the red-teaming harness *grades* safety under
attack, the prompt-injection firewall *blocks* attacks inbound at runtime,
the approval gate *holds* dangerous actions for a human. This is the fourth
wall — **scrub the leaks outbound**. Tool outputs are where secrets
actually escape: a `crm.get_customer` call returns a real email, a
`deploy.get_env` call returns a real AWS key, and that text goes straight
into the model's **context window** — the working memory the model reads
while it thinks — and from there into logs, traces, and eval datasets.
This scrubber sits between the tool and the model and redacts first.

## Quickstart

```bash
# one-shot: stdin -> stdout
echo 'mail priya.sharma@helioshome.test' | python -m pii_redactor scrub
# -> mail [REDACTED:email]

# CI gate: exit 0 clean, 1 findings, 2 error
python -m pii_redactor check fixtures/tool_trace.jsonl

# streaming (chunk-boundary safe, see below)
python -m pii_redactor scrub --stream --chunk-size 64 transcript.jsonl

# JSON API
python -m pii_redactor serve --port 8077
curl -X POST localhost:8077/scrub -d '{"text":"card 4532015112830366"}'
# -> {"redacted":"card [REDACTED:card]","findings":[...]}

# asserted end-to-end demo
python demo.py
```

Or as a library:

```python
from pii_redactor import scrub

redacted, findings = scrub(tool_output_text)
for f in findings:
    print(f.detector, f.category, f.start, f.end)
```

## What it detects

| Detector | Catches | Smarts |
|---|---|---|
| `PAT-EMAIL` / `PAT-PHONE` / `PAT-SSN` | emails, US/international phones, SSNs | phone requires separators/parens (bare 10-digit order numbers don't match); SSN validates area/group/serial rules (`000-00-0000` never fires) |
| `PAT-CARD` | 13–19 digit card numbers | **Luhn check** — the checksum algorithm printed on every real card; random digit runs fail it and are left alone |
| `PAT-AWS-KEY` / `PAT-GITHUB-TOKEN` / `PAT-STRIPE-KEY` | `AKIA…`, `ghp_…`, `sk_live_…` | provider-shaped prefixes |
| `PAT-JWT` / `PAT-URL-CREDS` | `eyJ…` tokens, `https://user:pass@host` | URL redacts only the `user:pass` part — scheme and host stay readable |
| `PAT-PRIVATE-KEY` | `-----BEGIN … PRIVATE KEY-----` blocks | multiline, DOTALL |
| `ENT-SECRET` / `ENT-SECRET-CTX` | unlabeled high-**entropy** tokens — *entropy* is randomness-per-character; random secrets score high, English scores low | fires on shape alone at ≥ 4.0 bits/char, or on secret-ish context (`api_key = "…"`); UUIDs and git SHAs are exempt |

Overlap resolution is **specificity-first**: a URL-credentials match beats the
email-shaped phantom inside it (`s3cr3t@db.internal`), a JWT beats an entropy
sub-match, a Luhn-valid card beats a phone-shaped substring.

## Allowlist-safe by design

The allowlist is checked *before* a match becomes a finding, so exempt values
are never redacted and never logged. Built-in defaults cover publicly
documented fakes (RFC 2606 `example.com`, AWS's documented example key,
Stripe test keys, well-known test card numbers, `password123`-style dummies).
Operators merge their own via JSON:

```json
{"exact": ["staging-db@helioshome.test"], "regex": ["test-[a-z]+@example\\.com"]}
```

## Streaming without leaks

`StreamingScrubber.feed(chunk)` / `.flush()` is **byte-identical** to the
one-shot `scrub()` for *any* chunking — pinned by tests that split fixtures
at every 32nd byte and inside every secret, down to 1-byte chunks. Four
mechanisms make that true:

1. **SPAN safe-cut** — every detector only matches characters from a known
   set; emission stops at the last character outside it, so no match (whole
   or partial) is ever split by an emission boundary.
2. **Finding-aware cut-back** — after detection, the cut retreats to the
   start of any real finding that would span it.
3. **Dangling-BEGIN hold** — a private-key `BEGIN` without its `END` yet
   holds emission at the `BEGIN`, so a key split across chunks is never
   half-emitted. (The private key is the only unbounded detector.)
4. **Context carry** — the entropy detector's 80-char lookback sees the true
   preceding text across feed boundaries.

The lag window (768 chars) exceeds the longest bounded match (512) plus the
context lookback, so an incomplete secret can never reach back into
already-emitted text.

## Audit log

Every redaction appends a **hash-chained** JSONL entry — each entry's
fingerprint covers the previous entry's, so deleting or editing an entry
breaks the chain — with `seq`, timestamp, detector, category, `span_sha256`,
and `span_len`. The log stores the SHA-256 of the removed span, never the
span itself: proof of *what* was removed without retaining the secret.
`pii-redactor audit --verify log.jsonl` checks the chain. Same chaining
discipline as the sibling `tool-approval-gate`.

## Evals

```
python evals/run_evals.py   # 7/7 golden evals; eval_report.json committed
python tests/run_tests.py   # 71/71 hermetic unit tests (stdlib only)
```

Golden evals pin exact findings per fixture (detector, category, span),
zero-findings on 11 false-positive traps, redacted-output md5s, streaming
determinism across chunk sizes 1/7/64/1000, custom-allowlist behavior, and
the audit chain. `eval_report.json` is byte-identical across runs
(md5 `e41a6e3c084bc7797155167b35f1124b` × 3) — determinism is itself an eval.

## Dev loop: bugs the tests caught

1. **Variable-width lookbehind** — the URL-credentials pattern used
   `(?<=scheme://)` with a variable-length scheme; Python's `re` rejects it
   at compile time. Fixed with a capture group + explicit span selection.
2. **Phone missed `(214) 555-0182`** — the area-code branch didn't allow the
   space after `)`. Fixed; the bare-10-digits rejection still holds.
3. **Card span swallowed a trailing space** — `(?:\d[ \-. ]?){13,19}` could
   end on a separator, so `4111111111111111 ` (test card + space) missed the
   exact allowlist entry and fired. The pattern now starts and ends on a
   digit; edge separators never join the span.
4. **Streaming leaked split secrets** — the first streaming design scrubbed
   each emitted prefix standalone, so an entropy token's `api_key =` context
   (already emitted) was invisible and a private-key block split at a JSON
   `\n` escape diverged from one-shot. Rebuilt around the four mechanisms
   above; the 1-byte-chunk grid test pins it.
5. **Email phantom inside URLs** — `s3cr3t@db.internal` outscored the
   URL-credentials match on length. Overlap resolution is now
   specificity-first; the userinfo redaction keeps the URL readable.
6. **Demo miscounted its own secrets** — asserted 6 `[REDACTED:secret]`
   where the fixture has 5. The demo now counts from the findings list.

## Limitations (honest)

- Heuristic, not exhaustive: no IP/hostname detector (too FP-prone without
  an org's network map); non-US PII formats are out of scope.
- The entropy threshold (4.0 bits/char) is calibrated, not universal —
  `tests/test_entropy.py` pins the calibration samples.
- UUID-shaped values are assumed to be identifiers, never secrets.
- An *unterminated* private-key block (BEGIN, no END) is emitted as-is at
  flush; paranoid mode (redact on BEGIN) is a documented non-goal.
- All fixtures are fictional Helios Home/Cloud sample data. No real secrets,
  no personal data, stdlib only, no network.
