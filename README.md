# tool-output-pii-redactor

A **PII redactor for agent tool outputs** — the last-mile privacy layer that
scrubs secrets out of what your agent shows, logs, and streams.

Tool calls return messy real-world text: API keys in error messages, customer
emails in search results, SSNs in support transcripts. This package finds and
redacts them *before* they hit a log file, a UI, or a model context:

- **detectors** — email, phone, SSN, credit card, API keys / secrets, including
  entropy-based detection for high-entropy tokens
- **scrubber** — one-shot `scrub()` plus a `StreamingScrubber` for
  token-by-token redaction on live streams (byte-identical to one-shot)
- **allowlist** — per-category exceptions so legitimate values (your own
  support number, documented test keys) survive redaction
- **audit** — every redaction lands in a **hash-chained audit log**, so a
  tampered history is detectable (`audit --verify`)

## Why this exists (the hiring signal)

Every team shipping agents to customers hits the same compliance wall: the
agent works, but legal won't let tool outputs touch logs, dashboards, or
retraining pipelines while they might contain customer PII. The
prompt-injection firewall blocks *attacks* at runtime; the approval gate stops
*dangerous calls*; this redactor is the third leg: **even a perfectly-behaved
agent can't leak what it never emits.** Drop it between the tool executor and
everything downstream — logs, UI, evals, fine-tuning data.

Pairs with the sibling builds: lint the schemas first (`tool-schema-linter`),
pin behavior in CI (`tool-call-trace-replay`), validate outputs
(`structured-output-validator`), gate the dangerous calls
(`tool-approval-gate`), and scrub the PII here.

## Quickstart

```bash
python3 demo.py                          # asserted end-to-end demo
python3 -m pii_redactor scrub < trace.jsonl
python3 -m pii_redactor check trace.jsonl   # CI gate: 0 clean, 1 findings, 2 error
python3 -m pii_redactor serve --port 8472   # JSON API: POST /scrub
python3 -m pii_redactor audit --verify audit.log
```

Or as a library:

```python
from pii_redactor import scrub

redacted, findings = scrub(tool_output_text)
for f in findings:
    print(f.category, f.span)   # email, phone, ssn, card, secret, credentials
```

## Layout

- `pii_redactor/` — detectors, scrubber, streaming scrubber, allowlist,
  hash-chained audit log, CLI
- `fixtures/` — sample tool traces, including false-positive traps
- `tests/` — full suite, 71/71 (`python3 tests/run_tests.py`), incl. a
  no-network test
- `evals/` — golden eval cases + report

## Notes

- All fixtures use fictional PII (`.test` domains, 555 numbers,
  `sk_live_51FictionalKeyValue99`) — safe to run anywhere.
- Stdlib only. No network calls.
