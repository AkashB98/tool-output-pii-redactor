"""CLI: scrub / check / demo / serve / audit.

Exit codes (CI-friendly, sibling convention):
    scrub  0 always (prints redacted text to stdout)
    check  0 = clean (no findings), 1 = findings present, 2 = error
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

from .allowlist import Allowlist
from .audit import AuditLog
from .scrubber import StreamingScrubber, find_findings, scrub


def _read_input(path: str | None) -> str:
    if path:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    return sys.stdin.read()


def _make_allowlist(path: str | None) -> Allowlist:
    return Allowlist.from_file(path) if path else Allowlist.default()


def cmd_scrub(args: argparse.Namespace) -> int:
    allow = _make_allowlist(args.allowlist)
    audit = AuditLog(args.audit_log) if args.audit_log else None
    text = _read_input(args.input)
    if args.stream:
        s = StreamingScrubber(allowlist=allow, audit=audit)
        chunk = args.chunk_size
        out = []
        for i in range(0, len(text), chunk):
            out.append(s.feed(text[i:i + chunk]))
        out.append(s.flush())
        sys.stdout.write("".join(out))
    else:
        redacted, _ = scrub(text, allow, audit)
        sys.stdout.write(redacted)
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    try:
        allow = _make_allowlist(args.allowlist)
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(f"error: bad allowlist file: {exc}", file=sys.stderr)
        return 2
    try:
        text = _read_input(args.input)
    except OSError as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 2
    findings = find_findings(text, allow)
    if findings:
        print(f"{len(findings)} finding(s):", file=sys.stderr)
        for f in findings:
            print(f"  {f.detector} [{f.category}] at {f.start}:{f.end}",
                  file=sys.stderr)
        return 1
    print("clean: no findings", file=sys.stderr)
    return 0


def cmd_demo(_args: argparse.Namespace) -> int:
    # demo.py is a top-level sibling module, not part of the package
    import os, sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import demo
    demo.run()
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    ok, msg = AuditLog.verify(args.audit_log)
    print(msg)
    return 0 if ok else 2


class _Handler(BaseHTTPRequestHandler):
    allow: Allowlist = Allowlist.default()

    def log_message(self, *a):  # quiet
        pass

    def do_POST(self):  # noqa: N802
        if self.path != "/scrub":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            body = json.loads(self.rfile.read(length) or b"{}")
        except json.JSONDecodeError:
            self.send_error(400, "invalid JSON")
            return
        redacted, findings = scrub(str(body.get("text", "")), self.allow)
        payload = json.dumps({
            "redacted": redacted,
            "findings": [
                {"detector": f.detector, "category": f.category,
                 "start": f.start, "end": f.end, "redaction": f.redaction}
                for f in findings
            ],
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def cmd_serve(args: argparse.Namespace) -> int:
    _Handler.allow = _make_allowlist(args.allowlist)
    srv = HTTPServer(("127.0.0.1", args.port), _Handler)
    print(f"serving POST /scrub on 127.0.0.1:{srv.server_port}", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pii-redactor",
                                description="Scrub secrets and PII from agent "
                                            "tool outputs before they reach the model.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scrub", help="redact stdin/file to stdout")
    s.add_argument("input", nargs="?", help="input file (default: stdin)")
    s.add_argument("--allowlist", help="custom allowlist JSON file")
    s.add_argument("--audit-log", help="append redactions to hash-chained JSONL log")
    s.add_argument("--stream", action="store_true",
                   help="scrub in streaming chunks (boundary-safe)")
    s.add_argument("--chunk-size", type=int, default=64)
    s.set_defaults(func=cmd_scrub)

    c = sub.add_parser("check", help="CI gate: 0 clean, 1 findings, 2 error")
    c.add_argument("input", nargs="?", help="input file (default: stdin)")
    c.add_argument("--allowlist", help="custom allowlist JSON file")
    c.set_defaults(func=cmd_check)

    d = sub.add_parser("demo", help="run the asserted end-to-end demo")
    d.set_defaults(func=cmd_demo)

    v = sub.add_parser("serve", help="JSON API: POST /scrub")
    v.add_argument("--port", type=int, default=8077)
    v.add_argument("--allowlist", help="custom allowlist JSON file")
    v.set_defaults(func=cmd_serve)

    a = sub.add_parser("audit", help="verify a hash-chained audit log")
    a.add_argument("--verify", dest="audit_log", required=True)
    a.set_defaults(func=cmd_audit)
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
