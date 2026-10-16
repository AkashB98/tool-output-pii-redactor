"""No-network guard: the package must never touch the network.

Same discipline as every sibling build: stub out socket at import and
fail any test that triggers a real connection.
"""

import sys
import os
import socket

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


class _GuardedSocket(socket.socket):
    def connect(self, *a, **k):
        raise AssertionError("network access attempted in hermetic test")


def test_no_network_import_and_scrub():
    real = socket.socket
    socket.socket = _GuardedSocket
    try:
        for mod in [m for m in list(sys.modules) if m.startswith("pii_redactor")]:
            del sys.modules[mod]
        from pii_redactor import scrub, StreamingScrubber
        text = open(os.path.join(os.path.dirname(__file__), "..",
                                 "fixtures", "tool_trace.jsonl")).read()
        scrub(text)
        s = StreamingScrubber()
        for i in range(0, len(text), 64):
            s.feed(text[i:i + 64])
        s.flush()
    finally:
        socket.socket = real
