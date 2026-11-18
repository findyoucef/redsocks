#!/usr/bin/env python3
"""Opt-in PF test: sudo python3 tests/macos_pf_test.py.

Uses an isolated child of the existing com.apple/* anchors and one benchmark
destination. It never reloads the main ruleset or edits /etc/pf.conf, and
releases its PF enable reference and removes its rules on exit.
"""

import contextlib
import os
import re
import socket
import subprocess
import sys

from native_test import proxy, receive, redirector


def pfctl(*args, rules=None):
    result = subprocess.run(["/sbin/pfctl", *args], input=rules,
                            text=True, capture_output=True, check=True)
    return result.stdout + result.stderr


def main():
    if sys.platform != "darwin" or os.geteuid() != 0:
        raise SystemExit("Run on macOS: sudo python3 tests/macos_pf_test.py")
    if 'anchor "com.apple/*"' not in pfctl("-sr"):
        raise SystemExit("The active main ruleset lacks the standard com.apple/* filter anchor; no changes made.")
    if 'rdr-anchor "com.apple/*"' not in pfctl("-sn"):
        raise SystemExit("The active main ruleset lacks the standard com.apple/* rdr anchor; no changes made.")

    anchor = f"com.apple/redsocks-test-{os.getpid()}"
    destination = "198.18.0.123"
    target_port = 18080
    token = None
    try:
        with proxy("socks5", destination=destination, destination_port=target_port) as upstream:
            with redirector(upstream, backend="pf") as (port, _):
                rules = (
                    f"rdr pass on lo0 inet proto tcp from any to {destination} port {target_port} "
                    f"-> 127.0.0.1 port {port}\n"
                    f"pass out route-to (lo0 127.0.0.1) inet proto tcp from any "
                    f"to {destination} port {target_port} user root\n"
                )
                pfctl("-a", anchor, "-nf", "-", rules=rules)
                enabled = pfctl("-E")
                match = re.search(r"Token\s*:\s*(\d+)", enabled)
                if not match:
                    raise RuntimeError(f"pfctl did not return an enable token: {enabled}")
                token = match.group(1)
                pfctl("-a", anchor, "-f", "-", rules=rules)
                with socket.create_connection((destination, target_port), timeout=5) as client:
                    payload = b"PF original-destination test\r\n"
                    client.sendall(payload)
                    if receive(client, len(payload)) != payload:
                        raise AssertionError("PF tunnel did not preserve data")
        print("PASS: PF redirected IPv4 TCP and SOCKS5 received the original destination.")
    finally:
        # Attempt every cleanup even if one pfctl invocation fails.
        for table in ("rules", "nat"):
            with contextlib.suppress(subprocess.CalledProcessError):
                pfctl("-a", anchor, "-F", table)
        if token:
            pfctl("-X", token)


if __name__ == "__main__":
    main()
