#!/usr/bin/env python3
"""Live PF UDP test on a narrowly scoped benchmark destination range."""

import socket
import unittest

from macos_pf_test import pf_anchor, require_pf
from udp_test import exchange, udp_proxy, udp_redirector


def rules(port):
    return (
        f"rdr pass on lo0 inet proto udp from any to 198.18.0.0/24 port 18080:18081 "
        f"-> 127.0.0.1 port {port}\n"
        "pass out route-to (lo0 127.0.0.1) inet proto udp from any "
        "to 198.18.0.0/24 port 18080:18081 user root\n"
    )


def client():
    result = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    result.bind(("0.0.0.0", 0))
    result.settimeout(4)
    return result


class PFUDPTests(unittest.TestCase):
    def test_fixed_destination(self):
        destination = ("198.18.0.123", 18080)
        with udp_proxy(auth=True) as upstream, udp_redirector(upstream, destination, "pf") as (port, _):
            with pf_anchor(rules(port)), client() as app:
                app.connect(destination)
                for payload in [b"fixed target", b"", bytes(range(256)) * 32]:
                    app.send(payload)
                    data, sender = app.recvfrom(65535)
                    self.assertEqual((data, sender), (payload, destination))
            self.assertEqual(len(upstream.requests), 3)
            self.assertTrue(all(target == destination for target, _ in upstream.requests))

    def test_one_socket_multiple_destinations(self):
        destinations = [("198.18.0.123", 18080), ("198.18.0.124", 18080), ("198.18.0.123", 18081)]
        with udp_proxy() as upstream, udp_redirector(upstream, None, "pf") as (port, _):
            with pf_anchor(rules(port)), client() as app:
                for wave in range(2):
                    expected = {f"{wave}:{index}".encode(): target for index, target in enumerate(destinations)}
                    for payload, target in expected.items():
                        app.sendto(payload, target)
                    observed = {}
                    for _ in expected:
                        payload, sender = app.recvfrom(65535)
                        observed[payload] = sender
                    self.assertEqual(observed, expected)
            self.assertEqual(upstream.associations, len(destinations))

    def test_two_clients(self):
        target = ("198.18.0.123", 18080)
        with udp_proxy() as upstream, udp_redirector(upstream, None, "pf") as (port, _):
            with pf_anchor(rules(port)), client() as first, client() as second:
                exchange(first, target, b"client one")
                exchange(second, target, b"client two")
            self.assertEqual(upstream.associations, 2)


if __name__ == "__main__":
    require_pf()
    unittest.main(verbosity=2)
