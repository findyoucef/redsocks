#!/usr/bin/env python3
"""SOCKS5 UDP tests with a local protocol peer; no firewall or root needed."""

import contextlib
import select
import socket
import socketserver
import struct
import threading
import time
import unittest

from native_test import Proxy, daemon, receive


DESTINATION = ("198.18.0.123", 5353)


class AssociateHandler(socketserver.BaseRequestHandler):
    def handle(self):
        control = self.request
        control.settimeout(3)
        established = False
        try:
            version, count = receive(control, 2)
            methods = receive(control, count)
            method = 2 if self.server.auth else 0
            if version != 5 or method not in methods:
                raise ValueError("invalid SOCKS5 UDP greeting")
            control.sendall(bytes([5, method]))
            if method == 2:
                if receive(control, 1) != b"\x01":
                    raise ValueError("invalid password version")
                username = receive(control, receive(control, 1)[0])
                password = receive(control, receive(control, 1)[0])
                if (username, password) != (b"user", b"pass"):
                    raise ValueError("invalid credentials")
                control.sendall(b"\x01\x00")
            if receive(control, 4) != b"\x05\x03\x00\x01":
                raise ValueError("expected UDP ASSOCIATE")
            receive(control, 6)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
                relay.bind(("127.0.0.1", 0))
                host = "0.0.0.0" if self.server.wildcard else "127.0.0.1"
                control.sendall(b"\x05\x00\x00\x01" + socket.inet_aton(host)
                                + struct.pack("!H", relay.getsockname()[1]))
                self.server.controls.append(control)
                self.server.associations += 1
                established = True
                while not self.server.stopped.is_set():
                    readable, _, _ = select.select([control, relay], [], [], 0.1)
                    if control in readable and not control.recv(1):
                        return
                    if relay not in readable:
                        continue
                    data, client = relay.recvfrom(65535)
                    if len(data) < 10 or data[:4] != b"\x00\x00\x00\x01":
                        raise ValueError("invalid SOCKS5 UDP request")
                    target = (socket.inet_ntoa(data[4:8]), struct.unpack("!H", data[8:10])[0])
                    self.server.requests.append((target, data[10:]))
                    if self.server.malformed:
                        bad = [b"\x00", b"\x01" + data[1:10] + b"bad-reserved",
                               data[:2] + b"\x01" + data[3:10] + b"bad-fragment",
                               data[:3] + b"\x04" + data[4:10] + b"bad-type",
                               data[:4] + socket.inet_aton("198.18.0.124") + data[8:10] + b"bad-host",
                               data[:8] + struct.pack("!H", target[1] + 1) + b"bad-port"]
                        for packet in bad:
                            relay.sendto(packet, client)
                    relay.sendto(data, client)
        except (EOFError, ConnectionError, OSError):
            pass
        except Exception as error:
            self.server.errors.append(error)
        finally:
            if established:
                self.server.closed += 1


@contextlib.contextmanager
def udp_proxy(auth=False, wildcard=False, malformed=False):
    with Proxy(("127.0.0.1", 0), AssociateHandler) as server:
        server.auth, server.wildcard, server.malformed = auth, wildcard, malformed
        server.controls, server.requests, server.errors = [], [], []
        server.associations, server.closed = 0, 0
        server.stopped = threading.Event()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.stopped.set()
            server.shutdown()
            thread.join(timeout=2)
        if server.errors:
            raise AssertionError(server.errors)


@contextlib.contextmanager
def udp_redirector(server, destination=DESTINATION, backend="generic", extra="", local_tun=None):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = 0 if local_tun else reservation.getsockname()[1]
    target = (f"dest_ip = {destination[0]}; dest_port = {destination[1]};"
              if destination else "")
    credentials = 'login = "user"; password = "pass";' if server.auth else ""
    interface = f'local_tun = "{local_tun}";' if local_tun else ""
    config = f"""base {{ log = stderr; log_info = on; daemon = off; redirector = {backend}; }}
        redudp {{ local_ip = 127.0.0.1; local_port = {port};
        ip = 127.0.0.1; port = {server.server_address[1]};
        {target} {credentials} {extra} {interface} }}
    """
    with daemon(config) as process:
        yield port, process


def udp_client():
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client.settimeout(3)
    return client


def exchange(client, endpoint, payload):
    client.sendto(payload, endpoint)
    data, sender = client.recvfrom(65535)
    if data != payload or sender != endpoint:
        raise AssertionError(("UDP reply differs", data, sender, endpoint))


class UDPTests(unittest.TestCase):
    def test_binary_empty_and_repeated_datagrams(self):
        with udp_proxy() as upstream, udp_redirector(upstream) as (port, _), udp_client() as client:
            payloads = [b"", b"second", bytes(range(256)) * 32, b"last"]
            for payload in payloads:
                exchange(client, ("127.0.0.1", port), payload)
            self.assertEqual(upstream.requests, [(DESTINATION, p) for p in payloads])
            self.assertEqual(upstream.associations, 1)

    def test_password_and_wildcard_relay_address(self):
        with udp_proxy(auth=True, wildcard=True) as upstream, udp_redirector(upstream) as (port, _), udp_client() as client:
            exchange(client, ("127.0.0.1", port), b"authenticated")

    def test_malformed_replies_are_dropped(self):
        with udp_proxy(malformed=True) as upstream, udp_redirector(upstream) as (port, _), udp_client() as client:
            exchange(client, ("127.0.0.1", port), b"valid")
            client.settimeout(0.1)
            with self.assertRaises(socket.timeout):
                client.recvfrom(65535)

    def test_clients_are_isolated(self):
        with udp_proxy() as upstream, udp_redirector(upstream) as (port, _), udp_client() as first, udp_client() as second:
            first.sendto(b"first", ("127.0.0.1", port))
            second.sendto(b"second", ("127.0.0.1", port))
            self.assertEqual(first.recvfrom(64)[0], b"first")
            self.assertEqual(second.recvfrom(64)[0], b"second")
            self.assertEqual(upstream.associations, 2)

    def test_idle_association_expires_and_reopens(self):
        with udp_proxy() as upstream, udp_redirector(upstream, extra="udp_timeout = 1;") as (port, _), udp_client() as client:
            exchange(client, ("127.0.0.1", port), b"before timeout")
            deadline = time.monotonic() + 3
            while not upstream.closed and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertEqual(upstream.closed, 1)
            exchange(client, ("127.0.0.1", port), b"after timeout")
            self.assertEqual(upstream.associations, 2)

    def test_control_disconnect_recovers(self):
        with udp_proxy() as upstream, udp_redirector(upstream) as (port, _), udp_client() as client:
            endpoint = ("127.0.0.1", port)
            exchange(client, endpoint, b"before close")
            upstream.controls[0].shutdown(socket.SHUT_RDWR)
            client.settimeout(0.2)
            for _ in range(10):
                try:
                    exchange(client, endpoint, b"after close")
                    break
                except socket.timeout:
                    continue
            else:
                self.fail("UDP association did not recover from control-channel closure")
            self.assertEqual(upstream.associations, 2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
