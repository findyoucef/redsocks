#!/usr/bin/env python3
"""Portable TCP regression tests; no firewall changes or root required.

Run directly (not through the legacy Python 2 pytest conftest): make check.
The generic redirector supplies the listener's address to a fake upstream
proxy, which checks the handshake and echoes tunneled bytes.
"""

import base64
import contextlib
import os
from pathlib import Path
import pwd
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import unittest


ROOT = Path(__file__).resolve().parent.parent
BINARY = Path(os.environ.get("REDSOCKS_BINARY", ROOT / "redsocks")).resolve()


def receive(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError("proxy handshake ended early")
        data += part
    return data


class Proxy(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class MissingAuthHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            headers = b""
            while not headers.endswith(b"\r\n\r\n"):
                headers += receive(self.request, 1)
                if len(headers) > 16384:
                    raise ValueError("oversized request")
            self.server.requests.append(headers)
            self.request.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                                 b"Content-Length: 0\r\n\r\n")
        except Exception as error:
            self.server.errors.append(error)


class ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(5)
        try:
            if self.server.protocol == "http-connect":
                headers = b""
                while not headers.endswith(b"\r\n\r\n"):
                    headers += receive(sock, 1)
                    if len(headers) > 16384:
                        raise ValueError("oversized CONNECT request")
                if not headers.startswith(f"CONNECT {self.server.destination}:".encode()):
                    raise ValueError("incorrect original destination")
                if self.server.destination_port is not None and not headers.startswith(
                        f"CONNECT {self.server.destination}:{self.server.destination_port} ".encode()):
                    raise ValueError("incorrect original port")
                if self.server.auth:
                    expected = b"Proxy-Authorization: Basic " + base64.b64encode(b"user:pass")
                    if expected.lower() not in headers.lower():
                        self.server.challenges += 1
                        sock.sendall(b'HTTP/1.1 407 Proxy Authentication Required\r\n'
                                     b'Proxy-Authenticate: Basic realm="test"\r\n'
                                     b'Content-Length: 0\r\n\r\n')
                        return
                sock.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            else:
                version, count = receive(sock, 2)
                methods = receive(sock, count)
                if version != 5 or 0 not in methods:
                    raise ValueError("invalid SOCKS5 greeting")
                sock.sendall(b"\x05\x00")
                if receive(sock, 4) != b"\x05\x01\x00\x01":
                    raise ValueError("invalid IPv4 SOCKS5 CONNECT")
                destination = receive(sock, 6)
                if destination[:4] != socket.inet_aton(self.server.destination):
                    raise ValueError("incorrect SOCKS5 original destination")
                if self.server.destination_port is not None and int.from_bytes(destination[4:], "big") != self.server.destination_port:
                    raise ValueError("incorrect SOCKS5 original port")
                sock.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x01")
            while True:
                data = sock.recv(65536)
                if not data:
                    break
                sock.sendall(data)
        except (EOFError, ConnectionError, socket.timeout):
            # Clients are deliberately disconnected by the pressure test.
            pass
        except Exception as error:
            self.server.errors.append(error)


@contextlib.contextmanager
def proxy(protocol="http-connect", auth=False, destination="127.0.0.1", destination_port=None):
    with Proxy(("127.0.0.1", 0), ProxyHandler) as server:
        server.protocol, server.auth = protocol, auth
        server.destination = destination
        server.destination_port = destination_port
        server.errors, server.challenges = [], 0
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join(timeout=2)
        if server.errors:
            raise AssertionError(server.errors)


def configuration(port, upstream, protocol, extra="", auth=False, backend="generic"):
    credentials = 'login = "user"; password = "pass";' if auth else ""
    return f"""base {{
        log = stderr; log_info = on; log_debug = off;
        daemon = off; redirector = {backend}; {extra}
    }}
    redsocks {{
        local_ip = 127.0.0.1; local_port = {port};
        ip = 127.0.0.1; port = {upstream}; type = {protocol};
        {credentials}
    }}
    """


@contextlib.contextmanager
def daemon(config_text):
    with tempfile.TemporaryDirectory(prefix="redsocks-test-") as tmp:
        config = Path(tmp) / "redsocks.conf"
        config.write_text(config_text)
        with (Path(tmp) / "stderr").open("w+") as log:
            process = subprocess.Popen([str(BINARY), "-c", str(config)],
                                       stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    log.seek(0)
                    output = log.read()
                    if process.poll() is not None:
                        raise AssertionError(f"redsocks exited: {output}")
                    if "redsocks started" in output:
                        break
                    time.sleep(0.02)
                else:
                    raise AssertionError("redsocks did not start")
                yield process
            except Exception:
                log.seek(0)
                print("redsocks output:\n" + log.read(), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
                log.seek(0)
                output = log.read()
            if process.returncode != 0:
                raise AssertionError(f"redsocks exit {process.returncode}: {output}")


@contextlib.contextmanager
def redirector(server, extra="", backend="generic"):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config = configuration(port, server.server_address[1], server.protocol,
                           extra, server.auth, backend)
    with daemon(config) as process:
        yield port, process


def echo(port, payload=b"tunneled bytes\r\n"):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
        client.sendall(payload)
        if receive(client, len(payload)) != payload:
            raise AssertionError("tunnel corrupted data")


class NativeTests(unittest.TestCase):
    def test_http_relay_missing_auth_header(self):
        # A malformed challenge must close the connection without logging freed
        # memory or double-freeing the status line. Repeat to check daemon health.
        with Proxy(("127.0.0.1", 0), MissingAuthHandler) as upstream:
            upstream.protocol, upstream.auth = "http-relay", True
            upstream.requests, upstream.errors = [], []
            thread = threading.Thread(target=upstream.serve_forever, daemon=True)
            thread.start()
            try:
                with redirector(upstream) as (port, process):
                    for _ in range(2):
                        with socket.create_connection(("127.0.0.1", port), timeout=3) as client:
                            client.sendall(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
                            self.assertEqual(client.recv(1024), b"")
                        self.assertIsNone(process.poll())
                    self.assertEqual(len(upstream.requests), 2)
                    self.assertEqual(upstream.errors, [])
            finally:
                upstream.shutdown()
                thread.join(timeout=3)

    def test_http_connect_crlf(self):
        # Regresses #123: HTTP CONNECT must finish with libevent 2.1 headers.
        with proxy() as upstream, redirector(upstream) as (port, process):
            echo(port)
            self.assertIsNone(process.poll())

    def test_http_basic_auth(self):
        with proxy(auth=True) as upstream, redirector(upstream) as (port, _):
            echo(port)
            self.assertGreaterEqual(upstream.challenges, 1)

    def test_socks5(self):
        with proxy("socks5") as upstream, redirector(upstream) as (port, _):
            echo(port, bytes(range(256)) * 64)

    def test_idle_pressure_recovery(self):
        # Regresses #100: the timer drops an idle client, then must reenable
        # the listener even though the timer is no longer pending.
        settings = "redsocks_conn_max = 1; connpres_idle_timeout = 1; max_accept_backoff = 50;"
        with proxy() as upstream, redirector(upstream, settings) as (port, _):
            with socket.create_connection(("127.0.0.1", port), timeout=4) as idle:
                idle.sendall(b"first")
                self.assertEqual(receive(idle, 5), b"first")
                self.assertEqual(idle.recv(1), b"")
            echo(port, b"after pressure")

    @unittest.skipIf(os.geteuid() == 0, "requires an unprivileged caller")
    def test_group_drop_failure_is_fatal(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "redsocks.conf"
            user = pwd.getpwuid(os.geteuid()).pw_name
            config.write_text(configuration(0, 1080, "socks5", f'user = "{user}";'))
            result = subprocess.run([str(BINARY), "-c", str(config)],
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("setgroups", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
