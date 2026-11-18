#!/usr/bin/env python3
"""Portable DNS/UDP to TCP framing, multiplexing and reconnect regressions."""
import contextlib
import socket
import socketserver
import struct
import threading
import time
import unittest

from native_test import Proxy, daemon, receive


def query(identifier, padding=0):
    return struct.pack('!HHHHHH', identifier, 0x100, 1, 0, 0, 0) + b'\x00\x00\x06\x00\x01' + b'x' * padding


def response(packet):
    return packet[:2] + b'\x81\x80' + packet[4:]


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        self.server.connections += 1
        try:
            batch = []
            while True:
                length, = struct.unpack('!H', receive(self.request, 2))
                packet = receive(self.request, length)
                batch.append(response(packet))
                self.server.requests.append(packet)
                if len(batch) < self.server.batch:
                    continue
                wire = b''.join(struct.pack('!H', len(p)) + p for p in reversed(batch))
                # Split a length prefix and a DNS header across writes.
                for part in (wire[:1], wire[1:5], wire[5:]):
                    self.request.sendall(part)
                    time.sleep(0.01)
                batch.clear()
                if self.server.disconnect:
                    return
        except (EOFError, OSError):
            pass


@contextlib.contextmanager
def resolver(batch=1, disconnect=False, limit=16, timeout=2):
    with Proxy(('127.0.0.1', 0), DNSHandler) as server:
        server.batch, server.disconnect = batch, disconnect
        server.connections, server.requests = 0, []
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        config = f'''base {{ log = stderr; log_info = on; daemon = off; redirector = generic; }}
        dnsu2t {{ local_ip = 127.0.0.1; local_port = {port};
        remote_ip = 127.0.0.1; remote_port = {server.server_address[1]};
        remote_timeout = {timeout}; inflight_max = {limit}; }}
'''
        try:
            with daemon(config), socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
                client.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 131072)
                client.settimeout(4)
                client.connect(('127.0.0.1', port))
                yield client, server
        finally:
            server.shutdown()
            thread.join()


class DNSTests(unittest.TestCase):
    def test_pipelined_out_of_order_and_partial_frames(self):
        with resolver(batch=3) as (client, server):
            packets = [query(i, 60000 if i == 2 else 0) for i in range(1, 4)]
            for packet in packets:
                client.send(packet)
            self.assertEqual([client.recv(65535) for _ in packets], [response(p) for p in reversed(packets)])
            self.assertEqual(server.connections, 1)
            self.assertEqual(server.requests, packets)

    def test_reconnect_after_eof(self):
        with resolver(disconnect=True) as (client, server):
            for i in range(3):
                packet = query(i)
                client.send(packet)
                self.assertEqual(client.recv(65535), response(packet))
                time.sleep(0.1)
            self.assertEqual(server.connections, 3)

    def test_limit_reenables_listener(self):
        with resolver(limit=1) as (client, server):
            packets = [query(i) for i in range(5)]
            for packet in packets:
                client.send(packet)
            self.assertEqual([client.recv(65535) for _ in packets], [response(p) for p in packets])

    def test_timeout_reconnect_and_invalid_queries(self):
        with resolver(timeout=1) as (client, server):
            client.send(b'bad')
            client.send(response(query(99)))
            for i in range(2):
                client.send(query(i))
                self.assertEqual(client.recv(65535), response(query(i)))
                time.sleep(1.2)
            self.assertEqual(server.requests, [query(0), query(1)])
            self.assertEqual(server.connections, 2)


if __name__ == '__main__':
    unittest.main(verbosity=2)
