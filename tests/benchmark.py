#!/usr/bin/env python3
"""Informational TCP throughput comparison, no timing-based pass/fail threshold."""
import json
import platform
import socket
import statistics
import threading
import time

from native_test import configuration, daemon, proxy

SIZE = 32 * 1024 * 1024
BLOCK = b'x' * 65536


def transfer(port):
    with socket.create_connection(('127.0.0.1', port), timeout=15) as client:
        errors = []
        def send():
            try:
                for _ in range(SIZE // len(BLOCK)):
                    client.sendall(BLOCK)
            except Exception as error:
                errors.append(error)
        start = time.monotonic()
        sender = threading.Thread(target=send)
        sender.start()
        received = 0
        while received < SIZE:
            data = client.recv(min(65536, SIZE - received))
            if not data:
                raise RuntimeError('short benchmark response')
            if data != BLOCK[:len(data)]:
                raise RuntimeError('corrupt benchmark response')
            received += len(data)
        sender.join(timeout=15)
        if errors or sender.is_alive():
            raise RuntimeError(errors or 'sender stalled')
        return SIZE / (1024 * 1024) / (time.monotonic() - start)


results = {}
for mode in (['buffered', 'splice'] if platform.system() == 'Linux' else ['buffered']):
    with proxy('socks5') as upstream:
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        config = configuration(port, upstream.server_address[1], 'socks5')
        config = config.replace('type = socks5;', f'type = socks5; splice = {"true" if mode == "splice" else "false"};')
        with daemon(config):
            results[mode + '_MiB_per_second'] = round(statistics.median(transfer(port) for _ in range(3)), 2)
print(json.dumps({'system': platform.system(), 'machine': platform.machine(), 'bytes_per_transfer': SIZE, **results}))
