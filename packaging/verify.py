#!/usr/bin/env python3
"""Exercise extracted and installed packages on disposable CI runners only."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile

version, target = sys.argv[1:]
name = f'redsocks-{version}-{target}'
dist = Path('dist') / target
for line in (dist / f'{name}.sha256').read_text().splitlines():
    digest, filename = line.split('  ', 1)
    assert Path(filename).name == filename
    assert hashlib.sha256((dist / filename).read_bytes()).hexdigest() == digest
with tempfile.TemporaryDirectory() as temp:
    with tarfile.open(dist / f'{name}.tar.gz') as archive:
        archive.extractall(temp, filter='data')
    binary = Path(temp) / name / 'sbin/redsocks'
    assert binary.read_bytes() == Path('redsocks').read_bytes()
    subprocess.run([str(binary), '-v'], check=True)
    env = dict(os.environ, REDSOCKS_BINARY=str(binary))
    subprocess.run(['python3', 'tests/native_test.py'], env=env, check=True)
if target.startswith('macos-'):
    subprocess.run(['sudo', 'installer', '-pkg', str(dist / f'{name}.pkg'), '-target', '/'], check=True)
    installed = Path('/usr/local/sbin/redsocks')
else:
    subprocess.run(['sudo', 'dpkg', '-i', str(dist / f'{name}.deb')], check=True)
    installed = Path('/usr/sbin/redsocks')
assert installed.read_bytes() == Path('redsocks').read_bytes()
subprocess.run([str(installed), '-v'], check=True)
env = dict(os.environ, REDSOCKS_BINARY=str(installed))
for suite in ('native_test.py', 'udp_test.py', 'dns_test.py'):
    subprocess.run(['python3', 'tests/' + suite], env=env, check=True)
print('PASS: checksums, archive execution, native installation and installed binary regressions')
