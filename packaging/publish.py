#!/usr/bin/env python3
"""Publish a complete, verified set of packages; never replace a public release."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

version, directory = sys.argv[1:]
if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
    raise SystemExit('Invalid release version')
tag = 'v' + version
if os.environ.get('GITHUB_REF') != 'refs/tags/' + tag:
    raise SystemExit('Publishing requires the matching version tag')
assets = Path(directory)
expected = {f'redsocks-{version}-source.tar.gz'}
for target, extension in [('linux-x86_64', 'deb'), ('macos-arm64', 'pkg'), ('macos-x86_64', 'pkg')]:
    name = f'redsocks-{version}-{target}'
    expected.update((name + '.tar.gz', name + '.' + extension))
verified = set()
for checksum in assets.glob('*.sha256'):
    for line in checksum.read_text().splitlines():
        digest, filename = line.split('  ', 1)
        if filename not in expected or hashlib.sha256((assets / filename).read_bytes()).hexdigest() != digest:
            raise SystemExit(f'Invalid package checksum: {filename}')
        verified.add(filename)
if verified != expected:
    raise SystemExit(f'Missing packages: {expected - verified}')
manifest = assets / 'SHA256SUMS'
manifest.write_text(''.join(f'{hashlib.sha256((assets / f).read_bytes()).hexdigest()}  {f}\n' for f in sorted(expected)))
notes = assets / 'release-notes.txt'
notes.write_text(f'''redsocks {version}

Packages for macOS 15+ (Apple Silicon and Intel) and Ubuntu 24.04+ (x86-64).
Libevent is linked into the binaries; no Homebrew runtime dependency is needed.
macOS installers are unsigned and are not Apple-notarized.
Installation does not start a daemon or change firewall rules.
See the included releases.md and macos.md for setup instructions.
SHA256SUMS covers every asset. Complete corresponding redsocks source is included.
''')
result = subprocess.run(['gh', 'release', 'view', tag, '--json', 'isDraft'], capture_output=True, text=True)
if result.returncode == 0:
    if not json.loads(result.stdout)['isDraft']:
        raise SystemExit('Release already published; use a new version instead of replacing assets')
else:
    subprocess.run(['gh', 'release', 'create', tag, '--verify-tag', '--draft', '--title', f'redsocks {version}', '--notes-file', str(notes)], check=True)
subprocess.run(['gh', 'release', 'upload', tag, *[str(assets / f) for f in sorted(expected)], str(manifest), '--clobber'], check=True)
subprocess.run(['gh', 'release', 'edit', tag, '--draft=false', '--latest'], check=True)
