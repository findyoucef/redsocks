#!/usr/bin/env python3
"""Build, test and package the current commit; no installation or publishing."""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parent.parent
os.chdir(ROOT)
version = sys.argv[1] if len(sys.argv) == 2 else ''
if not re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version):
    raise SystemExit('Usage: python3 packaging/build.py X.Y.Z')


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def output(*args):
    return subprocess.check_output(args, text=True).strip()


run('git', 'diff', '--quiet', 'HEAD')
mac = sys.platform == 'darwin'
arch = platform.machine()
if (mac and arch not in ('arm64', 'x86_64')) or (not mac and (sys.platform != 'linux' or arch != 'x86_64')):
    raise SystemExit('Supported targets: macOS arm64/x86_64 and Linux x86_64')
target = ('macos-' if mac else 'linux-') + arch
name = f'redsocks-{version}-{target}'
dist = ROOT / 'dist' / target
dist.mkdir(parents=True, exist_ok=True)
if any(dist.iterdir()):
    raise SystemExit(f'{dist} must be empty; choose a fresh build checkout')
libdir = Path(output('pkg-config', '--variable=libdir', 'libevent_core'))
libevent = libdir / 'libevent_core.a'
if not libevent.is_file():
    raise SystemExit(f'Missing static archive: {libevent}')
env = dict(os.environ)
if mac:
    env['MACOSX_DEPLOYMENT_TARGET'] = '15.0'
run('make', 'clean')
makeargs = ['CC=clang' if mac else 'CC=gcc', f'LIBS={libevent}', f'RELEASE_VERSION={version}']
if mac:
    makeargs.append('LDFLAGS=-Wl,-fatal_warnings')
run('make', '-j2', *makeargs, env=env)
run('make', 'check', *makeargs, env=env)
if mac:
    dependencies = output('otool', '-L', 'redsocks')
    for line in dependencies.splitlines()[1:]:
        if not line.strip().startswith(('/usr/lib/', '/System/Library/')):
            raise SystemExit(f'Non-system dynamic dependency: {line}')
    run('codesign', '--force', '--sign', '-', 'redsocks')
    run('codesign', '--verify', '--strict', 'redsocks')
else:
    dependencies = output('ldd', 'redsocks')
    if 'libevent' in dependencies or 'not found' in dependencies:
        raise SystemExit(dependencies)
run('./redsocks', '-v')

with tempfile.TemporaryDirectory(prefix='redsocks-package-') as temporary:
    temp = Path(temporary)
    tree = temp / name
    (tree / 'sbin').mkdir(parents=True)
    shutil.copy2(ROOT / 'redsocks', tree / 'sbin/redsocks')
    docs = tree / 'share/doc/redsocks'
    docs.mkdir(parents=True)
    for file in ('README.md', 'doc/macos.md', 'doc/releases.md', 'packaging/NOTICE'):
        shutil.copy2(ROOT / file, docs / Path(file).name)
    shutil.copytree(ROOT / 'examples', docs / 'examples')
    shutil.copy2(ROOT / 'redsocks.conf.example', docs / 'examples/redsocks.conf.example')
    shutil.copytree(ROOT / 'packaging/licenses', docs / 'licenses')
    license_path = Path(output('brew', '--prefix', 'libevent')) / 'LICENSE' if mac else Path('/usr/share/doc/libevent-dev/copyright')
    shutil.copy2(license_path, docs / 'licenses/libevent.txt')
    source = docs / f'redsocks-{version}-source.tar.gz'
    run('git', 'archive', '--format=tar.gz', f'--prefix=redsocks-{version}/', '-o', str(source), 'HEAD')
    (docs / 'BUILD.json').write_text(json.dumps({
        'version': version, 'commit': output('git', 'rev-parse', 'HEAD'),
        'target': target, 'libevent': output('pkg-config', '--modversion', 'libevent_core'),
        'compiler': output('clang' if mac else 'gcc', '--version').splitlines()[0],
        'dependencies': dependencies,
    }, indent=2) + '\n')
    with tarfile.open(dist / f'{name}.tar.gz', 'w:gz') as archive:
        archive.add(tree, arcname=name)
    root = temp / 'root'
    prefix = root / ('usr/local' if mac else 'usr')
    shutil.copytree(tree, prefix)
    if mac:
        component = temp / 'component.pkg'
        run('pkgbuild', '--root', str(root), '--identifier', 'io.github.findyoucef.redsocks',
            '--version', version, '--install-location', '/', '--ownership', 'recommended', str(component))
        distribution = temp / 'distribution.xml'
        distribution.write_text(f'''<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
<title>redsocks {version}</title>
<options customize="never" hostArchitectures="{arch}" require-scripts="false"/>
<allowed-os-versions><os-version min="15.0"/></allowed-os-versions>
<choices-outline><line choice="default"/></choices-outline>
<choice id="default" visible="false"><pkg-ref id="io.github.findyoucef.redsocks"/></choice>
<pkg-ref id="io.github.findyoucef.redsocks" version="{version}">component.pkg</pkg-ref>
</installer-gui-script>
''')
        run('productbuild', '--distribution', str(distribution), '--package-path', str(temp), str(dist / f'{name}.pkg'))
    else:
        control = root / 'DEBIAN'
        control.mkdir()
        # Build-host minimum is explicit: release binaries target Ubuntu 24.04+.
        (control / 'control').write_text(f'''Package: redsocks
Version: {version}
Architecture: amd64
Maintainer: findyoucef <findyoucef@users.noreply.github.com>
Depends: libc6 (>= 2.39)
Section: net
Priority: optional
Homepage: https://github.com/findyoucef/redsocks
Description: Transparent IPv4 TCP and UDP proxy redirector
 Includes SOCKS and HTTP CONNECT support and DNS helpers.
''')
        run('dpkg-deb', '--root-owner-group', '--build', str(root), str(dist / f'{name}.deb'))
        shutil.copy2(source, dist / source.name)
    checksums = []
    for asset in sorted(dist.iterdir()):
        checksums.append(f'{hashlib.sha256(asset.read_bytes()).hexdigest()}  {asset.name}\n')
    (dist / f'{name}.sha256').write_text(''.join(checksums))
print(f'Packages ready in {dist}')
