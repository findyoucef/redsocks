#!/usr/bin/env python3
"""Validate release gating without credentials or network mutations."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parent.parent / 'packaging/publish.py'


class PublishTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.assets = Path(self.temp.name)
        self.files = ['redsocks-1.2.3-source.tar.gz']
        for target, extension in [('linux-x86_64', 'deb'), ('macos-arm64', 'pkg'), ('macos-x86_64', 'pkg')]:
            self.files += [f'redsocks-1.2.3-{target}.tar.gz', f'redsocks-1.2.3-{target}.{extension}']
        lines = []
        for name in self.files:
            data = name.encode()
            (self.assets / name).write_bytes(data)
            lines.append(f'{hashlib.sha256(data).hexdigest()}  {name}\n')
        (self.assets / 'packages.sha256').write_text(''.join(lines))

    def execute(self, exists=False, draft=False, ref='refs/tags/v1.2.3'):
        commands = []
        def gh(args, **kwargs):
            commands.append(args)
            return subprocess.CompletedProcess(args, 0 if exists else 1,
                                               stdout=json.dumps({'isDraft': draft}))
        with patch.dict(os.environ, {'GITHUB_REF': ref}), patch.object(sys, 'argv', [str(SCRIPT), '1.2.3', str(self.assets)]), patch('subprocess.run', side_effect=gh):
            runpy.run_path(str(SCRIPT), run_name='__main__')
        return commands

    def test_complete_release_publishes_only_after_upload(self):
        commands = self.execute()
        self.assertEqual([c[2] for c in commands], ['view', 'create', 'upload', 'edit'])
        self.assertIn('--draft', commands[1])
        self.assertIn('--draft=false', commands[-1])
        self.assertEqual(len((self.assets / 'SHA256SUMS').read_text().splitlines()), 7)

    def test_existing_draft_can_resume(self):
        self.assertEqual([c[2] for c in self.execute(exists=True, draft=True)], ['view', 'upload', 'edit'])

    def test_public_release_is_never_replaced(self):
        with self.assertRaisesRegex(SystemExit, 'already published'):
            self.execute(exists=True)

    def test_corrupt_asset_is_rejected(self):
        (self.assets / self.files[0]).write_bytes(b'corrupt')
        with self.assertRaisesRegex(SystemExit, 'Invalid package checksum'):
            self.execute()

    def test_missing_target_is_rejected(self):
        checksum = self.assets / 'packages.sha256'
        checksum.write_text(''.join(checksum.read_text().splitlines(keepends=True)[:-1]))
        with self.assertRaisesRegex(SystemExit, 'Missing packages'):
            self.execute()

    def test_branch_cannot_publish(self):
        with self.assertRaisesRegex(SystemExit, 'matching version tag'):
            self.execute(ref='refs/heads/main')


if __name__ == '__main__':
    unittest.main(verbosity=2)
