import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from observer.__main__ import main
from observer import config
from tools.guest_check import protected, platform

ROOT = Path(__file__).resolve().parents[1]


class DeploymentTests(unittest.TestCase):
    def test_path_protection_refuses_links_writable_files_and_wrong_owner(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plain = root / 'plain'; plain.write_text('sentinel'); plain.chmod(0o600)
            protected(plain, uid=os.getuid(), private=True)
            with self.assertRaises(ValueError): protected(plain, uid=os.getuid()+1)
            plain.chmod(0o666)
            with self.assertRaises(ValueError): protected(plain, uid=os.getuid())
            plain.chmod(0o600)
            link = root / 'link'; link.symlink_to(plain)
            with self.assertRaises(ValueError): protected(link, uid=os.getuid())
            link.unlink(); link.symlink_to(root / 'missing')
            with self.assertRaises(ValueError): protected(link, uid=os.getuid())
            link.unlink(); os.link(plain, link)
            with self.assertRaises(ValueError): protected(plain, uid=os.getuid())
            self.assertEqual(plain.read_text(), 'sentinel')

    def test_platform_refuses_privileged_uid_map(self):
        from types import SimpleNamespace
        def read(path, *args, **kwargs):
            return 'ID=debian\nVERSION_ID="12"\n' if str(path) == '/etc/os-release' else '0 0 4294967295\n'
        with patch('tools.guest_check.os.geteuid', return_value=0), patch.object(Path, 'read_text', read), \
                patch.object(Path, 'is_dir', return_value=True), \
                patch('tools.guest_check.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=b'lxc\n')):
            with self.assertRaises(ValueError): platform()
        with patch('tools.guest_check.os.geteuid', return_value=0), patch.object(Path, 'read_text',
                lambda p: 'ID=debian\nVERSION_ID="12"\n' if str(p) == '/etc/os-release' else '0 100000 65536\n'), \
                patch.object(Path, 'is_dir', return_value=True), \
                patch('tools.guest_check.subprocess.run', return_value=SimpleNamespace(returncode=0, stdout=b'lxc\n')):
            platform()

    def test_sandbox_preflight_works_before_activation_without_network(self):
        cfg = config.load(ROOT / 'config.example.json')
        self.assertFalse(cfg['enabled'])
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config'; path.write_text(json.dumps(cfg)); path.chmod(0o600)
            token = Path(directory) / 'provider_token'; token.write_text('synthetic-token'); token.chmod(0o600)
            with patch.dict(os.environ, {'CREDENTIALS_DIRECTORY': directory}), \
                    patch('observer.__main__.os.geteuid', return_value=1000), \
                    patch('observer.__main__.cycle', side_effect=AssertionError('network')), \
                    patch('observer.runner.clock_trusted', return_value=True), redirect_stdout(io.StringIO()) as output:
                self.assertEqual(main(['--config', str(path), '--state-dir', directory, '--preflight']), 0)
                self.assertEqual(json.loads(output.getvalue())['network_requests'], 0)

    def test_strict_acceptance_exit_refuses_unhealthy_successful_cycle(self):
        cfg = config.load(ROOT / 'config.example.json'); cfg['enabled'] = cfg['provider']['contract_verified'] = True
        evidence = {'schema': 1, 'clock_trusted': True, 'provider_heartbeat': True, 'spool_events': 0,
                    'spool_dropped': 0, 'outcomes': {'wan_edge': False, 'edge_exposure': None, 'private_queue': None},
                    'incidents': {'wan_edge': False}}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config'; path.write_text(json.dumps(cfg)); path.chmod(0o600)
            token = Path(directory) / 'provider_token'; token.write_text('synthetic-token'); token.chmod(0o600)
            with patch.dict(os.environ, {'CREDENTIALS_DIRECTORY': directory}), \
                    patch('observer.__main__.os.geteuid', return_value=1000), \
                    patch('observer.__main__.cycle', return_value=evidence), redirect_stdout(io.StringIO()):
                args = ['--config', str(path), '--state-dir', directory, '--live']
                self.assertEqual(main(args), 0)  # Ordinary monitoring still records outages.
                self.assertEqual(main(args + ['--require-healthy']), 2)
