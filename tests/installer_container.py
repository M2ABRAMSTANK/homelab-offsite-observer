"""Disposable Debian Docker test: real Ansible/filesystem, simulated init only.

Run with /source read-only and no network. Never run on an operator machine.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess

assert Path('/.dockerenv').exists(), 'disposable Docker container required'
assert not Path('/opt/offsite-observer').exists(), 'fresh fixture required'
root = Path('/tmp/source')
shutil.copytree('/source', root, ignore=shutil.ignore_patterns('.git', '__pycache__'))
os.chdir(root)
__import__("sys").path.insert(0, str(root))
os.environ['ANSIBLE_CONFIG'] = str(root / 'deploy/ansible.cfg')
os.environ['ANSIBLE_LOCAL_TEMP'] = '/tmp/ansible-local'
base = ['ansible-playbook', '-i', 'deploy/inventory.local.yml', 'deploy/install.yml']

def run(extra=(), success=True):
    result = subprocess.run(base + list(extra), capture_output=True, text=True)
    # Only synthetic inputs exist in this disposable fixture.
    Path('/tmp/last-installer.log').write_text(result.stdout + result.stderr)
    if (result.returncode == 0) != success:
        print(result.stdout, result.stderr)
        raise AssertionError('unexpected installer result')
    return result.stdout

run(success=False)  # Docker must be refused as a production target.
assert not Path('/opt/offsite-observer').exists()
print('PASS: production guard refuses Docker before install')
# Replace ONLY the guest platform probe in the temporary fixture copy. All path,
# user/group, config and Ansible installation behavior remains the real source.
probe = root / 'tools/guest_check.py'
probe.write_text(probe.read_text().replace('                platform()', '                pass  # disposable fixture only'))
shutil.copy2(root / 'tests/fake_systemctl.py', '/usr/bin/systemctl')
os.chmod('/usr/bin/systemctl', 0o755)
run()
print('PASS: disabled install completes with real Debian Ansible and filesystem')
assert Path('/etc/offsite-observer/config.json').stat().st_mode & 0o777 == 0o600
assert Path('/etc/offsite-observer').stat().st_mode & 0o777 == 0o700
cfg = Path('/etc/offsite-observer/config.json')
config = json.loads(cfg.read_text()); config['observer_id'] = 'preserved'
cfg.write_text(json.dumps(config))
uid = __import__('pwd').getpwnam('offsite-observer').pw_uid
gid = __import__('pwd').getpwnam('offsite-observer').pw_gid
state = Path('/var/lib/offsite-observer'); state.mkdir(mode=0o700); os.chown(state, uid, gid)
from observer import state as state_module
state_module.write(state, state_module.empty())
os.chown(state / 'state.json', uid, gid)
before = (state / 'state.json').read_bytes()
output = run()
assert 'changed=0' in output, output
assert json.loads(cfg.read_text())['observer_id'] == 'preserved'
assert (state / 'state.json').read_bytes() == before
print('PASS: repeat install changes zero tasks and preserves config/state')
subprocess.run(['systemctl', 'start', 'offsite-observer.timer'], check=True)
run(success=False)
assert json.loads(Path('/run/fake-systemctl.json').read_text())['offsite-observer.timer']['ActiveState'] == 'active'
run(['-e', '{"observer_stop_for_update":true}'])
assert json.loads(Path('/run/fake-systemctl.json').read_text())['offsite-observer.timer']['ActiveState'] == 'inactive'
print('PASS: active update refused; explicit update stops timer')
data = json.loads(Path('/run/fake-systemctl.json').read_text())
data.setdefault('offsite-observer.service', {'LoadState':'loaded','UnitFileState':'disabled','SubState':'start'})['ActiveState'] = 'activating'
Path('/run/fake-systemctl.json').write_text(json.dumps(data))
run(success=False)
assert json.loads(Path('/run/fake-systemctl.json').read_text())['offsite-observer.service']['ActiveState'] == 'activating'
data['offsite-observer.service']['ActiveState'] = 'inactive'
Path('/run/fake-systemctl.json').write_text(json.dumps(data))
print('PASS: activating oneshot worker requires update consent')
units = [str(path) for path in Path('/etc/systemd/system').glob('offsite-observer*.service')]
subprocess.run(['systemd-analyze', 'verify'] + units, check=True)
print('PASS: all generated units pass Debian systemd syntax verification')
result = subprocess.run(['ansible-playbook', '-i', 'deploy/inventory.local.yml', 'deploy/activate.yml'], capture_output=True)
assert result.returncode != 0
print('PASS: activation refuses default-off request')
unit = Path('/etc/systemd/system/offsite-observer-preflight.service')
unit.unlink(); unit.symlink_to('/tmp/untouched')
Path('/tmp/untouched').write_text('sentinel')
run(success=False)
assert Path('/tmp/untouched').read_text() == 'sentinel'
print('PASS: symlink destination refused without modifying target')
