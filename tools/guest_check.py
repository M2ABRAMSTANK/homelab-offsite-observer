#!/usr/bin/env python3
"""Read-only preflight for a dedicated unprivileged Debian observer guest."""
import argparse
import grp
import json
import os
from pathlib import Path
import pwd
import stat
import subprocess
import sys


def protected(path, uid=0, directory=False, private=False):
    path = Path(path)
    if not path.exists() and not path.is_symlink():
        return
    meta = path.lstat()
    if (stat.S_ISLNK(meta.st_mode) or meta.st_uid != uid
            or meta.st_mode & (0o077 if private else 0o022)
            or (directory and not stat.S_ISDIR(meta.st_mode))
            or (not directory and (not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1))):
        raise ValueError('unsafe installation path')


def platform():
    if os.geteuid() != 0 or sys.version_info < (3, 11):
        raise ValueError('root and Python 3.11 required for installation')
    release = dict(line.split('=', 1) for line in Path('/etc/os-release').read_text().splitlines() if '=' in line)
    if release.get('ID', '').strip('"') != 'debian' or release.get('VERSION_ID', '').strip('"') not in ('12', '13'):
        raise ValueError('Debian 12 or 13 required')
    virt = subprocess.run(['systemd-detect-virt', '--container'], capture_output=True, timeout=5)
    if virt.returncode or virt.stdout.strip() != b'lxc' or not Path('/run/systemd/system').is_dir():
        raise ValueError('systemd LXC guest required')
    mappings = [list(map(int, line.split())) for line in Path('/proc/self/uid_map').read_text().splitlines()]
    if not any(start == 0 and outside > 0 for start, outside, count in mappings):
        raise ValueError('unprivileged UID mapping required')


def paths():
    for name in ('/opt', '/etc', '/var', '/var/lib', '/etc/systemd', '/etc/systemd/system'):
        protected(name, directory=True)
    for name in ('/opt/offsite-observer', '/etc/offsite-observer',
                 '/etc/systemd/system/offsite-observer.service.d',
                 '/etc/systemd/system/offsite-observer-preflight.service.d',
                 '/etc/systemd/system/offsite-observer-acceptance.service.d',
                 '/etc/systemd/system/offsite-observer-provider-test@.service.d'):
        protected(name, directory=True)
        path = Path(name)
        if path.exists():
            for entry in path.rglob('*'):
                protected(entry, directory=entry.is_dir(), private=name == '/etc/offsite-observer')
    for name in ('offsite-observer-preflight.service', 'offsite-observer-acceptance.service', 'offsite-observer-provider-test@.service'):
        protected('/etc/systemd/system/' + name)
    for suffix in ('service', 'timer'):
        protected('/etc/systemd/system/offsite-observer.' + suffix)
    try:
        group = grp.getgrnam('offsite-observer')
    except KeyError:
        group = None
    if group is not None and (group.gr_mem or any(p.pw_gid == group.gr_gid and p.pw_name != 'offsite-observer' for p in pwd.getpwall())):
        raise ValueError('service group is shared')
    try:
        account = pwd.getpwnam('offsite-observer')
    except KeyError:
        if Path('/var/lib/offsite-observer').exists() or Path('/var/lib/offsite-observer').is_symlink():
            raise ValueError('state exists without service account')
        return
    if (account.pw_uid == 0 or account.pw_dir != '/nonexistent'
            or account.pw_shell != '/usr/sbin/nologin'
            or os.getgrouplist(account.pw_name, account.pw_gid) != [account.pw_gid]):
        raise ValueError('unsafe existing service account')
    protected('/var/lib/offsite-observer', account.pw_uid, directory=True, private=True)
    state = Path('/var/lib/offsite-observer')
    if state.exists():
        for entry in state.iterdir():
            protected(entry, account.pw_uid, private=True)


def canary_paths():
    for name in ('/opt', '/etc', '/etc/systemd', '/etc/systemd/system', '/opt/offsite-canary'):
        protected(name, directory=True)
    protected('/etc/systemd/system/offsite-canary.service')
    root = Path('/opt/offsite-canary')
    if root.exists():
        for entry in root.rglob('*'):
            protected(entry, directory=entry.is_dir())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--paths-only', action='store_true')
    parser.add_argument('--canary-paths-only', action='store_true')
    args = parser.parse_args()
    try:
        if args.canary_paths_only:
            canary_paths()
        else:
            if not args.paths_only:
                platform()
            paths()
        print(json.dumps({'platform_valid': not (args.paths_only or args.canary_paths_only), 'paths_valid': True}))
        return 0
    except (ValueError, OSError, KeyError, subprocess.SubprocessError):
        print('{"error":"guest_preflight_failed"}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
