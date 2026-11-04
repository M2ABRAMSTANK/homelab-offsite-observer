#!/usr/bin/python3
"""Filesystem installer test double ONLY. Does not emulate systemd sandboxing."""
import json
from pathlib import Path
import sys

args = [arg for arg in sys.argv[1:] if not arg.startswith('-')]
store = Path('/run/fake-systemctl.json')
data = json.loads(store.read_text()) if store.exists() else {}
command = args[0] if args else ''
units = args[1:]

def info(name):
    return data.setdefault(name, {'ActiveState': 'inactive', 'UnitFileState': 'disabled',
                                  'LoadState': 'loaded', 'SubState': 'dead'})

def save():
    store.write_text(json.dumps(data))

if command == 'is-active':
    states = [info(unit)['ActiveState'] for unit in units]
    print('\n'.join(states))
    sys.exit(0 if 'active' in states else 3)
elif command == 'show':
    print('\n'.join(key + '=' + value for key, value in info(units[0]).items()))
elif command == 'is-enabled':
    enabled = info(units[0])['UnitFileState']
    print(enabled)
    sys.exit(0 if enabled == 'enabled' else 1)
elif command in ('enable', 'disable', 'start', 'stop', 'restart'):
    for unit in units:
        if command in ('enable', 'disable'):
            info(unit)['UnitFileState'] = 'enabled' if command == 'enable' else 'disabled'
        else:
            info(unit)['ActiveState'] = 'inactive' if command == 'stop' else 'active'
    save()
elif command == 'list-unit-files':
    for unit in Path('/etc/systemd/system').glob('offsite-observer*.service'):
        print(unit.name, info(unit.name)['UnitFileState'])
elif command == 'list-units' and any(arg.startswith('--state=') for arg in sys.argv):
    for name, item in data.items():
        if item['ActiveState'] in ('active', 'activating', 'deactivating', 'reloading'):
            print(name, 'loaded', item['ActiveState'], 'running', 'Synthetic observer fixture')
elif command == 'list-units':
    for unit in Path('/etc/systemd/system').glob('offsite-observer*.service'):
        print(unit.name, 'loaded', info(unit.name)['ActiveState'], 'dead', 'Synthetic observer fixture')
elif command in ('daemon-reload', 'reset-failed'):
    pass
else:
    print('unsupported fake systemctl command', file=sys.stderr)
    sys.exit(1)
