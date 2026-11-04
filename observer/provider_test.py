"""Explicit provider acceptance probes, separate from monitoring/state transitions."""
import argparse
import json
import os
import secrets as random_secrets
from pathlib import Path
import sys
import time

from . import config, providers
from .checks import utc
from .runner import parallel


def main(argv=None):
    parser = argparse.ArgumentParser(description='Contact configured providers only with --send. No monitoring state writes.')
    parser.add_argument('action', choices=('incident', 'recovery', 'heartbeat', 'failure'))
    parser.add_argument('--send', action='store_true')
    args = parser.parse_args(argv)
    if not args.send:
        print('{"mode":"dry-run","network_requests":0,"state_writes":0}')
        return 0
    try:
        directory = Path(os.environ['CREDENTIALS_DIRECTORY'])
        if os.geteuid() == 0:
            raise ValueError('non-root required')
        cfg = config.load(directory / 'config', secure=True)
        if not providers.native(cfg):
            raise ValueError('native provider required')
        secrets = providers.credentials(directory)
        if args.action in ('incident', 'recovery'):
            event = {'key': 'acceptance_test', 'event': args.action, 'at': utc(time.time()),
                     'id': random_secrets.token_hex(16)}
            job = providers.event_request(cfg, secrets, event)
        else:
            job = providers.heartbeat_request(secrets, failed=args.action == 'failure')
        response = parallel({'provider': dict(job, timeout=5)}, 5)['provider']
        accepted = (providers.event_accepted(response, secrets) if args.action in ('incident', 'recovery')
                    else providers.heartbeat_accepted(response))
        print(json.dumps({'action': args.action, 'transport_accepted': accepted,
                          'recipient_delivery_verified': False, 'state_writes': 0,
                          'event_id': event['id'] if args.action in ('incident', 'recovery') else None}))
        return 0 if accepted else 2
    except (OSError, ValueError, TypeError, KeyError):
        print('{"error":"provider_test_failed"}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
