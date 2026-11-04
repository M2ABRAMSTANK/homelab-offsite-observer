#!/usr/bin/env python3
"""Validate private deployment inputs locally; emit only coverage and gate booleans."""
import argparse
import json
from pathlib import Path
import sys

from observer import config, providers
from observer.transport import endpoint


def validate(directory, *, activation=False):
    directory = Path(directory)
    cfg = config.load(directory / 'config.json', secure=True)
    active_urls = [cfg['readiness']['url'], cfg['freshness']['url']]
    active_urls.extend(item['url'] for item in cfg['negative'])
    if cfg['private']['enabled']:
        active_urls.append(cfg['private']['url'])
    if not providers.native(cfg):
        active_urls.extend((cfg['provider']['heartbeat_url'], cfg['provider']['events_url']))
    if activation:
        if not cfg['enabled'] or not cfg['provider']['contract_verified']:
            raise ValueError('activation gates incomplete')
        if any(endpoint(url)[0].lower().rstrip('.').endswith(('.invalid', '.example', '.test', '.localhost'))
               or endpoint(url)[0].lower().rstrip('.') == 'localhost' for url in active_urls):
            raise ValueError('replace reserved deployment targets')
    # Use the same token validators as runtime, through a name-to-path directory
    # adapter only for the root source files. No token is returned in evidence.
    class Sources:
        def __truediv__(self, name):
            return directory / {'provider_token': 'provider.token', 'heartbeat_token': 'heartbeat.token',
                                'telegram_chat': 'telegram_chat.token', 'private_token': 'private.token'}[name]
    if providers.native(cfg):
        providers.credentials(Sources())
    else:
        config.token(Sources(), 'provider_token')
    if cfg['private']['enabled']:
        config.token(Sources(), 'private_token')
    return {'configuration_valid': True, 'native_provider': providers.native(cfg),
            'private_enabled': cfg['private']['enabled'], 'enabled': cfg['enabled'],
            'contract_verified': cfg['provider']['contract_verified']}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', default='/etc/offsite-observer')
    parser.add_argument('--activation', action='store_true')
    args = parser.parse_args()
    try:
        print(json.dumps(validate(args.directory, activation=args.activation)))
        return 0
    except (ValueError, OSError, TypeError, KeyError):
        print('{"error":"deployment_inputs_invalid"}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
