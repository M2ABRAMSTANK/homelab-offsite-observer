"""Native provider contracts. No provider URL, token or response enters evidence."""
import json
import re

from . import config
from .checks import json_object

KIND = 'telegram_healthchecks'


def native(cfg):
    return cfg['provider'].get('kind') == KIND


def credentials(directory):
    values = {}
    patterns = {
        'provider_token': r'[0-9]{5,20}:[A-Za-z0-9_-]{20,100}',
        'telegram_chat': r'-?[1-9][0-9]{0,19}',
        'heartbeat_token': r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    }
    from pathlib import Path
    for name, pattern in patterns.items():
        path = directory / name if hasattr(directory, '__truediv__') else Path(directory) / name
        value = config.secure_file(path).decode('ascii').strip()
        if not re.fullmatch(pattern, value):
            raise ValueError('invalid provider credential')
        values[name] = value
    return values


def event_request(cfg, secrets, event):
    # Telegram has no idempotency key. Include a stable ID for human deduplication;
    # a successful send followed by a lost response can produce a duplicate retry.
    text = (f"Offsite {cfg['observer_id']}: {event['key']} {event['event']}\n"
            f"{event['at']}\nEvent {event['id']}")
    payload = {'chat_id': int(secrets['telegram_chat']), 'text': text,
               'protect_content': True, 'disable_web_page_preview': True}
    return {'url': 'https://api.telegram.org/bot' + secrets['provider_token'] + '/sendMessage',
            'payload': json.dumps(payload, separators=(',', ':')).encode('ascii')}


def event_accepted(response, secrets):
    if not response.tls or response.kind != 'http' or response.status != 200:
        return False
    try:
        data = json_object(response.body)
        result = data['result']
        return (data['ok'] is True and type(result['message_id']) is int
                and result['message_id'] > 0 and type(result['chat']['id']) is int
                and result['chat']['id'] == int(secrets['telegram_chat']))
    except (ValueError, KeyError, TypeError, RecursionError):
        return False


def heartbeat_request(secrets, failed=False):
    return {'url': 'https://hc-ping.com/' + secrets['heartbeat_token'] + ('/fail' if failed else ''),
            'payload': b''}


def heartbeat_accepted(response):
    return (response.tls and response.kind == 'http' and response.status == 200
            and response.body == b'OK')
