import copy
import io
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

from observer import config, providers, runner, state
from observer.provider_test import main as provider_test
from observer.transport import Response
from canary.__main__ import response as canary_response
from tools.deployment_check import validate as deployment_validate
from observer.acceptance import accepted

ROOT = Path(__file__).resolve().parents[1]
SECRETS = {'provider_token': '12345678:' + 'a' * 32, 'telegram_chat': '-123456789',
           'heartbeat_token': '00000000-0000-4000-8000-000000000001'}


def telegram(chat=-123456789):
    return Response('http', tls=True, status=200,
                    body=json.dumps({'ok': True, 'result': {'message_id': 7, 'chat': {'id': chat}}}).encode())


class ProviderTests(unittest.TestCase):
    def cfg(self):
        return config.load(ROOT / 'config.telegram.example.json')

    def test_native_has_fixed_destinations_and_no_bearer_leakage(self):
        payload = {'id': 'a' * 32, 'key': 'wan_edge', 'event': 'incident', 'at': runner.utc(time.time())}
        req = providers.event_request(self.cfg(), SECRETS, payload)
        self.assertEqual(req['url'], 'https://api.telegram.org/bot' + SECRETS['provider_token'] + '/sendMessage')
        body = json.loads(req['payload'])
        self.assertEqual(body['chat_id'], -123456789)
        self.assertIn(payload['id'], body['text'])
        self.assertNotIn(SECRETS['provider_token'], body['text'])
        self.assertNotIn('headers', req)
        hb = providers.heartbeat_request(SECRETS, failed=True)
        self.assertEqual(hb['url'], 'https://hc-ping.com/' + SECRETS['heartbeat_token'] + '/fail')
        self.assertEqual(hb['payload'], b'')

    def test_telegram_requires_tls_ok_message_and_exact_recipient(self):
        self.assertTrue(providers.event_accepted(telegram(), SECRETS))
        for response in (telegram(chat=99), Response('http', tls=True, status=200, body=b'{"ok":false}'),
                         Response('http', tls=False, status=200), Response('http', tls=True, status=302),
                         Response('http', tls=True, status=429), Response('http', tls=True, status=200, body=b'[]')):
            self.assertFalse(providers.event_accepted(response, SECRETS))
        for body in ({'ok': 1, 'result': {'message_id': 1, 'chat': {'id': -123456789}}},
                     {'ok': True, 'result': {'message_id': True, 'chat': {'id': -123456789}}}):
            self.assertFalse(providers.event_accepted(Response('http', tls=True, status=200, body=json.dumps(body).encode()), SECRETS))

    def test_deadman_requires_documented_response(self):
        self.assertTrue(providers.heartbeat_accepted(Response('http', tls=True, status=200, body=b'OK')))
        for body in (b'', b'not OK', b'{"ok":true}'):
            self.assertFalse(providers.heartbeat_accepted(Response('http', tls=True, status=200, body=body)))

    def test_credentials_and_configuration_reject_injection_or_redirects(self):
        with tempfile.TemporaryDirectory() as directory:
            for key, value in SECRETS.items():
                path = Path(directory) / key
                path.write_text(value)
                path.chmod(0o600)
            self.assertEqual(providers.credentials(directory), SECRETS)
            for key, invalid in [('provider_token', 'https://elsewhere.invalid/token'),
                                 ('telegram_chat', '@another_account'), ('heartbeat_token', '../another')]:
                path = Path(directory) / key
                path.write_text(invalid)
                with self.assertRaises(ValueError):
                    providers.credentials(directory)
                path.write_text(SECRETS[key])
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                providers.credentials(directory)
            cfg = self.cfg()
            cfg['provider']['events_url'] = 'https://untrusted.invalid/'
            path = Path(directory) / 'config.json'
            path.write_text(json.dumps(cfg))
            with self.assertRaises(ValueError):
                config.load(path)

    def test_deployment_validation_refuses_placeholders_and_missing_secrets(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            cfg = self.cfg()
            path.write_text(json.dumps(cfg)); path.chmod(0o600)
            with self.assertRaises(OSError):
                deployment_validate(directory)
            for source, name in [('provider_token', 'provider'), ('heartbeat_token', 'heartbeat'), ('telegram_chat', 'telegram_chat')]:
                token = Path(directory) / (name + '.token')
                token.write_text(SECRETS[source]); token.chmod(0o600)
            self.assertTrue(deployment_validate(directory)['native_provider'])
            cfg['enabled'] = cfg['provider']['contract_verified'] = True
            path.write_text(json.dumps(cfg))
            with self.assertRaises(ValueError):
                deployment_validate(directory, activation=True)

    def test_provider_test_default_is_inert(self):
        with patch('observer.provider_test.parallel', side_effect=AssertionError('network')), redirect_stdout(io.StringIO()) as output:
            self.assertEqual(provider_test(['incident']), 0)
            self.assertEqual(json.loads(output.getvalue())['network_requests'], 0)

    def test_canary_exact_path_nonce_and_freshness_contract(self):
        for path, nonces in [('/metrics', ['a'*32]), ('/v1/observer/canary?x=1', ['a'*32]),
                             ('/v1/observer/canary', []), ('/v1/observer/canary', ['a'*32]*2),
                             ('/v1/observer/canary', ['<script>'])]:
            self.assertNotEqual(canary_response(path, nonces)[0], 200)
        status, raw = canary_response('/v1/observer/canary', ['a'*32])
        self.assertEqual(status, 200)
        from observer.checks import validate
        self.assertTrue(validate(Response('http', tls=True, status=200, headers={'cache-control':'no-store'}, body=raw),
                                 'freshness', nonce='a'*32, now=time.time(), clock=True))

    def test_activation_requires_health_not_just_successful_fail_ping(self):
        good = {'schema': 1, 'clock_trusted': True, 'provider_heartbeat': True, 'spool_events': 0,
                'spool_dropped': 0, 'outcomes': {'wan_edge': True, 'edge_exposure': True, 'private_queue': None},
                'incidents': {key: False for key in state.KEYS}}
        self.assertTrue(accepted(good))
        for key, value in [('spool_events', 1), ('spool_dropped', 1), ('provider_heartbeat', False), ('clock_trusted', False)]:
            self.assertFalse(accepted(dict(good, **{key: value})))
        for key in good['outcomes']:
            broken = copy.deepcopy(good); broken['outcomes'][key] = False
            self.assertFalse(accepted(broken))

    def test_pending_backoff_stays_failed_and_no_heartbeat_before_persistence(self):
        cfg = self.cfg()
        calls = []
        def probes(jobs, timeout):
            calls.append(jobs)
            if 'heartbeat' in jobs:
                self.assertTrue(Path(directory, 'state.json').exists())
                return {'heartbeat': Response('http', tls=True, status=200, body=b'OK')}
            self.assertNotIn('provider', jobs)  # Backoff must not retry early.
            return {name: Response('network_error') for name in jobs}
        with tempfile.TemporaryDirectory() as directory:
            now = time.time()
            pending = state.empty()
            for _ in range(3): state.advance(pending, 'wan_edge', False, now)
            pending['events'][0]['next'] = now + 100
            state.write(directory, pending)
            with patch('observer.runner.parallel', side_effect=probes), patch('observer.runner.clock_trusted', return_value=True):
                evidence = runner.cycle(cfg, SECRETS, directory)
            self.assertTrue(calls[-1]['heartbeat']['url'].endswith('/fail'))
            self.assertEqual(evidence['spool_events'], 1)
            self.assertNotIn(SECRETS['provider_token'], json.dumps(evidence))

    def test_outage_sends_telegram_but_successful_deadman_and_recovers(self):
        cfg = self.cfg(); calls = []; healthy = False
        def probes(jobs, timeout):
            calls.append(jobs)
            if 'provider' in jobs: return {'provider': telegram()}
            if 'heartbeat' in jobs: return {'heartbeat': Response('http', tls=True, status=200, body=b'OK')}
            if not healthy: return {name: Response('network_error') for name in jobs}
            result = {}
            for name, kw in jobs.items():
                if kw.get('negative'):
                    spec = next(s for s in cfg['negative'] if s['name'] == name)
                    result[name] = Response('http', tls=True, status=403) if spec['expected'] == 'http_denial' else Response('post_tls_eof', tls=True)
                else:
                    raw = b'{"status":"ok"}' if name == 'readiness' else canary_response('/v1/observer/canary', [kw['headers']['X-Observer-Nonce']])[1]
                    result[name] = Response('http', tls=True, status=200, headers={'cache-control':'no-store'}, body=raw)
            return result
        with tempfile.TemporaryDirectory() as directory, patch('observer.runner.parallel', side_effect=probes), patch('observer.runner.clock_trusted', return_value=True):
            for _ in range(3): evidence = runner.cycle(cfg, SECRETS, directory)
            self.assertTrue(evidence['incidents']['wan_edge'])
            self.assertEqual(evidence['spool_events'], 0)
            self.assertFalse(calls[-1]['heartbeat']['url'].endswith('/fail'))
            healthy = True
            for _ in range(2): evidence = runner.cycle(cfg, SECRETS, directory)
            self.assertFalse(evidence['incidents']['wan_edge'])
            messages = [json.loads(j['provider']['payload'])['text'] for j in calls if 'provider' in j]
            self.assertIn('wan_edge incident', messages[0]); self.assertIn('wan_edge recovery', messages[1])

    def test_failed_state_write_never_emits_native_heartbeat(self):
        with tempfile.TemporaryDirectory() as directory, patch('observer.runner.clock_trusted', return_value=True), \
                patch('observer.runner.write', side_effect=OSError('disk full')), \
                patch('observer.runner.parallel', return_value={'readiness': Response('network_error'), 'freshness': Response('network_error')}) as probes:
            with self.assertRaises(OSError): runner.cycle(self.cfg(), SECRETS, directory)
            self.assertFalse(any('heartbeat' in call.args[0] for call in probes.call_args_list))

    def test_deadman_failure_alerts_through_telegram(self):
        messages = []
        def probes(jobs, timeout):
            if 'heartbeat' in jobs:
                return {'heartbeat': Response('network_error')}
            if 'provider' in jobs:
                messages.append(json.loads(jobs['provider']['payload'])['text'])
                return {'provider': telegram()}
            # Home outage is independent; both incident classes must be retained.
            return {name: Response('network_error') for name in jobs}
        with tempfile.TemporaryDirectory() as directory, patch('observer.runner.parallel', side_effect=probes), patch('observer.runner.clock_trusted', return_value=True):
            for _ in range(4): evidence = runner.cycle(self.cfg(), SECRETS, directory)
            self.assertFalse(evidence['provider_heartbeat'])
            self.assertTrue(evidence['incidents']['provider_path'])
            self.assertTrue(any('provider_path incident' in message for message in messages))

    def test_failed_native_recovery_is_durable_and_deadman_stays_failed(self):
        cfg = self.cfg(); heartbeat_urls = []
        def probes(jobs, timeout):
            if 'provider' in jobs: return {'provider': Response('network_error')}
            if 'heartbeat' in jobs:
                heartbeat_urls.append(jobs['heartbeat']['url'])
                return {'heartbeat': Response('http', tls=True, status=200, body=b'OK')}
            result = {}
            for name, kw in jobs.items():
                if kw.get('negative'):
                    spec = next(s for s in cfg['negative'] if s['name'] == name)
                    result[name] = Response('http', tls=True, status=403) if spec['expected'] == 'http_denial' else Response('post_tls_eof', tls=True)
                else:
                    raw = b'{"status":"ok"}' if name == 'readiness' else canary_response('/v1/observer/canary', [kw['headers']['X-Observer-Nonce']])[1]
                    result[name] = Response('http', tls=True, status=200, headers={'cache-control':'no-store'}, body=raw)
            return result
        with tempfile.TemporaryDirectory() as directory:
            pending = state.empty()
            pending['machines']['wan_edge'].update(open=True, fail=0, **{'pass': 1, 'notified': time.time()})
            state.write(directory, pending)
            with patch('observer.runner.parallel', side_effect=probes), patch('observer.runner.clock_trusted', return_value=True):
                evidence = runner.cycle(cfg, SECRETS, directory)
            self.assertFalse(evidence['incidents']['wan_edge'])  # observed health, not delivery
            self.assertTrue(heartbeat_urls[-1].endswith('/fail'))
            retained = state.read(directory)['events']
            self.assertEqual([(event['key'], event['event']) for event in retained], [('wan_edge', 'recovery')])
            self.assertEqual(retained[0]['attempts'], 1)

    def test_canary_http_handler_rejects_duplicate_nonce_and_sets_no_store(self):
        import socket
        import threading
        from canary.__main__ import Handler
        def exchange(headers):
            client, server = socket.socketpair()
            thread = threading.Thread(target=lambda: Handler(server, ('127.0.0.1', 1), None))
            thread.start()
            client.sendall(('GET /v1/observer/canary HTTP/1.0\r\n' + headers + '\r\n').encode())
            client.shutdown(socket.SHUT_WR)
            client.settimeout(2)
            chunks = []
            try:
                # Handler does not own/close the supplied socket; parse by content length.
                raw = client.recv(4096)
                while b'\r\n\r\n' not in raw: raw += client.recv(4096)
                head, body = raw.split(b'\r\n\r\n', 1)
                length = int(next(line.split(b':', 1)[1] for line in head.split(b'\r\n') if line.lower().startswith(b'content-length:')))
                while len(body) < length: body += client.recv(4096)
                return head, body
            finally:
                thread.join(3); client.close(); server.close()
                self.assertFalse(thread.is_alive())
        head, body = exchange('X-Observer-Nonce: ' + 'a'*32 + '\r\n')
        self.assertIn(b'200 OK', head); self.assertIn(b'Cache-Control: no-store', head)
        self.assertEqual(json.loads(body)['nonce'], 'a'*32)
        head, body = exchange(('X-Observer-Nonce: ' + 'a'*32 + '\r\n')*2)
        self.assertIn(b'400 Bad Request', head); self.assertEqual(body, b'')

    def test_native_budget_reserves_event_and_deadman_after_slow_probes(self):
        cfg = self.cfg(); elapsed = [0.0]; calls = []
        def probes(jobs, timeout):
            calls.append((set(jobs), timeout))
            elapsed[0] += timeout
            if 'heartbeat' in jobs: return {'heartbeat': Response('http', tls=True, status=200, body=b'OK')}
            if 'provider' in jobs: return {'provider': telegram()}
            responses = {}
            for name, kw in jobs.items():
                if kw.get('negative'):
                    # Unexpected exposure still must be eligible to consume its full phase.
                    responses[name] = Response('http', tls=True, status=200)
                else:
                    raw = b'{"status":"ok"}' if name == 'readiness' else canary_response('/v1/observer/canary', [kw['headers']['X-Observer-Nonce']])[1]
                    responses[name] = Response('http', tls=True, status=200, headers={'cache-control':'no-store'}, body=raw)
            return responses
        with tempfile.TemporaryDirectory() as directory:
            initial = state.empty()
            for _ in range(3): state.advance(initial, 'wan_edge', False, time.time())
            state.write(directory, initial)
            with patch('observer.runner.time.monotonic', side_effect=lambda: elapsed[0]),                     patch('observer.runner.parallel', side_effect=probes), patch('observer.runner.clock_trusted', return_value=True):
                runner.cycle(cfg, SECRETS, directory)
        self.assertEqual(next(timeout for names, timeout in calls if names == {'provider'}), 2)
        self.assertEqual(next(timeout for names, timeout in calls if names == {'heartbeat'}), 2)
        self.assertLess(elapsed[0], runner.BUDGET)
