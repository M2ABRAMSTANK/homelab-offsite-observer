"""Bounded loopback HTTP canary behind an existing authenticated-TLS edge."""
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import re


def response(path, nonces):
    if path != '/v1/observer/canary':
        return 404, b''
    if len(nonces) != 1 or not re.fullmatch('[0-9a-f]{32}', nonces[0]):
        return 400, b''
    return 200, json.dumps({'schema': 1, 'nonce': nonces[0],
                           'generated_at': datetime.now(timezone.utc).isoformat()},
                          separators=(',', ':')).encode('ascii')


class Handler(BaseHTTPRequestHandler):
    # One request per connection; no threaded/unbounded connection allocation.
    protocol_version = 'HTTP/1.0'
    server_version = 'Canary'
    sys_version = ''
    timeout = 2

    def do_GET(self):
        status, body = response(self.path, self.headers.get_all('X-Observer-Nonce') or [])
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass  # Never log a request, header or nonce.


class Server(HTTPServer):
    request_queue_size = 8

    def handle_error(self, *args):
        pass  # Client disconnects must not emit traceback/request details.


def main():
    # Only the existing reverse proxy can reach this listener. No TLS or public
    # listener is created here, and no provider or private queue data is exposed.
    with Server(('127.0.0.1', 8789), Handler) as server:
        server.serve_forever()


if __name__ == '__main__':
    main()
