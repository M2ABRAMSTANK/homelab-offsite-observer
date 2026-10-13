import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from observer.transport import endpoint, request, socks_connect, MAX_BODY


class FakeSocks:
    def __init__(self, reply=b"\x05\x00\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"):
        self.reply = reply
        self.sent = []

    def sendall(self, value):
        self.sent.append(value)

    def recv(self, count):
        value, self.reply = self.reply[:count], self.reply[count:]
        return value


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("openssl"):
            raise RuntimeError("openssl required for meaningful local TLS transport fixtures")
        cls.temp = tempfile.TemporaryDirectory()
        cls.cert = Path(cls.temp.name) / "cert.pem"
        cls.key = Path(cls.temp.name) / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-sha256", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                        "-keyout", str(cls.key), "-out", str(cls.cert)], check=True, capture_output=True)
        cls.original_context = staticmethod(ssl.create_default_context)
        cls.original_connect = staticmethod(socket.create_connection)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def serve(self, wire, *, negative=False, hostname="localhost", trusted=True, tls=True):
        client, raw = socket.socketpair()
        client.settimeout(1)
        errors = []
        def server():
            try:
                with raw:
                    if not tls:
                        return
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(self.cert, self.key)
                    with context.wrap_socket(raw, server_side=True) as secured:
                        secured.settimeout(2)
                        secured.recv(8192)
                        if wire:
                            secured.sendall(wire)
                        else:
                            # Send a real TLS close_notify; socketpair abrupt close can
                            # surface as EPIPE during TLS 1.3 post-handshake processing.
                            secured.unwrap().close()
            except (OSError, ssl.SSLError) as error:
                errors.append(type(error).__name__)
        thread = threading.Thread(target=server)
        thread.start()
        factory = (lambda: self.original_context(cafile=str(self.cert))) if trusted else self.original_context
        try:
            with patch("observer.transport.ssl.create_default_context", side_effect=factory), \
                    patch("observer.transport.socket.create_connection",
                          return_value=client):
                response = request(f"https://{hostname}/fixture", timeout=1, negative=negative)
        finally:
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
        return response

    def test_valid_tls_denial_and_post_tls_eof(self):
        response = self.serve(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 999999\r\n\r\n", negative=True)
        self.assertEqual((response.kind, response.tls, response.status, response.body), ("http", True, 403, b""))
        response = self.serve(b"", negative=True)
        self.assertTrue(response.tls)
        self.assertEqual(response.kind, "post_tls_eof")

    def test_before_tls_eof_untrusted_ca_and_wrong_hostname_fail(self):
        for kwargs in [{"tls": False}, {"trusted": False}, {"hostname": "wrong.example.invalid"}]:
            with self.subTest(kwargs=kwargs):
                response = self.serve(b"", negative=True, **kwargs)
                self.assertFalse(response.tls)
                self.assertNotEqual(response.kind, "post_tls_eof")

    def test_redirect_not_followed_and_oversize_refused(self):
        response = self.serve(b"HTTP/1.1 302 Found\r\nLocation: https://other.example.invalid/\r\nContent-Length: 0\r\n\r\n")
        self.assertEqual(response.status, 302)
        response = self.serve(b"HTTP/1.1 200 OK\r\nContent-Length: 20000\r\n\r\n" + b"a" * 20000)
        self.assertEqual(response.kind, "invalid_response")
        self.assertGreater(len(response.body), MAX_BODY)
        response = self.serve(b"HTTP/1.1 200 OK\r\nX-Big: " + b"a" * 17000 + b"\r\n\r\n")
        self.assertEqual(response.kind, "invalid_response")

    def test_socks_domain_dns_and_policy_refusal(self):
        fake = FakeSocks()
        socks_connect(fake, "private.example.invalid", 443)
        self.assertEqual(fake.sent[0], b"\x05\x01\x00")
        self.assertTrue(fake.sent[1].startswith(b"\x05\x01\x00\x03"))
        self.assertIn(b"private.example.invalid", fake.sent[1])
        with self.assertRaises(OSError):
            socks_connect(FakeSocks(b"\x05\x00\x05\x02\x00\x01"), "private.example.invalid", 443)

    def test_endpoint_rejects_credentials_injection_and_non_https(self):
        for url in ["http://edge.example.invalid/", "https://secret@edge.example.invalid/",
                    "https://edge.example.invalid/\r\nsecret", "https://edge.example.invalid/?token=secret",
                    "https://edge.example.invalid/#secret", "https://[::1]/"]:
            with self.assertRaises(ValueError):
                endpoint(url)
        for url in ["https://127.0.0.1/", "https://edge.example.invalid:0/"]:
            with self.assertRaises(ValueError):
                endpoint(url)
