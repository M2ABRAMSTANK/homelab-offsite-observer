import copy
import json
import unittest

from observer.checks import negative, utc, validate
from observer.transport import Response

NOW = 1_800_000_000
NONCE = "0" * 32


def reply(data, **kwargs):
    return Response("http", tls=True, status=200, headers={"cache-control": "no-store"},
                    body=json.dumps(data).encode(), **kwargs)


def canary():
    return {"schema": 1, "nonce": NONCE, "generated_at": utc(NOW)}


def heartbeat():
    return dict(canary(), queue={"ready": True, "active": 0, "oldest_pending_seconds": 0},
                security_alerts_firing=0)


class ChecksTests(unittest.TestCase):
    def test_fresh_canary_and_private(self):
        self.assertTrue(validate(reply(canary()), "freshness", nonce=NONCE, now=NOW))
        self.assertTrue(validate(reply(heartbeat()), "private", nonce=NONCE, now=NOW))

    def test_nonce_stale_skew_untrusted_clock(self):
        for kind, data in [("freshness", canary()), ("private", heartbeat())]:
            self.assertFalse(validate(reply(data), kind, nonce="different", now=NOW))
            for skew in [-121, 121]:
                self.assertFalse(validate(reply(data), kind, nonce=NONCE, now=NOW + skew))
            for skew in [-120, 120]:
                self.assertTrue(validate(reply(data), kind, nonce=NONCE, now=NOW + skew))
            self.assertFalse(validate(reply(data), kind, nonce=NONCE, now=NOW, clock=False))

    def test_negative_requires_verified_post_handshake_evidence(self):
        eof = {"expected": "post_tls_eof", "statuses": []}
        self.assertTrue(negative(Response("post_tls_eof", tls=True), eof))
        self.assertFalse(negative(Response("http", tls=True, status=200), eof))
        self.assertFalse(negative(Response("post_tls_reset", tls=True), eof))
        for response in [Response("post_tls_eof"), Response("tls_error"), Response("network_error"),
                         Response("timeout", tls=True)]:
            self.assertIsNone(negative(response, eof))
        self.assertIsNone(negative(Response("invalid_response", tls=True), eof))
        self.assertFalse(negative(Response("post_tls_eof", tls=True, status=200), eof))
        denial = {"expected": "http_denial", "statuses": [403]}
        self.assertTrue(negative(Response("http", tls=True, status=403), denial))
        self.assertFalse(negative(Response("http", tls=True, status=404), denial))

    def test_reject_schema_export_fields_and_bad_values(self):
        cases = []
        for key, values in [("security_alerts_firing", [-1, True, 1_000_001, 0.5, "0"]),
                            ("schema", [True, "1", 2])]:
            for value in values:
                data = heartbeat()
                data[key] = value
                cases.append(data)
        for key, values in [("ready", [False, 1, "true"]),
                            ("active", [-1, True, 0.1]),
                            ("oldest_pending_seconds", [-1, True, 61, float("inf")])]:
            for value in values:
                data = heartbeat()
                data["queue"][key] = value
                cases.append(data)
        data = heartbeat()
        data["metrics"] = {"private": "data"}
        cases.append(data)
        data = heartbeat()
        data["queue"]["rows"] = []
        cases.append(data)
        for data in cases:
            with self.subTest(data=data):
                self.assertFalse(validate(reply(data), "private", nonce=NONCE, now=NOW))

    def test_nostore_exact_keys_duplicates_redirects_and_tls(self):
        for kind, data in [("freshness", canary()), ("private", heartbeat())]:
            response = reply(data)
            for header in ["", "no-cache", "no-store=true", "public"]:
                response.headers = {"cache-control": header}
                self.assertFalse(validate(response, kind, nonce=NONCE, now=NOW))
            response = reply(data)
            response.body = b'{"schema":1,"schema":1}'
            self.assertFalse(validate(response, kind, nonce=NONCE, now=NOW))
            for attr, value in [("status", 302), ("tls", False), ("kind", "timeout")]:
                response = reply(data)
                setattr(response, attr, value)
                self.assertFalse(validate(response, kind, nonce=NONCE, now=NOW))
        data = canary()
        data["extra"] = "refused"
        self.assertFalse(validate(reply(data), "freshness", nonce=NONCE, now=NOW))
        data = canary()
        data["generated_at"] = "2027-01-15T08:00:00"
        self.assertFalse(validate(reply(data), "freshness", nonce=NONCE, now=NOW))

    def test_exact_readiness(self):
        self.assertTrue(validate(reply({"status": "ok"}), "readiness", expected={"status": "ok"}))
        self.assertFalse(validate(reply({"status": "ok", "extra": True}), "readiness", expected={"status": "ok"}))
        self.assertFalse(validate(reply({"ready": 1}), "readiness", expected={"ready": True}))
