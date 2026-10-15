"""Strict schemas keep the heartbeat from becoming a general data-export API."""
from datetime import datetime, timezone
import json
import math


def integer(value, maximum=1_000_000):
    return type(value) is int and 0 <= value <= maximum


def json_object(body):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = value
        return result
    def finite(text):
        value = float(text)
        if not math.isfinite(value):
            raise ValueError("non-finite JSON")
        return value
    return json.loads(body, object_pairs_hook=unique, parse_float=finite,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("non-finite JSON")))


def fresh(data, nonce, now):
    timestamp = data.get("generated_at")
    if data.get("nonce") != nonce or not isinstance(timestamp, str) or len(timestamp) > 40:
        return False
    try:
        stamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return (stamp.tzinfo is not None and stamp.utcoffset().total_seconds() == 0
                and abs(now - stamp.timestamp()) <= 120)
    except (ValueError, OverflowError, AttributeError):
        return False


def validate(response, kind, *, nonce="", now=0, expected=None, max_age=60, clock=True):
    if not response.tls or response.kind != "http" or response.status != 200:
        return False
    try:
        data = json_object(response.body)
        if kind == "readiness":
            return type(data) is dict and exact_value(data, expected)
        if not clock or type(data) is not dict:
            return False
        if "no-store" not in [x.strip().lower() for x in response.headers.get("cache-control", "").split(",")]:
            return False
        if not fresh(data, nonce, now):
            return False
        if kind == "freshness":
            return set(data) == {"schema", "nonce", "generated_at"} and type(data["schema"]) is int and data["schema"] == 1
        if kind != "private" or set(data) != {"schema", "nonce", "generated_at", "queue", "security_alerts_firing"}:
            return False
        queue = data["queue"]
        return (type(data["schema"]) is int and data["schema"] == 1
                and type(queue) is dict and set(queue) == {"ready", "active", "oldest_pending_seconds"}
                and type(queue["ready"]) is bool and queue["ready"]
                and integer(queue["active"])
                and type(queue["oldest_pending_seconds"]) in (int, float)
                # Bound remote integers before math.isfinite converts them to float.
                and 0 <= queue["oldest_pending_seconds"] <= max_age
                and math.isfinite(queue["oldest_pending_seconds"])
                and integer(data["security_alerts_firing"]))
    except (ValueError, TypeError, KeyError, RecursionError):
        return False


def exact_value(actual, expected):
    if type(actual) is not type(expected):
        return False
    if type(actual) is dict:
        return set(actual) == set(expected) and all(exact_value(actual[k], expected[k]) for k in actual)
    if type(actual) is list:
        return len(actual) == len(expected) and all(exact_value(a, e) for a, e in zip(actual, expected))
    return actual == expected


def negative(response, spec):
    if not response.tls or response.kind in {"timeout", "network_error", "tls_error", "invalid_response"}:
        return None
    if spec["expected"] == "http_denial":
        return response.kind == "http" and response.status in spec["statuses"]
    return response.status == 0 and response.kind == spec["expected"]


def utc(now):
    return datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z")
