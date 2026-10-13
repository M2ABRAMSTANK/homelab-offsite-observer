"""Fail closed on unknown configuration fields and unsupported provider assumptions."""
import json
import os
from pathlib import Path
import re
import stat

from .checks import json_object, integer
from .transport import endpoint


def exact(obj, keys):
    if type(obj) is not dict or set(obj) != set(keys):
        raise ValueError("configuration schema mismatch")


def load(path, *, secure=False):
    if secure:
        raw = secure_file(path)
    else:
        with Path(path).open("rb") as fp:
            raw = fp.read(32769)
    if len(raw) > 32768:
        raise ValueError("configuration too large")
    cfg = json_object(raw)
    exact(cfg, {"schema", "enabled", "observer_id", "readiness", "freshness", "negative", "private", "provider"})
    if type(cfg["schema"]) is not int or cfg["schema"] != 1 or type(cfg["enabled"]) is not bool:
        raise ValueError("invalid configuration version or activation")
    if not isinstance(cfg["observer_id"], str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", cfg["observer_id"]):
        raise ValueError("invalid observer identifier")
    exact(cfg["readiness"], {"url", "expected"})
    endpoint(cfg["readiness"]["url"])
    if type(cfg["readiness"]["expected"]) is not dict or not cfg["readiness"]["expected"]:
        raise ValueError("readiness requires an exact expected object")
    # Only JSON values are supported; equality is an operator-defined readiness contract.
    if len(json.dumps(cfg["readiness"]["expected"])) > 4096:
        raise ValueError("readiness object too large")
    exact(cfg["freshness"], {"url"})
    endpoint(cfg["freshness"]["url"])
    if type(cfg["negative"]) is not list or not 1 <= len(cfg["negative"]) <= 8:
        raise ValueError("require 1..8 negative checks")
    names = set()
    for spec in cfg["negative"]:
        exact(spec, {"name", "url", "expected", "statuses"})
        if not isinstance(spec["name"], str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", spec["name"]) or spec["name"] in names:
            raise ValueError("invalid or duplicate negative check name")
        names.add(spec["name"])
        endpoint(spec["url"])
        if spec["expected"] not in {"http_denial", "post_tls_eof", "post_tls_reset"}:
            raise ValueError("invalid negative response class")
        if type(spec["statuses"]) is not list or len(spec["statuses"]) > 8:
            raise ValueError("invalid negative statuses")
        if spec["expected"] == "http_denial":
            if not spec["statuses"] or any(type(s) is not int or not 400 <= s <= 499 for s in spec["statuses"]):
                raise ValueError("denial requires exact 4xx statuses")
        elif spec["statuses"]:
            raise ValueError("abort checks cannot have HTTP statuses")
    exact(cfg["private"], {"enabled", "url", "socks_port", "max_pending_seconds"})
    if type(cfg["private"]["enabled"]) is not bool:
        raise ValueError("private.enabled must be boolean")
    endpoint(cfg["private"]["url"])
    if not integer(cfg["private"]["socks_port"], 65535) or cfg["private"]["socks_port"] < 1024:
        raise ValueError("invalid loopback SOCKS port")
    if not integer(cfg["private"]["max_pending_seconds"], 3600):
        raise ValueError("invalid private queue age threshold")
    exact(cfg["provider"], {"heartbeat_url", "events_url", "contract_verified"})
    endpoint(cfg["provider"]["heartbeat_url"])
    endpoint(cfg["provider"]["events_url"])
    if type(cfg["provider"]["contract_verified"]) is not bool:
        raise ValueError("provider.contract_verified must be boolean")
    return cfg


def secure_file(path, *, root=False):
    flags = os.O_RDONLY | os.O_NOFOLLOW
    fd = os.open(path, flags)
    try:
        meta = os.fstat(fd)
        if not stat.S_ISREG(meta.st_mode) or meta.st_mode & 0o077 or meta.st_size > 32768 or meta.st_nlink != 1:
            raise ValueError("credential/config permissions or size invalid")
        if meta.st_uid != (0 if root else os.getuid()):
            raise ValueError("credential/config owner invalid")
        with os.fdopen(fd, "rb", closefd=False) as fp:
            return fp.read(32769)
    finally:
        os.close(fd)


def token(directory, name):
    # systemd LoadCredential gives the service a private, read-only credential copy.
    raw = secure_file(Path(directory) / name).decode("ascii").strip()
    if not re.fullmatch(r"[A-Za-z0-9._~+/-]{8,4096}={0,2}", raw):
        raise ValueError("invalid bearer credential")
    return raw
