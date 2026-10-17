"""One atomic, bounded file; probe bodies and credentials never enter this store."""
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import stat
import time
import uuid

from .checks import json_object, utc

MAX_EVENTS = 1000
MAX_BYTES = 16 * 1024 * 1024
MAX_AGE = 86400
# A timer normally runs every 30 seconds. Retain a bounded short rollback without
# allowing a corrupt future timestamp to pin an event indefinitely.
MAX_FUTURE_SKEW = 300
MAX_RETRY = 300
KEYS = ("wan_edge", "edge_exposure", "private_queue", "clock", "provider_path")


def empty():
    return {"schema": 1, "machines": {k: {"open": False, "fail": 0, "pass": 0, "notified": 0} for k in KEYS},
            "events": [], "dropped": 0}


def advance(state, key, outcome, now, *, delivery_ok=True):
    """Inconclusive cycles retain streaks. Probe success alone never clears an outage."""
    machine = state["machines"][key]
    event = None
    if outcome is False:
        machine["fail"] = min(3, machine["fail"] + 1)
        machine["pass"] = 0
        if machine["fail"] >= 3 and not machine["open"]:
            machine["open"] = True
            event = "incident"
    elif outcome is True:
        machine["fail"] = 0
        machine["pass"] = min(2, machine["pass"] + 1)
        if machine["open"] and machine["pass"] >= 2 and delivery_ok:
            machine["open"] = False
            event = "recovery"
    if machine["open"] and now - machine["notified"] >= MAX_AGE:
        event = "incident"
    if event:
        machine["notified"] = now
        state["events"].append({"id": uuid.uuid4().hex, "key": key, "event": event,
                                "at": utc(now), "created": now, "attempts": 0, "next": now})


def bound(state, now):
    kept = [e for e in state["events"]
            if -MAX_FUTURE_SKEW <= now - e["created"] <= MAX_AGE]
    state["dropped"] = min(1_000_000_000, state["dropped"] + len(state["events"]) - len(kept))
    state["events"] = kept
    while len(state["events"]) > MAX_EVENTS or len(encode(state)) > MAX_BYTES:
        state["events"].pop(0)
        state["dropped"] = min(1_000_000_000, state["dropped"] + 1)


def retry(event, now):
    event["attempts"] = min(16, event["attempts"] + 1)
    event["next"] = now + min(MAX_RETRY, 5 * 2 ** (event["attempts"] - 1))


def encode(state):
    return json.dumps(state, separators=(",", ":"), allow_nan=False).encode("ascii")


def _regular(fd):
    meta = os.fstat(fd)
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077 or meta.st_nlink != 1:
        raise ValueError("unsafe state file")


@contextmanager
def lock(directory):
    path = Path(directory)
    path.mkdir(mode=0o700, parents=False, exist_ok=True)
    meta = path.lstat()
    if not stat.S_ISDIR(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_mode & 0o077:
        raise ValueError("unsafe state directory")
    fd = os.open(path / "run.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        _regular(fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def _timestamp(value, now, future=MAX_FUTURE_SKEW):
    return type(value) in (int, float) and 0 <= value <= now + future


def read(directory, *, now=None):
    if now is None:
        now = time.time()
    path = Path(directory) / "state.json"
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except FileNotFoundError:
        return empty()
    try:
        _regular(fd)
        if os.fstat(fd).st_size > MAX_BYTES:
            raise ValueError("state too large")
        with os.fdopen(fd, "rb", closefd=False) as fp:
            state = json_object(fp.read(MAX_BYTES + 1))
        # Do not silently reset corrupt state and erase outage evidence.
        if (type(state) is not dict or set(state) != {"schema", "machines", "events", "dropped"}
                or type(state["schema"]) is not int or state["schema"] != 1
                or type(state["machines"]) is not dict
                or set(state["machines"]) != set(KEYS)
                or type(state["events"]) is not list or len(state["events"]) > MAX_EVENTS):
            raise ValueError("state schema invalid")
        for machine in state["machines"].values():
            if (type(machine) is not dict or set(machine) != {"open", "fail", "pass", "notified"}
                    or type(machine["open"]) is not bool
                    or type(machine["fail"]) is not int or not 0 <= machine["fail"] <= 3
                    or type(machine["pass"]) is not int or not 0 <= machine["pass"] <= 2
                    or not _timestamp(machine["notified"], now)):
                raise ValueError("state machine invalid")
        for event in state["events"]:
            if (type(event) is not dict or set(event) != {"id", "key", "event", "at", "created", "attempts", "next"}
                    or event["key"] not in KEYS or event["event"] not in {"incident", "recovery"}
                    or not isinstance(event["id"], str) or len(event["id"]) != 32
                    or not isinstance(event["at"], str) or len(event["at"]) > 40
                    or not _timestamp(event["created"], now)
                    or not _timestamp(event["next"], now, MAX_FUTURE_SKEW + MAX_RETRY)
                    or type(event["attempts"]) is not int or not 0 <= event["attempts"] <= 16):
                raise ValueError("state event invalid")
        if type(state["dropped"]) is not int or not 0 <= state["dropped"] <= 1_000_000_000:
            raise ValueError("state drop counter invalid")
        return state
    finally:
        os.close(fd)


def write(directory, state):
    content = encode(state)
    if len(content) > MAX_BYTES:
        raise ValueError("state too large")
    # One fixed pending slot under the run lock: repeated SIGKILLs cannot collect
    # arbitrarily many temporary files. Validate before truncating an old slot.
    path = Path(directory) / ".state.pending"
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    validated = False
    try:
        _regular(fd)
        validated = True
        os.ftruncate(fd, 0)
        with os.fdopen(fd, "wb") as fp:
            fd = None
            fp.write(content)
            fp.flush()
            os.fsync(fp.fileno())
        os.replace(path, Path(directory) / "state.json")
        dir_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if fd is not None:
            os.close(fd)
        if validated and os.path.exists(path):
            os.unlink(path)
