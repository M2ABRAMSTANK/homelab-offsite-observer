"""No daemon or listeners: bounded child probes, one locked atomic state update."""
import json
import multiprocessing
import secrets
import subprocess
import time

from .checks import negative, utc, validate
from .state import advance, bound, read, retry, write
from .transport import request, Response

BUDGET = 19  # Reserve one second inside the unit's hard 20-second timeout.


def clock_trusted():
    try:
        result = subprocess.run(["/usr/bin/timedatectl", "show", "-p", "NTPSynchronized", "--value"],
                                capture_output=True, timeout=1, check=False)
        return result.returncode == 0 and result.stdout.strip() == b"yes"
    except (OSError, subprocess.TimeoutExpired):
        return False


def _worker(pipe, function, kwargs):
    try:
        pipe.send(function(**kwargs))
    except Exception:
        # Fixed error class only: never exception text that may contain a URL or token.
        pipe.send(Response("worker_error"))
    finally:
        pipe.close()


def parallel(jobs, timeout, function=request):
    """Child lifetimes also bound DNS lookup and slow-drip responses."""
    if not jobs:
        return {}
    context = multiprocessing.get_context("fork")
    deadline = time.monotonic() + max(0, timeout)
    processes = []
    pending = {}
    results = {}
    try:
        for name, kwargs in jobs.items():
            receiver, sender = context.Pipe(duplex=False)
            process = context.Process(target=_worker, args=(sender, function, kwargs))
            process.start()
            sender.close()
            processes.append(process)
            pending[name] = receiver
        while pending and time.monotonic() < deadline:
            for name, pipe in list(pending.items()):
                if pipe.poll(0):
                    try:
                        results[name] = pipe.recv()
                    except EOFError:
                        results[name] = Response("worker_error")
                    pipe.close()
                    del pending[name]
            if pending:
                time.sleep(min(0.01, max(0, deadline - time.monotonic())))
        for name in pending:
            results[name] = Response("timeout", latency_ms=round(timeout * 1000))
    finally:
        for pipe in pending.values():
            pipe.close()
        for process in processes:
            if process.is_alive():
                process.kill()
            process.join(timeout=0.1)
            process.close()
    return results


def _provider(cfg, token, payload, identifier, deadline, heartbeat=False):
    remaining = min(2, deadline - time.monotonic() - 0.15)
    if remaining <= 0:
        return False
    response = parallel({"provider": {
        "url": cfg["provider"]["heartbeat_url" if heartbeat else "events_url"],
        "timeout": remaining,
        "headers": {"Authorization": f"Bearer {token}", "Idempotency-Key": identifier},
        "payload": json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("ascii"),
    }}, remaining)["provider"]
    return response.tls and response.kind == "http" and response.status in {200, 202, 204}


def cycle(cfg, credentials, directory):
    deadline = time.monotonic() + BUDGET
    state = read(directory, now=time.time())
    trusted = clock_trusted()
    now = time.time()
    # This heartbeat describes observer execution, even when every home check fails.
    # Never replay/spool liveness: delayed heartbeats could conceal observer death.
    provider_ok = _provider(cfg, credentials["provider_token"], {
        "schema": 1, "observer_id": cfg["observer_id"], "type": "heartbeat",
        "at": utc(now), "clock_trusted": trusted,
    }, secrets.token_hex(16), deadline, heartbeat=True)
    nonce = secrets.token_hex(16)
    jobs = {
        "readiness": {"url": cfg["readiness"]["url"]},
        "freshness": {"url": cfg["freshness"]["url"], "headers": {"X-Observer-Nonce": nonce}},
    }
    if cfg["private"]["enabled"]:
        jobs["private"] = {"url": cfg["private"]["url"], "proxy": cfg["private"]["socks_port"],
                           "headers": {"X-Observer-Nonce": nonce,
                                       "Authorization": f"Bearer {credentials['private_token']}"}}
    responses = parallel(jobs, min(8, max(0, deadline - time.monotonic() - 0.3)))
    now = time.time()
    wan = (validate(responses["readiness"], "readiness", expected=cfg["readiness"]["expected"])
           and validate(responses["freshness"], "freshness", nonce=nonce, now=now, clock=trusted))
    private = None
    if cfg["private"]["enabled"]:
        private = validate(responses["private"], "private", nonce=nonce, now=now, clock=trusted,
                           max_age=cfg["private"]["max_pending_seconds"])
    exposure = None
    if wan:
        negatives = parallel({spec["name"]: {"url": spec["url"], "negative": True}
                              for spec in cfg["negative"]},
                             min(8, max(0, deadline - time.monotonic() - 0.3)))
        outcomes = [negative(negatives[spec["name"]], spec) for spec in cfg["negative"]]
        exposure = False if False in outcomes else (True if all(v is True for v in outcomes) else None)
        responses.update({"negative_" + k: v for k, v in negatives.items()})
    now = time.time()
    for key, outcome in {"wan_edge": wan, "private_queue": private, "edge_exposure": exposure,
                         "clock": trusted, "provider_path": provider_ok}.items():
        advance(state, key, outcome, now, delivery_ok=provider_ok)
    bound(state, now)
    # Save before sending: a killed process may replay an event, never lose a newly opened incident.
    write(directory, state)
    delivered = 0
    # Preserve retained queue order; expiry can remove an undelivered incident.
    for event in list(state["events"]):
        if event["next"] > now or deadline - time.monotonic() < 0.3:
            break
        payload = {"schema": 1, "observer_id": cfg["observer_id"], "type": "event",
                   "id": event["id"], "key": event["key"], "event": event["event"], "at": event["at"]}
        if _provider(cfg, credentials["provider_token"], payload, event["id"], deadline):
            state["events"].remove(event)
            delivered += 1
        else:
            retry(event, now)
            break
    bound(state, now)
    write(directory, state)
    # Only fixed names/classes and aggregate counters are evidence. No URLs/body/headers.
    return {"schema": 1, "at": utc(now), "clock_trusted": trusted,
            "checks": {name: {"class": response.kind, "latency_ms": response.latency_ms}
                       for name, response in responses.items()},
            "outcomes": {"wan_edge": wan, "edge_exposure": exposure, "private_queue": private},
            "provider_heartbeat": provider_ok, "events_delivered": delivered,
            "spool_events": len(state["events"]), "spool_dropped": state["dropped"],
            "incidents": {key: value["open"] for key, value in state["machines"].items()}}
