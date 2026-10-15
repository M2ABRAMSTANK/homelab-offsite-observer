from contextlib import redirect_stdout, redirect_stderr
import io
import json
import multiprocessing
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from observer import config, runner, state
from observer.__main__ import main
from observer.transport import Response

ROOT = Path(__file__).resolve().parents[1]


def hanging(**kwargs):
    time.sleep(60)


class RuntimeTests(unittest.TestCase):
    def test_default_dry_run_zero_network_or_writes(self):
        with patch("observer.runner.request", side_effect=AssertionError("network")), \
                patch("observer.__main__.lock", side_effect=AssertionError("writes")), \
                redirect_stdout(io.StringIO()) as output:
            self.assertEqual(main(["--config", str(ROOT / "config.example.json")]), 0)
        self.assertEqual(json.loads(output.getvalue())["network_requests"], 0)
        self.assertEqual(json.loads(output.getvalue())["state_writes"], 0)

    def test_live_disabled_fails_closed_and_redacts(self):
        with patch("observer.__main__.os.geteuid", return_value=1000), \
                patch("observer.__main__.cycle", side_effect=AssertionError("live")), \
                redirect_stderr(io.StringIO()) as output:
            self.assertEqual(main(["--config", str(ROOT / "config.example.json"), "--live"]), 2)
        self.assertEqual(json.loads(output.getvalue())["error"], "configuration_or_runtime_failure")
        self.assertNotIn("example.invalid", output.getvalue())

    def test_unknown_configuration_and_invalid_negative_contract(self):
        base = config.load(ROOT / "config.example.json")
        mutations = [("extra", True), ("enabled", 1), ("observer_id", "secret/injected")]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for key, value in mutations:
                cfg = dict(base, **{key: value})
                path.write_text(json.dumps(cfg))
                with self.assertRaises(ValueError):
                    config.load(path)
            base["negative"][0]["statuses"] = [200]
            path.write_text(json.dumps(base))
            with self.assertRaises(ValueError):
                config.load(path)

    def test_clock_failure_is_explicit(self):
        with patch("observer.runner.subprocess.run", side_effect=OSError("missing")):
            self.assertFalse(runner.clock_trusted())
        for answer, expected in [(b"no\n", False), (b"yes\n", True), (b"unknown\n", False)]:
            with patch("observer.runner.subprocess.run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = answer
                self.assertEqual(runner.clock_trusted(), expected)

    def test_child_probe_timeout_bounds_dns_and_slow_drip(self):
        baseline = len(multiprocessing.active_children())
        started = time.monotonic()
        responses = runner.parallel({"slow": {}, "also_slow": {}}, 0.08, function=hanging)
        self.assertLess(time.monotonic() - started, 1)
        self.assertEqual({r.kind for r in responses.values()}, {"timeout"})
        self.assertEqual(len(multiprocessing.active_children()), baseline)

    def test_wan_loss_suppresses_negatives_and_spools_incident(self):
        cfg = config.load(ROOT / "config.example.json")
        groups = []
        def probes(jobs, timeout):
            groups.append(set(jobs))
            return {name: Response("network_error") for name in jobs}
        with tempfile.TemporaryDirectory() as directory, \
                patch("observer.runner.parallel", side_effect=probes), \
                patch("observer.runner._provider", return_value=False) as provider, \
                patch("observer.runner.clock_trusted", return_value=True):
            for _ in range(3):
                evidence = runner.cycle(cfg, {"provider_token": "test-secret"}, directory)
            self.assertTrue(evidence["incidents"]["wan_edge"])
            self.assertTrue(evidence["incidents"]["provider_path"])
            self.assertIsNone(evidence["outcomes"]["edge_exposure"])
            self.assertEqual(groups, [{"readiness", "freshness"}] * 3)
            events = state.read(directory)["events"]
            self.assertEqual({e["key"] for e in events}, {"wan_edge", "provider_path"})
            self.assertTrue(any(c.kwargs.get("heartbeat") for c in provider.call_args_list))
            self.assertNotIn("test-secret", json.dumps(evidence))
            self.assertNotIn("body", json.dumps(evidence))

    def test_fresh_eligible_unexpected_negative_opens_separate_incident(self):
        cfg = config.load(ROOT / "config.example.json")
        def probes(jobs, timeout):
            result = {}
            for name, kw in jobs.items():
                data = {"status": "ok"} if name == "readiness" else {
                    "schema": 1, "nonce": kw.get("headers", {}).get("X-Observer-Nonce"),
                    "generated_at": runner.utc(time.time())}
                result[name] = Response("http", tls=True, status=200,
                                        headers={"cache-control": "no-store"}, body=json.dumps(data).encode())
            return result
        with tempfile.TemporaryDirectory() as directory, \
                patch("observer.runner.parallel", side_effect=probes), \
                patch("observer.runner._provider", return_value=True), \
                patch("observer.runner.clock_trusted", return_value=True):
            for _ in range(3):
                evidence = runner.cycle(cfg, {"provider_token": "test-secret"}, directory)
            self.assertTrue(evidence["incidents"]["edge_exposure"])
            self.assertFalse(evidence["incidents"]["wan_edge"])
            self.assertEqual(evidence["spool_events"], 0)

    def test_oversized_private_age_preserves_incidents_and_event_delivery(self):
        cfg = config.load(ROOT / "config.example.json")
        cfg["private"]["enabled"] = True
        now = 1_800_000_000
        groups = []

        def probes(jobs, timeout):
            groups.append(set(jobs))
            result = {}
            for name, kw in jobs.items():
                data = {"status": "ok"} if name == "readiness" else {
                    "schema": 1, "nonce": kw.get("headers", {}).get("X-Observer-Nonce"),
                    "generated_at": runner.utc(now)}
                if name == "private":
                    data.update(queue={"ready": True, "active": 0,
                                       "oldest_pending_seconds": 10**400},
                                security_alerts_firing=0)
                # HTTP 200 on either negative target is unexpected public exposure.
                result[name] = Response("http", tls=True, status=200,
                                        headers={"cache-control": "no-store"}, body=json.dumps(data).encode())
            return result

        with tempfile.TemporaryDirectory() as directory, \
                patch("observer.runner.parallel", side_effect=probes), \
                patch("observer.runner._provider", return_value=True) as provider, \
                patch("observer.runner.clock_trusted", return_value=True), \
                patch("observer.runner.time.time", return_value=now):
            pending = state.empty()
            for _ in range(3):
                state.advance(pending, "wan_edge", False, now - 30)
            queued_id = pending["events"][0]["id"]
            state.write(directory, pending)
            for count in range(1, 4):
                evidence = runner.cycle(cfg, {"provider_token": "test-secret",
                                              "private_token": "private-test-secret"}, directory)
                persisted = state.read(directory)
                self.assertIs(evidence["outcomes"]["private_queue"], False)
                self.assertIs(evidence["outcomes"]["wan_edge"], True)
                self.assertIs(evidence["outcomes"]["edge_exposure"], False)
                for key in ("private_queue", "edge_exposure"):
                    self.assertEqual(persisted["machines"][key]["fail"], count)
                    self.assertEqual(persisted["machines"][key]["open"], count == 3)
                self.assertEqual(evidence["events_delivered"], 2 if count == 3 else 1)
                self.assertEqual(persisted["events"], [])
            self.assertEqual(groups, [{"readiness", "freshness", "private"},
                                      {spec["name"] for spec in cfg["negative"]}] * 3)
            heartbeats = [call for call in provider.call_args_list if call.kwargs.get("heartbeat")]
            events = [call.args[2] for call in provider.call_args_list if not call.kwargs.get("heartbeat")]
            self.assertEqual(len(heartbeats), 3)
            self.assertEqual(events[0]["id"], queued_id)
            self.assertEqual([(event["key"], event["event"]) for event in events], [
                ("wan_edge", "incident"), ("wan_edge", "recovery"),
                ("private_queue", "incident"), ("edge_exposure", "incident")])
