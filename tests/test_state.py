import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from observer import state


class StateTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        self.state = state.empty()

    def open_incident(self, key="wan_edge"):
        for i in range(3):
            state.advance(self.state, key, False, self.now + i)

    def test_three_fail_two_recovery_and_provider_gate(self):
        self.open_incident()
        machine = self.state["machines"]["wan_edge"]
        self.assertTrue(machine["open"])
        self.assertEqual([e["event"] for e in self.state["events"]], ["incident"])
        for i in range(3):
            state.advance(self.state, "wan_edge", True, self.now + 4 + i, delivery_ok=False)
        self.assertTrue(machine["open"])
        state.advance(self.state, "wan_edge", True, self.now + 8, delivery_ok=True)
        self.assertFalse(machine["open"])
        self.assertEqual([e["event"] for e in self.state["events"]], ["incident", "recovery"])

    def test_independent_and_inconclusive_streaks(self):
        self.open_incident("private_queue")
        self.assertTrue(self.state["machines"]["private_queue"]["open"])
        self.assertFalse(self.state["machines"]["wan_edge"]["open"])
        state.advance(self.state, "edge_exposure", False, self.now)
        state.advance(self.state, "edge_exposure", None, self.now + 1)
        self.assertEqual(self.state["machines"]["edge_exposure"]["fail"], 1)
        self.assertEqual(len(self.state["events"]), 1)

    def test_inconclusive_private_cycle_retains_open_incident_and_reminder(self):
        self.open_incident("private_queue")
        initial = self.state["events"][0]
        state.advance(self.state, "private_queue", None, initial["created"] + state.MAX_AGE)
        machine = self.state["machines"]["private_queue"]
        self.assertTrue(machine["open"])
        self.assertEqual([event["event"] for event in self.state["events"]], ["incident", "incident"])

    def test_dedup_24h_and_retries_bounded(self):
        self.open_incident()
        for i in range(100):
            state.advance(self.state, "wan_edge", False, self.now + 3 + i)
        self.assertEqual(len(self.state["events"]), 1)
        state.advance(self.state, "wan_edge", False, self.now + 86402)
        self.assertEqual(len(self.state["events"]), 2)
        event = self.state["events"][-1]
        for i in range(100):
            state.retry(event, self.now)
            self.assertLessEqual(event["next"] - self.now, 300)
            self.assertLessEqual(event["attempts"], 16)

    def test_spool_count_bytes_age(self):
        self.open_incident()
        self.state["events"] = [dict(self.state["events"][0], id=f"{i:032x}") for i in range(1010)]
        state.bound(self.state, self.now + 5)
        self.assertEqual(len(self.state["events"]), 1000)
        self.assertEqual(self.state["dropped"], 10)
        with patch.object(state, "MAX_BYTES", 2000):
            state.bound(self.state, self.now + 5)
            self.assertLessEqual(len(state.encode(self.state)), 2000)
        state.bound(self.state, self.now + 86403)
        self.assertEqual(self.state["events"], [])

    def test_spool_retains_short_clock_rollback_but_drops_extreme_future_event(self):
        self.open_incident()
        queued = self.state["events"][0]
        state.bound(self.state, queued["created"] - 10)
        self.assertEqual(self.state["events"], [queued])
        queued["created"] = self.now + state.MAX_FUTURE_SKEW + 1
        state.bound(self.state, self.now)
        self.assertEqual(self.state["events"], [])

    def test_atomic_owner_mode_no_overlap_and_corruption(self):
        with tempfile.TemporaryDirectory() as directory:
            with state.lock(directory):
                with self.assertRaises(BlockingIOError):
                    with state.lock(directory):
                        pass
                state.write(directory, self.state)
                self.assertEqual(state.read(directory), self.state)
                path = Path(directory) / "state.json"
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                path.write_text('{"schema":1}')
                with self.assertRaises(ValueError):
                    state.read(directory)

    def test_refuse_symlink_and_world_readable_state(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "state.json"
            path.write_text("{}")
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                state.read(directory)
            path.unlink()
            path.symlink_to("/dev/null")
            with self.assertRaises(OSError):
                state.read(directory)

    def test_fixed_pending_slot_reuses_interrupted_write_simulation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".state.pending"
            for _ in range(3):
                with state.lock(directory):
                    # Represents an interrupted write before the atomic rename.
                    path.write_bytes(b"orphan" * 10000)
                    path.chmod(0o600)
                    state.write(directory, self.state)
                    self.assertFalse(path.exists())
                    self.assertEqual(state.read(directory), self.state)
                    self.assertEqual({p.name for p in Path(directory).iterdir()}, {"state.json", "run.lock"})

    def test_hardlinked_pending_slot_cannot_truncate_unrelated_file(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "keep"
            source.write_bytes(b"preserve")
            source.chmod(0o600)
            os.link(source, Path(directory) / ".state.pending")
            with self.assertRaises(ValueError):
                state.write(directory, self.state)
            self.assertEqual(source.read_bytes(), b"preserve")
            with self.assertRaises(ValueError):
                from observer.config import secure_file
                secure_file(source)

    def test_nonfinite_state_timestamp_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            state.write(directory, self.state)
            path = Path(directory) / "state.json"
            body = path.read_text().replace('"notified":0', '"notified":1e999', 1)
            path.write_text(body)
            with self.assertRaises(ValueError):
                state.read(directory)

    def test_list_shaped_machines_is_refused_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            state.write(directory, self.state)
            path = Path(directory) / "state.json"
            body = json.loads(path.read_text())
            body["machines"] = list(state.KEYS)
            path.write_text(json.dumps(body))
            with self.assertRaises(ValueError):
                state.read(directory)

    def test_boolean_schema_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            state.write(directory, self.state)
            path = Path(directory) / "state.json"
            body = json.loads(path.read_text())
            body["schema"] = True
            path.write_text(json.dumps(body))
            with self.assertRaises(ValueError):
                state.read(directory)

    def test_impossible_persisted_timestamps_are_refused(self):
        now = time.time()
        persisted = state.empty()
        for i in range(3):
            state.advance(persisted, "wan_edge", False, now + i)
        cases = (("notified", 10 ** 400), ("notified", now + state.MAX_FUTURE_SKEW + 1),
                 ("created", 10 ** 400), ("created", now + state.MAX_FUTURE_SKEW + 1),
                 ("next", 1e300), ("next", now + state.MAX_FUTURE_SKEW + state.MAX_RETRY + 1))
        for field, value in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                state.write(directory, persisted)
                path = Path(directory) / "state.json"
                body = json.loads(path.read_text())
                if field == "notified":
                    body["machines"]["wan_edge"][field] = value
                else:
                    body["events"][0][field] = value
                path.write_text(json.dumps(body))
                with self.assertRaises(ValueError):
                    state.read(directory)

    def test_persisted_short_clock_rollback_timestamps_are_accepted(self):
        now = time.time()
        persisted = state.empty()
        for i in range(3):
            state.advance(persisted, "wan_edge", False, now + i)
        persisted["events"][0]["created"] = now + state.MAX_FUTURE_SKEW
        persisted["events"][0]["next"] = now + state.MAX_FUTURE_SKEW + state.MAX_RETRY
        persisted["machines"]["wan_edge"]["notified"] = now + state.MAX_FUTURE_SKEW
        with tempfile.TemporaryDirectory() as directory:
            state.write(directory, persisted)
            self.assertEqual(state.read(directory, now=now), persisted)
