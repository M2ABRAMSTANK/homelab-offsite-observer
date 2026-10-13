import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from observer import state


class StateTests(unittest.TestCase):
    def setUp(self):
        self.now = 1_800_000_000
        self.state = state.empty()

    def fail(self, key="wan_edge"):
        for i in range(3):
            state.advance(self.state, key, False, self.now + i)

    def test_three_fail_two_recovery_and_provider_gate(self):
        self.fail()
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
        self.fail("private_queue")
        self.assertTrue(self.state["machines"]["private_queue"]["open"])
        self.assertFalse(self.state["machines"]["wan_edge"]["open"])
        state.advance(self.state, "edge_exposure", False, self.now)
        state.advance(self.state, "edge_exposure", None, self.now + 1)
        self.assertEqual(self.state["machines"]["edge_exposure"]["fail"], 1)
        self.assertEqual(len(self.state["events"]), 1)

    def test_dedup_24h_and_retries_bounded(self):
        self.fail()
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
        self.fail()
        self.state["events"] = [dict(self.state["events"][0], id=f"{i:032x}") for i in range(1010)]
        state.bound(self.state, self.now + 5)
        self.assertEqual(len(self.state["events"]), 1000)
        self.assertEqual(self.state["dropped"], 10)
        with patch.object(state, "MAX_BYTES", 2000):
            state.bound(self.state, self.now + 5)
            self.assertLessEqual(len(state.encode(self.state)), 2000)
        state.bound(self.state, self.now + 86403)
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
