"""Exact transcript tests for experiment 0001H connection reuse."""

from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path

from experiments.network_authority.connection_reuse_fixture import direct_reuse, serve


class ConnectionReuseFixtureTests(unittest.TestCase):
    def test_two_real_connections_are_distinct_and_complete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ready = root / "ready.json"
            observation = root / "observation.json"
            errors = []

            def target() -> None:
                try:
                    serve("127.0.0.1", 0, ready, observation)
                except BaseException as error:
                    errors.append(error)

            thread = threading.Thread(target=target)
            thread.start()
            for _ in range(100):
                if ready.is_file() or errors:
                    break
                time.sleep(0.01)
            self.assertTrue(ready.is_file(), errors)
            port = json.loads(ready.read_bytes())["port"]
            self.assertEqual(direct_reuse("127.0.0.1", port), ["registered-exchange", "excess-exchange"])
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(json.loads(observation.read_bytes())["connection_count"], 2)

    def test_external_endpoint_is_rejected_before_socket_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary, self.assertRaises(Exception):
            serve("0.0.0.0", 0, Path(temporary) / "ready", Path(temporary) / "observation")


if __name__ == "__main__":
    unittest.main()
