"""Falsifiers for shared immutable experiment publication primitives."""

from __future__ import annotations

import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from experiments.network_authority.record_common import write_new


class RecordCommonTests(unittest.TestCase):
    def test_final_path_is_absent_until_all_bytes_are_durable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "ready.json"
            entered_write = threading.Event()
            release_write = threading.Event()
            errors: list[BaseException] = []
            original_write = os.write

            def delayed_write(descriptor: int, data: object) -> int:
                entered_write.set()
                if not release_write.wait(timeout=2):
                    raise RuntimeError("publication test did not release the writer")
                return original_write(descriptor, data)  # type: ignore[arg-type]

            def publish() -> None:
                try:
                    with mock.patch(
                        "experiments.network_authority.record_common.os.write",
                        side_effect=delayed_write,
                    ):
                        write_new(target, b'{"complete":true}\n')
                except BaseException as error:
                    errors.append(error)

            thread = threading.Thread(target=publish)
            thread.start()
            self.assertTrue(entered_write.wait(timeout=2))
            self.assertFalse(target.exists())
            release_write.set()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(target.read_bytes(), b'{"complete":true}\n')
            self.assertEqual(list(root.glob(".*.tmp")), [])

    def test_existing_destination_is_never_replaced_and_temp_is_removed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "result.json"
            write_new(target, b"first\n", 0o640)
            with self.assertRaises(FileExistsError):
                write_new(target, b"second\n")
            self.assertEqual(target.read_bytes(), b"first\n")
            self.assertEqual(target.stat().st_mode & 0o777, 0o640)
            self.assertEqual(list(root.glob(".*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
