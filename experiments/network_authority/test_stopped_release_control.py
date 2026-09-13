"""Static and native tests for the experiment stopped-release control."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parent / "stopped_release_control.c"


class StoppedReleaseControlTests(unittest.TestCase):
    def test_source_orders_stop_observation_acknowledgement_and_exec(self) -> None:
        source = SOURCE.read_text()
        self.assertLess(source.index("raise(SIGSTOP)"), source.index('"boundary-acknowledged.txt"'))
        self.assertLess(source.index('"boundary-acknowledged.txt"'), source.index("execvp(argv[3]"))
        self.assertIn("waitpid(child, &status, WUNTRACED)", source)
        self.assertIn('"child-stopped.txt"', source)

    @unittest.skipUnless(sys.platform.startswith("linux"), "native Linux control")
    def test_native_child_cannot_run_before_acknowledgement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "control"
            compiled = subprocess.run(["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(SOURCE), "-o", str(binary)], check=False, capture_output=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr.decode())
            completed = subprocess.run([str(binary), str(root), "--", "/bin/sh", "-c", 'test -f "$1/boundary-acknowledged.txt"', "sh", str(root)], check=False, capture_output=True)
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertEqual((root / "child-stopped.txt").read_bytes(), b"child-stopped\n")


if __name__ == "__main__":
    unittest.main()
