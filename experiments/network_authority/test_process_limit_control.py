"""Static and native falsifiers for the experiment process-limit control."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parent / "process_limit_control.c"


class ProcessLimitControlTests(unittest.TestCase):
    def test_source_requires_dropped_identity_and_exact_limit(self) -> None:
        source = SOURCE.read_text()
        for required in ("geteuid() == 0", "getuid() != getgid()", "RLIMIT_NPROC", ".rlim_cur = 1", ".rlim_max = 1"):
            self.assertIn(required, source)

    @unittest.skipUnless(sys.platform.startswith("linux"), "native Linux control")
    def test_source_compiles_with_warnings_as_errors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            completed = subprocess.run(
                ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2", str(SOURCE), "-o", str(Path(temporary) / "control")],
                check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())


if __name__ == "__main__":
    unittest.main()
