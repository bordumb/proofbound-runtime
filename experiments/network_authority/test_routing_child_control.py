"""Native falsifiers for the experiment 0001F A/B child boundary."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.routing_boundary_probe import (
    CASES,
    foreign_descriptor_closed,
    run,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPOSITORY_ROOT / "experiments/network_authority/routing_child_control.c"
PROBE = REPOSITORY_ROOT / "experiments/network_authority/routing_boundary_probe.py"


class RoutingBoundaryProbeTests(unittest.TestCase):
    def test_catalog_is_closed_and_unknown_direct_call_fails(self) -> None:
        self.assertEqual(len(CASES), len(set(CASES)))
        with self.assertRaises(ValueError):
            run("unknown", None)

    def test_foreign_descriptor_probe_distinguishes_open_and_closed(self) -> None:
        descriptor = os.open("/dev/null", os.O_RDONLY)
        self.assertEqual(foreign_descriptor_closed(descriptor), 7)
        os.close(descriptor)
        self.assertEqual(foreign_descriptor_closed(descriptor), 0)


@unittest.skipUnless(
    sys.platform.startswith("linux") and os.geteuid() == 0,
    "native Linux root boundary test",
)
class RoutingChildControlTests(unittest.TestCase):
    def test_complete_native_probe_catalog(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "routing-child-control"
            compiled = subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-O2",
                    str(SOURCE),
                    "-o",
                    str(binary),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr.decode())
            programs: list[bytes] = []
            observations: list[bytes] = []
            for index, case in enumerate(CASES):
                state = root / f"state-{index}"
                foreign_descriptor: int | None = None
                passed: tuple[int, ...] = ()
                command = [
                    str(binary),
                    str(state),
                    "--",
                    sys.executable,
                    str(PROBE),
                    "--case",
                    case,
                ]
                if case == "foreign-descriptor-closed":
                    foreign_descriptor = os.open("/dev/null", os.O_RDONLY)
                    passed = (foreign_descriptor,)
                    command.extend(["--foreign-fd", str(foreign_descriptor)])
                try:
                    completed = subprocess.run(
                        command,
                        pass_fds=passed,
                        check=False,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5,
                    )
                finally:
                    if foreign_descriptor is not None:
                        os.close(foreign_descriptor)
                self.assertEqual(
                    completed.returncode,
                    0,
                    f"{case}: {completed.stderr.decode(errors='replace')}",
                )
                programs.append((state / "seccomp-program.bin").read_bytes())
                observations.append((state / "boundary-observations.txt").read_bytes())
            self.assertTrue(programs[0])
            self.assertEqual(len(set(programs)), 1)
            self.assertEqual(len(set(observations)), 1)
            self.assertIn(b"socket_policy=inet-stream-only\n", observations[0])


if __name__ == "__main__":
    unittest.main()
