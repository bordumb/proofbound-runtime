"""Native falsifiers for experiment 0001F port-only Landlock control."""

from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from experiments.network_authority.routing_landlock_probe import run


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
LANDLOCK_SOURCE = (
    REPOSITORY_ROOT / "experiments/network_authority/routing_landlock_control.c"
)
BOUNDARY_SOURCE = (
    REPOSITORY_ROOT / "experiments/network_authority/routing_child_control.c"
)
PROBE = REPOSITORY_ROOT / "experiments/network_authority/routing_landlock_probe.py"


class RoutingLandlockProbeTests(unittest.TestCase):
    def test_invalid_or_equal_ports_fail_closed(self) -> None:
        self.assertEqual(run(0, 1), 7)
        self.assertEqual(run(443, 443), 7)


class RoutingLandlockHeaderCompatibilityTests(unittest.TestCase):
    def test_control_compiles_against_filesystem_only_landlock_header(self) -> None:
        if zig := shutil.which("zig"):
            compiler = [zig, "cc", "-target", "aarch64-linux-musl"]
        elif sys.platform.startswith("linux") and (cc := shutil.which("cc")):
            compiler = [cc]
        else:
            self.skipTest("Linux compiler unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            linux = root / "linux"
            linux.mkdir()
            (linux / "landlock.h").write_text(
                """\
#ifndef _LINUX_LANDLOCK_H
#define _LINUX_LANDLOCK_H
#include <linux/types.h>
struct landlock_ruleset_attr { __u64 handled_access_fs; };
enum landlock_rule_type { LANDLOCK_RULE_PATH_BENEATH = 1 };
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif
""",
                encoding="ascii",
            )
            output = root / "routing-landlock-control"
            completed = subprocess.run(
                [
                    *compiler,
                    "-I",
                    str(root),
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-O2",
                    str(LANDLOCK_SOURCE),
                    "-o",
                    str(output),
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())


@unittest.skipUnless(
    sys.platform.startswith("linux") and os.geteuid() == 0,
    "native Linux root Landlock test",
)
class RoutingLandlockControlTests(unittest.TestCase):
    def compile(self, source: Path, output: Path) -> None:
        completed = subprocess.run(
            [
                "cc",
                "-std=c11",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-O2",
                str(source),
                "-o",
                str(output),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())

    def test_control_reports_the_exact_kernel_abi(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            control = Path(temporary) / "routing-landlock-control"
            self.compile(LANDLOCK_SOURCE, control)
            completed = subprocess.run(
                [str(control), "--print-abi"],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            self.assertGreaterEqual(int(completed.stdout), 4)

    def test_port_rule_composes_with_common_child_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o755)
            landlock = root / "routing-landlock-control"
            boundary = root / "routing-child-control"
            probe = root / PROBE.name
            landlock_state = root / "landlock-state"
            child_state = root / "child-state"
            shutil.copyfile(PROBE, probe)
            probe.chmod(0o644)
            self.assertEqual(probe.read_bytes(), PROBE.read_bytes())
            self.compile(LANDLOCK_SOURCE, landlock)
            self.compile(BOUNDARY_SOURCE, boundary)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(("127.0.0.1", 0))
                listener.listen(1)
                listener.settimeout(5)
                allowed_port = listener.getsockname()[1]
                denied_port = allowed_port + 1 if allowed_port < 65535 else allowed_port - 1
                errors: list[BaseException] = []

                def accept_once() -> None:
                    try:
                        connection, _peer = listener.accept()
                        connection.close()
                    except BaseException as error:
                        errors.append(error)

                thread = threading.Thread(target=accept_once)
                thread.start()
                completed = subprocess.run(
                    [
                        str(landlock),
                        str(allowed_port),
                        str(landlock_state),
                        "--",
                        str(boundary),
                        str(child_state),
                        "--",
                        sys.executable,
                        str(probe),
                        "--allowed-port",
                        str(allowed_port),
                        "--denied-port",
                        str(denied_port),
                    ],
                    check=False,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=10,
                )
                thread.join(timeout=6)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode(errors="replace"),
            )
            self.assertEqual(
                {path.name for path in landlock_state.iterdir()},
                {"boundary-observations.txt", "ruleset-configuration.txt"},
            )
            configuration = (landlock_state / "ruleset-configuration.txt").read_text(
                encoding="ascii"
            )
            self.assertIn(f"allowed_port={allowed_port}\n", configuration)
            self.assertIn("handled_access=bind-tcp,connect-tcp\n", configuration)
            self.assertTrue((child_state / "seccomp-program.bin").is_file())


if __name__ == "__main__":
    unittest.main()
