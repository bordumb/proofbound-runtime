"""Native falsifier for the experiment 0001F dual-stack BPF endpoint maps."""

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

from experiments.network_authority.routing_endpoint_probe import run


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ENDPOINT_SOURCE = (
    REPOSITORY_ROOT / "experiments/network_authority/routing_endpoint_control.c"
)
BOUNDARY_SOURCE = (
    REPOSITORY_ROOT / "experiments/network_authority/routing_child_control.c"
)
PROBE = REPOSITORY_ROOT / "experiments/network_authority/routing_endpoint_probe.py"


def native_prerequisites() -> bool:
    """Report whether this process can execute the privileged native test."""

    return (
        sys.platform.startswith("linux")
        and os.geteuid() == 0
        and Path("/sys/fs/cgroup/cgroup.controllers").is_file()
        and Path("/sys/kernel/btf/vmlinux").is_file()
    )


class RoutingEndpointProbeTests(unittest.TestCase):
    def test_invalid_port_fails_before_socket_creation(self) -> None:
        self.assertEqual(run(0), 7)
        self.assertEqual(run(65535), 7)


@unittest.skipUnless(native_prerequisites(), "native Linux root cgroup-BPF test")
class RoutingEndpointControlTests(unittest.TestCase):
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

    def listener(self, family: int, port: int) -> socket.socket:
        listener = socket.socket(family, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if family == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind(("127.0.0.1" if family == socket.AF_INET else "::1", port))
        listener.listen(1)
        listener.settimeout(5)
        return listener

    def accept_once(
        self, listener: socket.socket, errors: list[BaseException]
    ) -> None:
        try:
            connection, _peer = listener.accept()
            connection.close()
        except BaseException as error:
            errors.append(error)

    def test_maps_select_only_exact_ipv4_and_ipv6_tuples(self) -> None:
        current = ""
        for line in Path("/proc/self/cgroup").read_text(encoding="ascii").splitlines():
            if line.startswith("0::"):
                current = line[3:]
        self.assertTrue(current.startswith("/"))
        cgroup_parent = Path("/sys/fs/cgroup") / current.lstrip("/")
        cgroup = cgroup_parent / f"proofbound-routing-test-{os.getpid()}"
        self.assertFalse(cgroup.exists())
        cgroup.mkdir()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                root.chmod(0o755)
                endpoint = root / "routing-endpoint-control"
                boundary = root / "routing-child-control"
                probe = root / PROBE.name
                state = root / "endpoint-state"
                child_state = root / "child-state"
                shutil.copyfile(PROBE, probe)
                probe.chmod(0o644)
                self.assertEqual(probe.read_bytes(), PROBE.read_bytes())
                self.compile(ENDPOINT_SOURCE, endpoint)
                self.compile(BOUNDARY_SOURCE, boundary)

                listener4 = self.listener(socket.AF_INET, 0)
                port = listener4.getsockname()[1]
                if port == 65535:
                    listener4.close()
                    listener4 = self.listener(socket.AF_INET, 0)
                    port = listener4.getsockname()[1]
                listener6 = self.listener(socket.AF_INET6, port)
                errors: list[BaseException] = []
                threads = [
                    threading.Thread(target=self.accept_once, args=(listener4, errors)),
                    threading.Thread(target=self.accept_once, args=(listener6, errors)),
                ]
                for thread in threads:
                    thread.start()
                try:
                    command = [
                        str(endpoint),
                        str(cgroup),
                        "127.0.0.1",
                        "::1",
                        str(port),
                        str(state),
                        "--",
                        str(boundary),
                        str(child_state),
                        "--",
                        sys.executable,
                        str(probe),
                        "--port",
                        str(port),
                    ]
                    completed = subprocess.run(
                        command,
                        check=False,
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=10,
                    )
                finally:
                    for thread in threads:
                        thread.join(timeout=6)
                    listener6.close()
                    listener4.close()
                self.assertEqual(errors, [])
                self.assertEqual(
                    completed.returncode,
                    0,
                    completed.stderr.decode(errors="replace"),
                )
                expected_files = {
                    "boundary-observations.txt",
                    "connect4-map-key.bin",
                    "connect4-program.bin",
                    "connect4-verifier.log",
                    "connect6-map-key.bin",
                    "connect6-program.bin",
                    "connect6-verifier.log",
                    "map-value.bin",
                }
                self.assertEqual({item.name for item in state.iterdir()}, expected_files)
                self.assertEqual((state / "map-value.bin").read_bytes(), b"\x01")
                self.assertEqual((state / "connect4-map-key.bin").stat().st_size, 8)
                self.assertEqual((state / "connect6-map-key.bin").stat().st_size, 20)
                observation = (state / "boundary-observations.txt").read_text(
                    encoding="ascii"
                )
                self.assertIn("map_entries=1\n", observation)
                self.assertIn("map_readback=true\n", observation)
                self.assertTrue((child_state / "seccomp-program.bin").stat().st_size)
        finally:
            cgroup.rmdir()


if __name__ == "__main__":
    unittest.main()
