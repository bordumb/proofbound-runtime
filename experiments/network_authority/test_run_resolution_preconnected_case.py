"""Falsifiers for resolution preconnected one-case orchestration."""

from __future__ import annotations

import argparse
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from experiments.network_authority.decision_http_fixture import script_exchange
from experiments.network_authority.record_common import canonical_json
from experiments.network_authority.run_resolution_preconnected_case import (
    _relay_http,
    child_command,
    run,
)


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
MATRIX = REPOSITORY_ROOT / "experiments/network_authority/decision-matrix.toml"


class ResolutionPreconnectedCaseTests(unittest.TestCase):
    def arguments(self, root: Path, case: str) -> argparse.Namespace:
        registered = root / "registered.json"
        substitute = root / "substitute.json"
        registered.write_bytes(canonical_json({"resolver": "registered"}))
        substitute.write_bytes(canonical_json({"resolver": "substitute"}))
        return argparse.Namespace(
            case=case,
            repository_root=REPOSITORY_ROOT,
            matrix=MATRIX,
            case_root=root / "case",
            raw_output=root / "case/raw-cell.json",
            child_control=root / "child-control",
            client=root / "client.py",
            allowed_certificate=root / "certificate.pem",
            allowed_private_key=root / "private-key.pem",
            registered_resolver=registered,
            substitute_resolver=substitute,
        )

    def test_child_command_binds_cookie_peer_and_exact_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            arguments = self.arguments(root, "redirect-other-port")
            command = child_command(
                arguments,
                root / "invoke",
                7,
                99,
                {"pid": 10, "uid": 20, "gid": 30},
                "channel-redirect-port",
            )
            self.assertEqual(command[1:7], ["7", "99", "10", "20", "30", str(root / "invoke/child-boundary")])
            self.assertIn("channel-redirect-port", command)

    def test_http_relay_preserves_exact_request_and_response(self) -> None:
        local_parent, local_child = socket.socketpair()
        remote_parent, remote_fixture = socket.socketpair()
        request, response, _event = script_exchange("redirect-host")
        errors: list[BaseException] = []

        def child() -> None:
            try:
                local_child.sendall(request)
                local_child.shutdown(socket.SHUT_WR)
                received = bytearray()
                while len(received) < len(response):
                    received.extend(local_child.recv(len(response) - len(received)))
                self.assertEqual(bytes(received), response)
            except BaseException as error:
                errors.append(error)
            finally:
                local_child.close()

        def fixture() -> None:
            try:
                received = bytearray()
                while len(received) < len(request):
                    received.extend(remote_fixture.recv(len(request) - len(received)))
                self.assertEqual(bytes(received), request)
                remote_fixture.sendall(response)
                remote_fixture.shutdown(socket.SHUT_WR)
            except BaseException as error:
                errors.append(error)
            finally:
                remote_fixture.close()

        child_thread = threading.Thread(target=child)
        fixture_thread = threading.Thread(target=fixture)
        child_thread.start()
        fixture_thread.start()
        class PlainProtected:
            def sendall(self, data: bytes) -> None:
                remote_parent.sendall(data)
            def recv(self, size: int) -> bytes:
                return remote_parent.recv(size)
            def unwrap(self) -> socket.socket:
                return remote_parent
        _relay_http(local_parent, PlainProtected(), "redirect-host")  # type: ignore[arg-type]
        local_parent.close()
        child_thread.join(timeout=2)
        fixture_thread.join(timeout=2)
        self.assertEqual(errors, [])

    def test_ambient_and_resolver_substitution_stop_before_connector(self) -> None:
        for case, field in (
            ("ambient-all-proxy", "plan_rejection"),
            ("resolver-configuration-substitution", "prelaunch_rejection"),
        ):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                arguments = self.arguments(Path(temporary), case)
                with mock.patch("os.geteuid", return_value=0), mock.patch(
                    "experiments.network_authority.run_resolution_preconnected_case.open_authenticated"
                ) as connected:
                    raw = run(arguments)
                connected.assert_not_called()
                self.assertIsNotNone(raw[field])
                self.assertFalse(raw["client_started"])


if __name__ == "__main__":
    unittest.main()
