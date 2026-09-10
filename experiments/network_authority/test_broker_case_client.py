#!/usr/bin/env python3
"""Falsifiers for broker case construction and attack exit semantics."""

from __future__ import annotations

import errno
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from experiments.network_authority.broker_case_client import (
    ERROR_RESPONSE,
    direct_socket_result,
    frame,
    rejection_result,
    request_for_case,
)
from experiments.network_authority.explicit_broker import MAX_FRAME_BYTES, wire_json


class CaseClientTests(unittest.TestCase):
    def test_direct_entrypoints_resolve_repository_package(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            for name in ("broker_case_client.py", "run_broker_case.py"):
                with self.subTest(name=name):
                    entrypoint = Path(__file__).with_name(name).resolve()
                    completed = subprocess.run(
                        [sys.executable, str(entrypoint), "--help"],
                        cwd=temporary,
                        check=False,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    self.assertEqual(completed.returncode, 0, completed.stderr)

    def test_allowed_and_target_requests_are_exact(self) -> None:
        allowed = request_for_case("allowed-request")
        self.assertEqual(
            allowed[4:],
            wire_json({"operation": "echo", "payload": "bounded payload"}),
        )
        target = request_for_case("target-substitution")
        self.assertIn(b'"target":"denied.test"', target[4:])

    def test_frame_attack_bytes_are_frozen(self) -> None:
        self.assertEqual(request_for_case("zero-frame-denied"), b"\x00\x00\x00\x00")
        self.assertEqual(
            request_for_case("oversized-frame-denied")[:4],
            (MAX_FRAME_BYTES + 1).to_bytes(4, "big"),
        )
        self.assertEqual(request_for_case("truncated-frame-denied"), b"\x00\x00\x00\x02x")
        self.assertEqual(request_for_case("invalid-utf8-denied"), frame(b"\xff"))

    def test_only_closed_error_counts_as_expected_rejection(self) -> None:
        self.assertEqual(rejection_result(ERROR_RESPONSE), 7)
        self.assertEqual(rejection_result(b""), 0)
        self.assertEqual(rejection_result(wire_json({"status": "ok"})), 0)

    def test_foreign_descriptor_fixture_is_observable_before_wrapper(self) -> None:
        with tempfile.TemporaryFile() as foreign:
            self.assertGreaterEqual(os.fstat(foreign.fileno()).st_ino, 0)

    def test_only_eperm_counts_as_direct_socket_denial(self) -> None:
        with mock.patch(
            "experiments.network_authority.broker_case_client.socket.socket",
            side_effect=OSError(errno.EPERM, "denied"),
        ):
            self.assertEqual(direct_socket_result(1), 7)
        with mock.patch(
            "experiments.network_authority.broker_case_client.socket.socket",
            side_effect=OSError(errno.EACCES, "other"),
        ):
            self.assertEqual(direct_socket_result(1), 0)
        created = mock.Mock()
        with mock.patch(
            "experiments.network_authority.broker_case_client.socket.socket",
            return_value=created,
        ):
            self.assertEqual(direct_socket_result(1), 0)
        created.close.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
