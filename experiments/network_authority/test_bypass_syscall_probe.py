"""Falsifiers for the experiment 0001H raw syscall observer."""

from __future__ import annotations

import errno
import os
import socket
import unittest
from unittest import mock

from experiments.network_authority.bypass_syscall_probe import (
    ACTIONS,
    BypassProbeError,
    execute,
    observe,
)


class BypassSyscallProbeTests(unittest.TestCase):
    def test_catalog_is_closed(self) -> None:
        self.assertEqual(len(ACTIONS), 8)
        self.assertEqual(len(ACTIONS), len(set(ACTIONS)))
        with self.assertRaises(BypassProbeError):
            execute("unknown", None)

    def test_observer_preserves_errno_without_classifying_it(self) -> None:
        for value in (errno.EPERM, errno.EACCES, errno.EBADF):
            with self.subTest(value=value):
                result = observe("operation", mock.Mock(side_effect=OSError(value, "failure")))
                self.assertEqual(result, {"errno": value, "result": "error", "syscall": "operation"})

    def test_unix_io_uring_raw_and_packet_operations_are_attempted(self) -> None:
        denied = OSError(errno.EPERM, "denied")
        with mock.patch("socket.socket", side_effect=denied) as created:
            pathname = execute("pathname-unix-socket", None)
            abstract = execute("abstract-unix-socket", None)
            raw = execute("raw-and-packet-sockets", None)
        self.assertEqual([item["errno"] for item in pathname + abstract + raw], [errno.EPERM] * 4)
        self.assertEqual(created.call_count, 4)
        with mock.patch(
            "experiments.network_authority.bypass_syscall_probe.io_uring_setup",
            side_effect=denied,
        ) as setup:
            self.assertEqual(execute("io-uring-descriptor-send", None)[0]["errno"], errno.EPERM)
        setup.assert_called_once_with()

    def test_inherited_descriptor_observation_distinguishes_open_and_closed(self) -> None:
        descriptor = os.open("/dev/null", os.O_RDONLY)
        try:
            self.assertEqual(execute("inherited-connected-internet-socket", descriptor)[0]["result"], "success")
        finally:
            os.close(descriptor)
        self.assertEqual(execute("inherited-connected-internet-socket", descriptor)[0]["errno"], errno.EBADF)

    def test_successful_socket_is_closed(self) -> None:
        channel = mock.MagicMock(spec=socket.socket)
        self.assertEqual(observe("socket", lambda: channel)["result"], "success")
        channel.close.assert_called_once_with()

    def test_fork_limit_errno_is_retained(self) -> None:
        with mock.patch("os.fork", side_effect=OSError(errno.EAGAIN, "limited")):
            self.assertEqual(
                execute("fork-exec-at-process-limit", None),
                [{"errno": errno.EAGAIN, "result": "error", "syscall": "fork"}],
            )

    def test_install_race_connect_is_attempted_only_for_frozen_target(self) -> None:
        denied = OSError(errno.EPERM, "denied")
        with mock.patch("socket.socket", side_effect=denied):
            result = execute("concurrent-install-and-connect", None, "127.0.0.2", 8443)
        self.assertEqual(result[0]["errno"], errno.EPERM)
        with self.assertRaises(BypassProbeError):
            execute("concurrent-install-and-connect", None, "127.0.0.1", 443)


if __name__ == "__main__":
    unittest.main()
