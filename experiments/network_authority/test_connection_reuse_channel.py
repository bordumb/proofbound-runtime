"""Exact one-use mediated protocol tests for experiment 0001H."""

from __future__ import annotations

import socket
import threading
import unittest

from experiments.network_authority.connection_reuse_channel import (
    broker_client, broker_server, channel_client, channel_server,
)


class ConnectionReuseChannelTests(unittest.TestCase):
    def exchange(self, server, client, expected: list[str]) -> None:
        parent, child = socket.socketpair()
        results = []
        errors = []

        def target() -> None:
            try:
                results.append(server(parent.detach()))
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=target)
        thread.start()
        try:
            self.assertEqual(client(child.fileno()), expected)
        finally:
            child.close()
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(results, [expected])

    def test_broker_rejects_second_operation(self) -> None:
        self.exchange(broker_server, broker_client, ["registered-exchange", "operation-rejected"])

    def test_channel_closes_after_first_exchange(self) -> None:
        self.exchange(channel_server, channel_client, ["registered-exchange", "channel-closed-after-registered-exchange"])


if __name__ == "__main__":
    unittest.main()
