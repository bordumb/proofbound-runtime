"""Falsifiers for the connection reuse boundary client."""

from __future__ import annotations

import unittest
from unittest import mock

from experiments.network_authority.connection_reuse_client import execute


class ConnectionReuseClientTests(unittest.TestCase):
    def test_direct_broker_and_channel_dispatch_exactly(self) -> None:
        with mock.patch("experiments.network_authority.connection_reuse_client.direct_reuse", return_value=["direct"]) as direct:
            self.assertEqual(execute("direct", "127.0.0.1", 443, None), ["direct"])
        direct.assert_called_once_with("127.0.0.1", 443)
        with mock.patch("experiments.network_authority.connection_reuse_client.broker_client", return_value=["broker"]):
            self.assertEqual(execute("broker", None, None, 7), ["broker"])
        with mock.patch("experiments.network_authority.connection_reuse_client.channel_client", return_value=["channel"]):
            self.assertEqual(execute("channel", None, None, 8), ["channel"])

    def test_cross_shape_arguments_fail_closed(self) -> None:
        for values in (("direct", None, 443, None), ("broker", "127.0.0.1", None, 7), ("channel", None, None, None)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                execute(*values)


if __name__ == "__main__":
    unittest.main()
