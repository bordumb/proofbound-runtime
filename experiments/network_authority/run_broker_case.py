#!/usr/bin/env python3
"""Run one broker case through the native child boundary."""

from __future__ import annotations

import argparse
import os
import socket
import subprocess
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from experiments.network_authority.broker_case_client import CASES


NO_BROKER = {
    "broker-crash-denied",
    "foreign-descriptor-denied",
}


def run(arguments: argparse.Namespace) -> int:
    """Run one child and optional broker without interpreting attack success."""

    parent_channel, child_channel = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    foreign_descriptor: int | None = None
    if arguments.case == "foreign-descriptor-denied":
        foreign_descriptor = os.open("/dev/null", os.O_RDONLY)

    broker: subprocess.Popen[bytes] | None = None
    broker_stdout = arguments.broker_stdout.open("xb")
    broker_stderr = arguments.broker_stderr.open("xb")
    try:
        if arguments.case not in NO_BROKER:
            endpoint_ip = (
                arguments.denied_endpoint_ip
                if arguments.case == "wrong-certificate-denied"
                else arguments.allowed_endpoint_ip
            )
            broker_command = [
                sys.executable,
                "-m",
                "experiments.network_authority.explicit_broker",
                "broker",
                "--fd",
                str(parent_channel.fileno()),
                "--endpoint-ip",
                endpoint_ip,
                "--endpoint-port",
                str(arguments.endpoint_port),
                "--service",
                "allowed.test",
                "--ca-certificate",
                str(arguments.allowed_certificate),
            ]
            broker = subprocess.Popen(
                broker_command,
                cwd=arguments.repository_root,
                pass_fds=(parent_channel.fileno(),),
                stdin=subprocess.DEVNULL,
                stdout=broker_stdout,
                stderr=broker_stderr,
            )
        parent_channel.close()

        command = [
            str(arguments.wrapper),
            str(child_channel.fileno()),
            str(arguments.state_directory),
            "--",
            sys.executable,
            str(arguments.client),
            "--case",
            arguments.case,
            "--fd",
            str(child_channel.fileno()),
        ]
        passed = [child_channel.fileno()]
        if foreign_descriptor is not None:
            command.extend(["--foreign-fd", str(foreign_descriptor)])
            passed.append(foreign_descriptor)
        try:
            child = subprocess.run(
                command,
                pass_fds=tuple(passed),
                stdin=subprocess.DEVNULL,
                check=False,
                timeout=8,
            )
            child_result = child.returncode if 0 <= child.returncode <= 255 else 0
        except subprocess.TimeoutExpired:
            child_result = 0
        child_channel.close()

        broker_result = 7
        if broker is not None:
            try:
                broker_result = broker.wait(timeout=5)
            except subprocess.TimeoutExpired:
                broker.kill()
                broker.wait(timeout=2)
                broker_result = 0
        if arguments.case == "allowed-request" and broker_result != 0:
            return 7
        return child_result
    finally:
        parent_channel.close()
        child_channel.close()
        if broker is not None and broker.poll() is None:
            broker.kill()
            broker.wait(timeout=2)
        if foreign_descriptor is not None:
            os.close(foreign_descriptor)
        broker_stdout.close()
        broker_stderr.close()


def parser() -> argparse.ArgumentParser:
    """Build the closed one-case interface."""

    result = argparse.ArgumentParser(allow_abbrev=False)
    result.add_argument("--case", choices=CASES, required=True)
    result.add_argument("--repository-root", type=Path, required=True)
    result.add_argument("--wrapper", type=Path, required=True)
    result.add_argument("--client", type=Path, required=True)
    result.add_argument("--state-directory", type=Path, required=True)
    result.add_argument("--broker-stdout", type=Path, required=True)
    result.add_argument("--broker-stderr", type=Path, required=True)
    result.add_argument("--allowed-endpoint-ip", required=True)
    result.add_argument("--denied-endpoint-ip", required=True)
    result.add_argument("--endpoint-port", type=int, required=True)
    result.add_argument("--allowed-certificate", type=Path, required=True)
    return result


def main() -> int:
    """Run one case or return bypass-like zero on orchestration ambiguity."""

    try:
        return run(parser().parse_args())
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"broker case orchestration failed: {error}", file=sys.stderr)
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
