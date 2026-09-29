"""Inject native proxy process faults after exact-release startup."""

import argparse
import os
from pathlib import Path
import signal
import subprocess
import time


def descendants(parent: int) -> list[int]:
    pending = [parent]
    result = []
    while pending:
        pid = pending.pop()
        try:
            children = Path(f"/proc/{pid}/task/{pid}/children").read_text().split()
        except (FileNotFoundError, ProcessLookupError):
            continue
        for child in children:
            member = int(child)
            result.append(member)
            pending.append(member)
    return result


def matching_child(parent: int, expected: os.stat_result) -> int | None:
    for pid in descendants(parent):
        try:
            actual = Path(f"/proc/{pid}/exe").stat()
        except (FileNotFoundError, ProcessLookupError, PermissionError):
            continue
        if (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino):
            return pid
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--proxy", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--plan", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--cgroup-root", type=Path, required=True)
    parser.add_argument("--fault", choices=("crash", "stop"), required=True)
    args = parser.parse_args()
    expected = args.proxy.stat()
    fixture = args.fixture.stat()
    process = subprocess.Popen(
        [str(args.binary), "run", "--plan", str(args.plan), "--receipt",
         str(args.receipt), "--cgroup-root", str(args.cgroup_root)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    injected_pid = None
    try:
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            pid = matching_child(process.pid, expected)
            child = matching_child(process.pid, fixture)
            if pid is not None and child is not None:
                break
            if process.poll() is not None:
                raise AssertionError("runtime exited before the child and proxy were serving")
            time.sleep(0.005)
        else:
            raise AssertionError("exact proxy and launched child were never observed together")
        injected_pid = pid
        os.kill(pid, signal.SIGKILL if args.fault == "crash" else signal.SIGSTOP)
        stdout, stderr = process.communicate(timeout=20)
        expected_code = (
            "network.egress.proxy.report-invalid" if args.fault == "crash"
            else "network.egress.proxy.drain-failed"
        )
        assert process.returncode != 0, (stdout, stderr)
        assert expected_code.encode() in stderr, (stdout, stderr)
        assert not args.receipt.exists(), args.receipt
    finally:
        if injected_pid is not None:
            try:
                actual = Path(f"/proc/{injected_pid}/exe").stat()
                if (actual.st_dev, actual.st_ino) == (expected.st_dev, expected.st_ino):
                    os.kill(injected_pid, signal.SIGKILL)
            except (FileNotFoundError, ProcessLookupError):
                pass
        if process.poll() is None:
            process.kill()
            process.communicate()


if __name__ == "__main__":
    main()
