#!/usr/bin/env python3
"""Falsifiers for the explicit-broker result recorder."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.record_broker_control import CASES, record
from experiments.network_authority.record_common import RecordError


class RecorderTests(unittest.TestCase):
    def test_direct_entrypoint_resolves_repository_package(self) -> None:
        entrypoint = Path(__file__).with_name("record_broker_control.py").resolve()
        with tempfile.TemporaryDirectory() as temporary:
            completed = subprocess.run(
                [sys.executable, str(entrypoint), "--help"],
                cwd=temporary,
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
        self.assertEqual(completed.returncode, 0, completed.stderr)

    def fixture(self, root: Path) -> tuple[Path, Path]:
        source = root / "source"
        work = root / "work"
        source_dir = source / "experiments" / "network_authority"
        source_dir.mkdir(parents=True)
        for name in (
            "broker-control.toml",
            "explicit_broker.py",
            "broker_case_client.py",
            "run_broker_case.py",
            "broker_child_control.c",
        ):
            (source_dir / name).write_text(f"{name}\n", encoding="utf-8")
        work.mkdir()
        wrapper = work / "broker-child-control"
        wrapper.write_bytes(b"wrapper\n")
        wrapper.chmod(0o755)
        (work / "allowed-certificate.pem").write_text("allowed\n", encoding="utf-8")
        (work / "denied-certificate.pem").write_text("denied\n", encoding="utf-8")
        for directory in (
            "state",
            "stdout",
            "stderr",
            "broker-stdout",
            "broker-stderr",
            "fixture-stdout",
            "fixture-stderr",
        ):
            (work / directory).mkdir()
        for case, _ in CASES:
            state = work / "state" / case
            state.mkdir()
            (state / "seccomp-program.bin").write_bytes(b"same program\n")
            (state / "boundary-observations.txt").write_text(
                "architecture=x86_64\n"
                "instruction_count=42\n"
                "no_new_privs=true\n"
                "retained_fd=4\n"
                "socket_family=unix\n"
                "socket_type=stream\n",
                encoding="utf-8",
            )
            for directory in ("stdout", "stderr", "broker-stdout", "broker-stderr"):
                (work / directory / f"{case}.log").write_text(
                    f"{directory} {case}\n", encoding="utf-8"
                )
        for service in ("allowed", "denied"):
            (work / "fixture-stdout" / f"{service}.log").write_text(
                f"{service} out\n", encoding="utf-8"
            )
            (work / "fixture-stderr" / f"{service}.log").write_text(
                f"{service} err\n", encoding="utf-8"
            )
        return source, work

    def arguments(self, root: Path, source: Path, work: Path, output: str) -> argparse.Namespace:
        values: dict[str, object] = {
            "output": str(root / output),
            "source_root": str(source),
            "work_root": str(work),
            "source_commit": "3" * 40,
            "architecture": "x86_64",
            "kernel_release": "6.8.0-test",
            "compiler": "cc test",
            "openssl": "openssl test",
            "python": "python test",
            "cleanup_observed": "true",
        }
        for case, expects_zero in CASES:
            values[case.replace("-", "_")] = "0" if expects_zero else "7"
        return argparse.Namespace(**values)

    def test_valid_result_has_exact_inventory_and_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            output = record(self.arguments(root, source, work, "result"))
            files = {
                path.relative_to(output).as_posix()
                for path in output.rglob("*")
                if path.is_file()
            }
            expected = {
                "RESULT.json",
                "artifact-manifest.json",
                "attack-results.json",
                "boundary-manifest.json",
                "broker-manifest.json",
                "fixture-manifest.json",
                "kernel-manifest.json",
                "plan.toml",
                "tool-manifest.json",
            }
            for case, _ in CASES:
                expected.update(
                    {
                        f"stdout/{case}.log",
                        f"stderr/{case}.log",
                        f"stdout/broker/{case}.log",
                        f"stderr/broker/{case}.log",
                    }
                )
            for service in ("allowed", "denied"):
                expected.update(
                    {
                        f"stdout/fixture/{service}.log",
                        f"stderr/fixture/{service}.log",
                    }
                )
            self.assertEqual(files, expected)
            result = json.loads((output / "RESULT.json").read_bytes())
            boundary = json.loads((output / "boundary-manifest.json").read_bytes())
            self.assertTrue(result["complete"])
            self.assertEqual(
                result["conclusion"], "explicit-broker-binds-fixed-service-control"
            )
            self.assertTrue(boundary["cleanup_observed"])
            self.assertEqual(len(boundary["cases"]), len(CASES))

    def test_foreign_output_is_preserved(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            output = root / "result"
            output.mkdir()
            foreign = output / "foreign"
            foreign.write_text("keep\n", encoding="utf-8")
            with self.assertRaises(RecordError):
                record(self.arguments(root, source, work, "result"))
            self.assertEqual(foreign.read_text(encoding="utf-8"), "keep\n")

    def test_unexpected_case_or_cleanup_is_not_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            arguments = self.arguments(root, source, work, "unexpected")
            arguments.direct_tcp_denied = "0"
            result_path = record(arguments)
            result = json.loads((result_path / "RESULT.json").read_bytes())
            self.assertFalse(result["complete"])
            self.assertEqual(result["conclusion"], "unexpected-control-result")

            arguments = self.arguments(root, source, work, "unclean")
            arguments.cleanup_observed = "false"
            result_path = record(arguments)
            result = json.loads((result_path / "RESULT.json").read_bytes())
            self.assertFalse(result["complete"])

    def test_boundary_drift_and_symlink_fail_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            drift = work / "state" / CASES[0][0] / "seccomp-program.bin"
            drift.write_bytes(b"different program\n")
            with self.assertRaises(RecordError):
                record(self.arguments(root, source, work, "drift"))
            self.assertFalse((root / "drift").exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            log = work / "stdout" / f"{CASES[0][0]}.log"
            log.unlink()
            os.symlink(work / "stderr" / f"{CASES[0][0]}.log", log)
            with self.assertRaises(RecordError):
                record(self.arguments(root, source, work, "symlink"))
            self.assertFalse((root / "symlink").exists())

    def test_equal_inputs_produce_equal_manifest_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            first = record(self.arguments(root, source, work, "first"))
            second = record(self.arguments(root, source, work, "second"))
            for name in (
                "RESULT.json",
                "artifact-manifest.json",
                "attack-results.json",
                "boundary-manifest.json",
                "broker-manifest.json",
                "fixture-manifest.json",
                "kernel-manifest.json",
                "tool-manifest.json",
            ):
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
