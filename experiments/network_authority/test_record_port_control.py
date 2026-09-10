#!/usr/bin/env python3
"""Falsifiers for the network experiment result recorder."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.record_port_control import RecordError, record


CASES = (
    "allowed-service",
    "same-port-service-substitution",
    "other-port-denied",
    "wrong-certificate-denied",
)


class RecorderTests(unittest.TestCase):
    def test_direct_entrypoint_resolves_repository_package(self) -> None:
        entrypoint = Path(__file__).with_name("record_port_control.py").resolve()
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
        work.mkdir()
        (work / "stdout").mkdir()
        (work / "stderr").mkdir()
        (source_dir / "port-control.toml").write_text("plan\n", encoding="utf-8")
        (source_dir / "landlock_port_control.c").write_text("source\n", encoding="utf-8")
        wrapper = work / "landlock-port-control"
        wrapper.write_bytes(b"wrapper\n")
        wrapper.chmod(0o755)
        (work / "allowed-certificate.pem").write_text("allowed\n", encoding="utf-8")
        (work / "denied-certificate.pem").write_text("denied\n", encoding="utf-8")
        for case in CASES:
            (work / "stdout" / f"{case}.log").write_text(f"{case} out\n", encoding="utf-8")
            (work / "stderr" / f"{case}.log").write_text(f"{case} err\n", encoding="utf-8")
        return source, work

    def arguments(self, root: Path, source: Path, work: Path, output: str) -> argparse.Namespace:
        return argparse.Namespace(
            output=str(root / output),
            source_root=str(source),
            work_root=str(work),
            source_commit="1" * 40,
            architecture="x86_64",
            kernel_release="6.8.0-test",
            landlock_abi="6",
            compiler="cc test",
            curl="curl test",
            openssl="openssl test",
            python="python test",
            allowed_service="0",
            same_port_service_substitution="0",
            other_port_denied="7",
            wrong_certificate_denied="60",
        )

    def test_valid_result_has_exact_inventory_and_conclusion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            output = record(self.arguments(root, source, work, "result"))
            self.assertEqual(
                sorted(path.relative_to(output).as_posix() for path in output.rglob("*") if path.is_file()),
                [
                    "RESULT.json",
                    "artifact-manifest.json",
                    "attack-results.json",
                    "fixture-manifest.json",
                    "kernel-manifest.json",
                    "plan.toml",
                    "stderr/allowed-service.log",
                    "stderr/other-port-denied.log",
                    "stderr/same-port-service-substitution.log",
                    "stderr/wrong-certificate-denied.log",
                    "stdout/allowed-service.log",
                    "stdout/other-port-denied.log",
                    "stdout/same-port-service-substitution.log",
                    "stdout/wrong-certificate-denied.log",
                    "tool-manifest.json",
                ],
            )
            result = json.loads((output / "RESULT.json").read_bytes())
            self.assertEqual(result["conclusion"], "port-only-landlock-cannot-select-service")

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

    def test_unexpected_exit_is_retained_not_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            arguments = self.arguments(root, source, work, "result")
            arguments.same_port_service_substitution = "7"
            output = record(arguments)
            result = json.loads((output / "RESULT.json").read_bytes())
            attacks = json.loads((output / "attack-results.json").read_bytes())
            self.assertEqual(result["conclusion"], "unexpected-control-result")
            self.assertFalse(attacks["cases"][1]["matched_expected"])

    def test_symlink_and_oversized_inputs_fail_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            certificate = work / "allowed-certificate.pem"
            certificate.unlink()
            os.symlink(work / "denied-certificate.pem", certificate)
            with self.assertRaises(RecordError):
                record(self.arguments(root, source, work, "result"))
            self.assertFalse((root / "result").exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            (work / "stdout" / "allowed-service.log").write_bytes(b"x" * (1024 * 1024 + 1))
            with self.assertRaises(RecordError):
                record(self.arguments(root, source, work, "result"))
            self.assertFalse((root / "result").exists())

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
                "fixture-manifest.json",
                "kernel-manifest.json",
                "tool-manifest.json",
            ):
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
