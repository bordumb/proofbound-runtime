#!/usr/bin/env python3
"""Falsifiers for the endpoint-control result recorder."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.record_common import RecordError
from experiments.network_authority.record_endpoint_control import record


CASES = (
    "allowed-endpoint",
    "same-port-endpoint-substitution",
    "other-port-denied",
    "wrong-certificate-denied",
)


class RecorderTests(unittest.TestCase):
    def test_direct_entrypoint_resolves_repository_package(self) -> None:
        entrypoint = Path(__file__).with_name("record_endpoint_control.py").resolve()
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
        (source_dir / "endpoint-control.toml").write_text("plan\n", encoding="utf-8")
        (source_dir / "cgroup_endpoint_control.c").write_text("source\n", encoding="utf-8")
        loader = work / "cgroup-endpoint-control"
        loader.write_bytes(b"loader\n")
        loader.chmod(0o755)
        (work / "connect4-program.bin").write_bytes(b"connect4\n")
        (work / "connect6-program.bin").write_bytes(b"connect6\n")
        (work / "connect4-verifier.log").write_text("accepted 4\n", encoding="utf-8")
        (work / "connect6-verifier.log").write_text("accepted 6\n", encoding="utf-8")
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
            source_commit="2" * 40,
            architecture="x86_64",
            kernel_release="6.8.0-test",
            btf_sha256="a" * 64,
            btf_size="8192",
            compiler="cc test",
            curl="curl test",
            openssl="openssl test",
            python="python test",
            cgroup_id="101",
            connect4_program_id="201",
            connect6_program_id="202",
            cleanup_observed="true",
            allowed_endpoint="0",
            same_port_endpoint_substitution="7",
            other_port_denied="7",
            wrong_certificate_denied="60",
        )

    def test_valid_result_has_exact_inventory_and_boundary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            output = record(self.arguments(root, source, work, "result"))
            files = sorted(
                path.relative_to(output).as_posix()
                for path in output.rglob("*")
                if path.is_file()
            )
            self.assertEqual(len(files), 16)
            self.assertEqual(
                files,
                [
                    "RESULT.json",
                    "artifact-manifest.json",
                    "attack-results.json",
                    "bpf-manifest.json",
                    "fixture-manifest.json",
                    "kernel-manifest.json",
                    "plan.toml",
                    "stderr/allowed-endpoint.log",
                    "stderr/other-port-denied.log",
                    "stderr/same-port-endpoint-substitution.log",
                    "stderr/wrong-certificate-denied.log",
                    "stdout/allowed-endpoint.log",
                    "stdout/other-port-denied.log",
                    "stdout/same-port-endpoint-substitution.log",
                    "stdout/wrong-certificate-denied.log",
                    "tool-manifest.json",
                ],
            )
            result = json.loads((output / "RESULT.json").read_bytes())
            boundary = json.loads((output / "bpf-manifest.json").read_bytes())
            self.assertTrue(result["complete"])
            self.assertEqual(
                result["conclusion"], "endpoint-control-selects-routing-tuple-only"
            )
            self.assertEqual(boundary["allowed_endpoint"]["ipv4"], "127.0.0.1")
            self.assertEqual(
                [program["program_id"] for program in boundary["programs"]],
                [201, 202],
            )

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

    def test_unexpected_exit_or_cleanup_is_retained_not_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            arguments = self.arguments(root, source, work, "unexpected")
            arguments.same_port_endpoint_substitution = "0"
            unexpected = record(arguments)
            result = json.loads((unexpected / "RESULT.json").read_bytes())
            self.assertFalse(result["complete"])
            self.assertEqual(result["conclusion"], "unexpected-control-result")

            arguments = self.arguments(root, source, work, "unclean")
            arguments.cleanup_observed = "false"
            unclean = record(arguments)
            result = json.loads((unclean / "RESULT.json").read_bytes())
            self.assertFalse(result["complete"])

    def test_invalid_identity_and_symlink_fail_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            arguments = self.arguments(root, source, work, "bad-digest")
            arguments.btf_sha256 = "not-a-digest"
            with self.assertRaises(RecordError):
                record(arguments)
            self.assertFalse((root / "bad-digest").exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            program = work / "connect4-program.bin"
            program.unlink()
            os.symlink(work / "connect6-program.bin", program)
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
                "bpf-manifest.json",
                "fixture-manifest.json",
                "kernel-manifest.json",
                "tool-manifest.json",
            ):
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())


if __name__ == "__main__":
    unittest.main()
