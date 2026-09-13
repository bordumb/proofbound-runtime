#!/usr/bin/env python3
"""Falsifiers for the preconnected-channel result recorder."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import ssl
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from experiments.network_authority.record_common import RecordError, canonical_json
from experiments.network_authority.record_preconnected_control import (
    CASES,
    FIXTURE_OBSERVATIONS,
    PRELAUNCH_CASES,
    SOURCE_FILES,
    record,
)


class RecorderTests(unittest.TestCase):
    def test_direct_entrypoint_resolves_repository_package(self) -> None:
        entrypoint = Path(__file__).with_name("record_preconnected_control.py").resolve()
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

    def certificate(self, root: Path, name: str) -> Path:
        certificate = root / f"{name}-certificate.pem"
        key = root / f"{name}-key.pem"
        completed = subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                f"/CN={name}.test",
                "-keyout",
                str(key),
                "-out",
                str(certificate),
            ],
            check=False,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode())
        return certificate

    def fixture(self, root: Path) -> tuple[Path, Path]:
        source = root / "source"
        work = root / "work"
        source_dir = source / "experiments" / "network_authority"
        source_dir.mkdir(parents=True)
        for name in ("preconnected-control.toml", *SOURCE_FILES):
            (source_dir / name).write_text(f"{name}\n", encoding="utf-8")
        work.mkdir()
        wrapper = work / "preconnected-child-control"
        wrapper.write_bytes(b"wrapper\n")
        wrapper.chmod(0o755)
        allowed = self.certificate(work, "allowed")
        denied = self.certificate(work, "denied")
        self.assertEqual(allowed.name, "allowed-certificate.pem")
        self.assertEqual(denied.name, "denied-certificate.pem")
        allowed_der = ssl.PEM_cert_to_DER_cert(allowed.read_text(encoding="ascii"))
        certificate_digest = hashlib.sha256(allowed_der).hexdigest()
        for directory in (
            "state",
            "home",
            "stdout",
            "stderr",
            "fixture-stdout",
            "fixture-stderr",
        ):
            (work / directory).mkdir()
        for index, (case, _, expects_boundary, expects_relay) in enumerate(CASES):
            state = work / "state" / case
            state.mkdir()
            (state / "fixture.ready").write_text("ready\n", encoding="ascii")
            child_cookie = 1000 + index * 2
            peer = {"gid": 0, "pid": 2000 + index, "uid": 0}
            authenticated = case not in PRELAUNCH_CASES
            connector = None
            if authenticated:
                connector = {
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "local_ip": "127.0.0.1",
                    "local_port": 30000 + index,
                    "peer_certificate_sha256": certificate_digest,
                    "peer_ip": "127.0.0.1",
                    "peer_port": 443,
                    "service_name": "allowed.test",
                    "tls_version": "TLSv1.3",
                }
            relay = None
            if expects_relay:
                relay = {
                    "child_to_service_bytes": 71,
                    "service_to_child_bytes": 90,
                    "tls_shutdown_observed": True,
                }
            observation = {
                "case": case,
                "child_started": expects_boundary,
                "connector_authenticated": authenticated,
                "connector_observation": connector,
                "fixture_exit": 0 if case in FIXTURE_OBSERVATIONS else 7,
                "fixture_reaped": True,
                "local_channel": {
                    "child_cookie": child_cookie,
                    "child_peer": peer,
                    "parent_cookie": child_cookie + 1,
                    "parent_peer": peer,
                    "type": "unix-stream",
                },
                "orchestration_outcome": (
                    "expected-prelaunch-failure"
                    if case in PRELAUNCH_CASES
                    else "child-complete"
                ),
                "relay_observation": relay,
                "schema": "proofbound-runtime-network-experiment-preconnected-case/1",
            }
            (state / "case-observations.json").write_bytes(canonical_json(observation))
            if case in FIXTURE_OBSERVATIONS:
                (state / "fixture-observation.txt").write_bytes(
                    FIXTURE_OBSERVATIONS[case]
                )
            if expects_boundary:
                boundary = state / "boundary"
                boundary.mkdir()
                (boundary / "seccomp-program.bin").write_bytes(b"same program\n")
                (boundary / "boundary-observations.txt").write_text(
                    "architecture=x86_64\n"
                    f"channel_cookie={child_cookie}\n"
                    "instruction_count=51\n"
                    "no_new_privs=true\n"
                    "peer_gid=0\n"
                    f"peer_pid={peer['pid']}\n"
                    "peer_uid=0\n"
                    "retained_fd=4\n"
                    "socket_family=unix\n"
                    "socket_type=stream\n",
                    encoding="ascii",
                )
                (work / "home" / f"{case}.started").write_text(
                    "started\n", encoding="ascii"
                )
            for directory in ("stdout", "stderr", "fixture-stdout", "fixture-stderr"):
                (work / directory / f"{case}.log").write_text(
                    f"{directory} {case}\n", encoding="utf-8"
                )
        return source, work

    def arguments(
        self, root: Path, source: Path, work: Path, output: str
    ) -> argparse.Namespace:
        values: dict[str, object] = {
            "output": str(root / output),
            "source_root": str(source),
            "work_root": str(work),
            "source_commit": "4" * 40,
            "architecture": "x86_64",
            "kernel_release": "6.8.0-test",
            "compiler": "cc test",
            "openssl": "openssl test",
            "python": "python test",
            "cleanup_observed": "true",
        }
        for case, expects_zero, _, _ in CASES:
            values[case.replace("-", "_")] = "0" if expects_zero else "7"
        return argparse.Namespace(**values)

    def test_valid_result_has_exact_boundaries_and_exposures(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            output = record(self.arguments(root, source, work, "result"))
            result = json.loads((output / "RESULT.json").read_bytes())
            attacks = json.loads((output / "attack-results.json").read_bytes())
            boundary = json.loads((output / "boundary-manifest.json").read_bytes())
            self.assertTrue(result["complete"])
            self.assertEqual(
                result["conclusion"],
                "preconnected-channel-binds-one-authenticated-session-control",
            )
            self.assertEqual(
                attacks["expected_authority_exposures"],
                ["undeclared-path-exposure", "connect-shape-exposure"],
            )
            self.assertEqual(
                len(boundary["cases"]), sum(case[2] for case in CASES)
            )
            inputs = {item["name"] for item in result["inputs"]}
            actual = {
                path.relative_to(output).as_posix()
                for path in output.rglob("*")
                if path.is_file() and path.name != "RESULT.json"
            }
            self.assertEqual(inputs, actual)

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

    def test_case_or_cleanup_mismatch_is_not_promoted(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            arguments = self.arguments(root, source, work, "unexpected")
            arguments.direct_tcp_denied = "0"
            result = json.loads(record(arguments).joinpath("RESULT.json").read_bytes())
            self.assertFalse(result["complete"])
            self.assertEqual(result["conclusion"], "unexpected-control-result")

            arguments = self.arguments(root, source, work, "unclean")
            arguments.cleanup_observed = "false"
            result = json.loads(record(arguments).joinpath("RESULT.json").read_bytes())
            self.assertFalse(result["complete"])

    def test_identity_drift_fails_before_publication(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, work = self.fixture(root)
            case = CASES[0][0]
            observation = work / "state" / case / "case-observations.json"
            value = json.loads(observation.read_bytes())
            value["connector_observation"]["peer_ip"] = "127.0.0.2"
            observation.write_bytes(canonical_json(value))
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


if __name__ == "__main__":
    unittest.main()
