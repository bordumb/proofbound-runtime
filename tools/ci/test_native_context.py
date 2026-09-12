import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from tools.ci.native_context import build_context, write_context


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class NativeContextTests(unittest.TestCase):
    def test_context_closes_host_source_cgroup_and_artifact_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cgroup = root / "cgroup"
            cgroup.mkdir()
            (cgroup / "cgroup.controllers").write_text("pids memory\n", encoding="utf-8")
            (cgroup / "cgroup.subtree_control").write_text(
                "+memory +pids\n", encoding="utf-8"
            )
            fixture = root / "native-boundary-probe"
            fixture.write_bytes(b"fixture")
            fixture.chmod(0o755)
            binaries = root / "bin"
            binaries.mkdir()
            for name in ("pbr", "pbr-native-launcher", "pbr-verify"):
                path = binaries / name
                path.write_bytes(name.encode())
                path.chmod(0o755)

            context = build_context(
                REPOSITORY_ROOT, "x86_64", cgroup, fixture, binaries
            )

            self.assertEqual(context["schema"], "proofbound-runtime-native-context/1")
            self.assertEqual(context["architecture"], "x86_64")
            self.assertEqual(context["cgroup_v2"]["controllers"], ["memory", "pids"])
            self.assertEqual(
                context["cgroup_v2"]["subtree_control"], ["+memory", "+pids"]
            )
            self.assertRegex(context["source_revision"], r"^[0-9a-f]{40}$")
            self.assertEqual(
                [(item["role"], item["name"]) for item in context["artifacts"]],
                [
                    ("native-boundary-fixture", "native-boundary-probe"),
                    ("runtime", "pbr"),
                    ("launcher", "pbr-native-launcher"),
                    ("verifier", "pbr-verify"),
                ],
            )
            self.assertEqual(
                context["artifacts"][0]["sha256"],
                hashlib.sha256(b"fixture").hexdigest(),
            )

            output = root / "native-context.json"
            write_context(output, context)
            self.assertEqual(json.loads(output.read_bytes()), context)
            with self.assertRaises(FileExistsError):
                write_context(output, context)

    def test_context_rejects_an_unsupported_architecture(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported native architecture"):
            build_context(
                REPOSITORY_ROOT,
                "riscv64",
                Path("unused"),
                Path("unused"),
                Path("unused"),
            )


if __name__ == "__main__":
    unittest.main()
