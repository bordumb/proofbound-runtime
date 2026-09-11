import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = REPOSITORY_ROOT / "tools" / "release" / "validate_release_state.py"


def changelog(*, unreleased: str = "", current: str = "0.2.0") -> str:
    return f"""# Changelog

## [Unreleased]
{unreleased}
## [{current}] - 2026-09-10

### Added

- New release behavior.

## [0.1.0] - 2026-09-09

### Added

- Previous release.

[Unreleased]: https://github.com/bordumb/proofbound-runtime/compare/v{current}...HEAD
[{current}]: https://github.com/bordumb/proofbound-runtime/compare/v0.1.0...v{current}
[0.1.0]: https://github.com/bordumb/proofbound-runtime/releases/tag/v0.1.0
"""


class ReleaseStateTests(unittest.TestCase):
    def validate(
        self,
        root: Path,
        *,
        version: str = "0.2.0",
        body: str | None = None,
        tags: str = "0.1.0",
    ) -> subprocess.CompletedProcess[str]:
        (root / "VERSION").write_text(version + "\n", encoding="utf-8")
        (root / "CHANGELOG.md").write_text(
            body if body is not None else changelog(current=version), encoding="utf-8"
        )
        return subprocess.run(
            [
                sys.executable,
                str(VALIDATOR),
                "--root",
                str(root),
                "--existing-tags",
                tags,
            ],
            cwd=REPOSITORY_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_new_closed_release_state_passes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.validate(Path(directory))
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_open_or_already_tagged_release_state_fails(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases = {
                "unreleased-content": {
                    "body": changelog(unreleased="\n### Added\n\n- Not promoted.\n")
                },
                "existing-tag": {"tags": "0.1.0,0.2.0"},
                "missing-release-entry": {"body": changelog(current="0.3.0")},
                "stale-unreleased-link": {
                    "body": changelog().replace("compare/v0.2.0...HEAD", "compare/v0.1.0...HEAD")
                },
                "non-increasing-version": {"version": "0.1.0"},
            }
            for name, overrides in cases.items():
                with self.subTest(name=name):
                    result = self.validate(root, **overrides)
                    self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
