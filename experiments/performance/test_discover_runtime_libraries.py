from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from experiments.performance.discover_runtime_libraries import (
    DiscoveryFailure,
    parse_interpreter,
    parse_libraries,
)


class RuntimeLibraryDiscoveryTests(unittest.TestCase):
    def test_interpreter_and_libraries_are_canonical_distinct_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            loader = (root / "ld-linux.so").resolve()
            libc = (root / "libc.so.6").resolve()
            libm = (root / "libm.so.6").resolve()
            for path in (loader, libc, libm):
                path.write_bytes(path.name.encode())
            alias = root / "libc-alias.so.6"
            alias.symlink_to(libc)
            readelf = f"      [Requesting program interpreter: {loader}]\n"
            ldd = (
                "linux-vdso.so.1 (0x0000)\n"
                f"libc.so.6 => {alias} (0x0001)\n"
                f"libm.so.6 => {libm} (0x0002)\n"
                f"{loader} (0x0003)\n"
                f"duplicate.so => {libc} (0x0004)\n"
            )

            interpreter = parse_interpreter(readelf)
            self.assertEqual(interpreter, loader)
            self.assertEqual(parse_libraries(ldd, interpreter), [libc, libm])

    def test_malformed_or_unresolved_inspection_fails_closed(self) -> None:
        with self.assertRaises(DiscoveryFailure):
            parse_interpreter("no interpreter here\n")
        with tempfile.TemporaryDirectory() as temporary:
            loader = Path(temporary) / "loader"
            loader.write_bytes(b"loader")
            with self.assertRaises(DiscoveryFailure):
                parse_libraries("libc.so.6 => not found\n", loader.resolve())
            with self.assertRaises(DiscoveryFailure):
                parse_libraries("linux-vdso.so.1 (0x0000)\n", loader.resolve())


if __name__ == "__main__":
    unittest.main()
