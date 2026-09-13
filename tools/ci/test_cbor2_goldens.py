import unittest
from pathlib import Path

import cbor2


ROOT = Path(__file__).resolve().parents[2] / "schemas/vectors/v2"


class IndependentCborGoldenTests(unittest.TestCase):
    def test_cbor2_canonical_encoder_reproduces_every_golden(self) -> None:
        vectors = sorted(ROOT.glob("*.cbor.hex"))
        self.assertGreater(len(vectors), 0)
        for vector in vectors:
            with self.subTest(vector=vector.name):
                golden = bytes.fromhex(vector.read_text(encoding="ascii").strip())
                decoded = cbor2.loads(golden)
                self.assertEqual(cbor2.dumps(decoded, canonical=True), golden)


if __name__ == "__main__":
    unittest.main()
