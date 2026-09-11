# Version 2 wire golden vectors

Each `*.cbor.hex` file contains one complete deterministic-CBOR item as
lowercase hexadecimal. The same basename's `*.projection.json` file is the
human-readable projection of that decoded item. In these vector projections,
CBOR byte strings are rendered as lowercase hexadecimal prefixed by `hex:`.
The projection is descriptive test output; it is never a verification input.

The bytes were initially generated with `cbor2` 5.9.0 in canonical mode and
are accepted only after the repository's separate strict decoder confirms
shortest forms, definite lengths, text-only map keys, bytewise key ordering,
no duplicate keys, one complete item, and equality with the checked-in
projection.
