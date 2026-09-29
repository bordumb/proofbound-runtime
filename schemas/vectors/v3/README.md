# Proposed version 3 wire vectors

Each `.cbor.hex` file is one deterministic CBOR item. Its JSON projection is
for inspection and is never execution or verification input. The maintained
Python encoder reproduces the plan vector. The independent strict decoder
checks every retained vector in `tools/ci/test_egress_v3_vector.py`.

The egress-observation vector records one undeclared CONNECT rejection with
only the exact target digest and length. Its complete per-reason counters and
closed proxy lifecycle exercise the standalone observation grammar. The
declared-egress execution-receipt vectors bind that observation as a
non-reusable receipt and bind the same authority with zero rejections as a
reusable receipt. Both are synthetic fixtures.

The compiled-policy vector records the proposed separation of direct deny,
child namespace, and proxy authority. Its `11` and `22` filter identities are
fixed synthetic fixture bytes, not hashes of installed seccomp programs.
The other vectors use deny mode to pin the proposed version transitions.
These fixtures do not establish a live egress supervisor or admitted
acceptance path. Production execution continues to reject version 3 plans.
