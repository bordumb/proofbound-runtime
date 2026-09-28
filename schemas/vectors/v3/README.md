# Proposed version 3 wire vectors

Each `.cbor.hex` file is one deterministic CBOR item. Its JSON projection is
for inspection and is never execution or verification input. The maintained
Python encoder reproduces the plan vector. The independent strict decoder
checks every retained vector in `tools/ci/test_egress_v3_vector.py`.

The compiled-policy vector records the proposed separation of direct deny,
child namespace, and proxy authority. Its `11` and `22` filter identities are
fixed synthetic fixture bytes, not hashes of installed seccomp programs.
The other vectors use deny mode to pin the proposed version transitions. They
do not establish an egress producer, namespace, proxy, receipt verifier, or
admitted acceptance path. Production execution continues to reject version 3
plans.
