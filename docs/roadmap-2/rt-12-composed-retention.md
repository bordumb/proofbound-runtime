# RT-12 integration record: composed retention

**Status:** closed until RT-11 is accepted and two consumers exist

**Primary owner:** Proofbound Runtime for the first receipt log

**Roadmap:** [Epic RT-12](../product-roadmap-2.md#10-epic-rt-12-content-addressed-receipt-log)

**Platform contract:** [Specification 0013](../specs/0013_platform_integration_contract.md)

## Product result

A third party can retain native receipts, their typed links, and signed log
checkpoints and later verify inclusion, consistency, native validity, and
consumer policy offline.

## Stored objects

The log stores or references separate content-addressed objects:

- Capsec report, when present;
- Auths decision and execution receipts;
- Runtime plan, receipt, commitment, and linkage record;
- Proofbound release and composed receipts;
- compatibility record;
- detached signing envelopes; and
- log checkpoints and proofs.

The log does not re-encode them as one semantic record. Inclusion establishes
only that the operator included exact bytes in the tree represented by a
checkpoint.

## Verification order

1. Verify checkpoint signature and witness policy.
2. Verify inclusion and consistency proofs.
3. Verify each native object with its owner verifier.
4. Verify the typed linkage graph.
5. Verify the selected compatibility tuple.
6. Apply consumer acceptance policy.

## Additional falsifiers

- Omit one native object while retaining its linkage reference.
- Serve two inconsistent checkpoints without a detectable witness conflict.
- Substitute the compatibility record after inclusion.
- Accept log time as trusted freshness without the required time policy.
- Treat inclusion as authorization, execution, or Proofbound status.

## Integration exit

RT-12 is platform-ready when two independent consumers can export the complete
object closure and reproduce every native and cross-project decision offline
from a pinned checkpoint.
