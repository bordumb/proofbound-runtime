# Roadmap 2 execution records

These records map the cross-project platform contract into each affected
Proofbound Runtime epic. They do not replace the ordered roadmap, a normative
specification, an architecture decision, a threat model, or a Proofbound claim.

The [Roadmap 2 overview](../product-roadmap-2.md) owns priority and merge order.
The [product roadmap execution order](../product-roadmap-execution-order.md)
owns dependencies across Roadmap 1 release closure, Roadmap 2, and candidate
promotion when the overview does not contain the current delivery checkpoint.
[Specification 0013](../specs/0013_platform_integration_contract.md) owns the
draft platform vocabulary, identity roles, composition rules, and compatibility
model. Each record below owns only the integration obligations for its epic.

| Epic | Integration record | Primary platform concern |
| --- | --- | --- |
| RT-7 | [Compatibility and distribution](rt-07-compatibility-and-distribution.md) | Independent versions, packages, and tested combinations |
| RT-8 | [Capability-informed drafting](rt-08-capability-informed-drafting.md) | Capsec provenance without automatic authority |
| RT-9 | [Authorized service execution](rt-09-authorized-service-execution.md) | Auths action identity versus Runtime service identity |
| RT-10 | [Guest identity](rt-10-guest-identity.md) | Host, guest, release, and workload identity separation |
| RT-11 | [Signing and platform identity](rt-11-signing-and-platform-identity.md) | Principal, workload, product, key, and operator identities |
| RT-12 | [Composed retention](rt-12-composed-retention.md) | Native receipts, typed links, checkpoints, and offline verification |
| RT-13 | [Platform execution service](rt-13-platform-execution-service.md) | API orchestration without sharing an execution boundary |

No record can close its epic by documentation alone. Its exit condition remains
the one in the Roadmap 2 overview.
