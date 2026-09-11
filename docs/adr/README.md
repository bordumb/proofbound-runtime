# Architecture decision records

Architecture decision records preserve accepted decisions that affect trust,
security boundaries, public contracts, or repository ownership.

## Status vocabulary

- `proposed` — under review and not binding;
- `accepted` — current project decision;
- `superseded` — replaced by a later ADR; or
- `rejected` — considered and not adopted.

Never rewrite an accepted decision to make a later architecture appear
inevitable. Add a new ADR and mark the earlier record as superseded.

## Index

| ADR | Decision | Status |
| --- | --- | --- |
| [0001](0001-linux-enforcement-boundary.md) | Use a native Linux enforcement boundary for version 1 | accepted |
| [0002](0002-external-receipt-commitment.md) | Require an external receipt commitment | accepted |
| [0003](0003-deterministic-cbor-wire-objects.md) | Encode committed version 2 wire objects as deterministic CBOR | accepted |
