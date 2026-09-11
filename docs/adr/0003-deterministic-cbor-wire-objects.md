# ADR 0003: Deterministic CBOR for committed wire objects

- **Status:** accepted
- **Date:** 2026-09-10
- **Decision owners:** Proofbound Runtime maintainers
- **Applies to:** every version 2 or later plan, compiled policy, run result,
  execution receipt, composed receipt, acceptance decision, and linkage
  object; version 1 contracts are unchanged

## Context

Version 1 receipts, run results, composed receipts, and the doctor and
preflight reports use RFC 8785 canonical JSON. The
[receipt semantics](../receipt-semantics.md) already carry workarounds for
that choice: counters and byte sizes are decimal strings because JSON has no
safe integer range, digests are fixed lowercase hex because JSON has no byte
string, and set-valued arrays must be pre-sorted by a semantic key. The
launcher protocol and the Lean statement encodings already use deterministic
CBOR. Proofbound uses canonical JSON for envelopes and CBOR for theorem
statements. Auths uses closed deterministic CBOR with integer map keys for
every signed object.

Product roadmap 2 and Specification 0008 plan for Runtime receipts to be
committed into signed objects and later signed and logged. Those draft files
remain outside this ADR's change scope.
[Specification 0007](../specs/0007_memory_and_swap_profile.md) already
requires a version 2 plan and receipt because version 1 is closed. The
project is prelaunch with no external users. There is no compatibility
obligation, only re-derivation cost, and that cost grows with every roadmap
wave that freezes more JSON surface.

## Decision

1. **Committed bytes are deterministic CBOR.** Every wire object at version 2
   or later whose bytes are digested, committed, signed, or compared by an
   independent verifier is encoded as deterministic CBOR under the core
   deterministic encoding requirements of RFC 8949 section 4.2.1: shortest
   form integers and lengths, definite lengths only, map keys sorted by the
   bytewise lexicographic order of their encoding, and no duplicate keys.
   Floating-point values, indefinite-length items, and tags the schema does
   not declare are rejected.
2. **A closed CDDL schema defines each object.** The CDDL and its golden
   vectors define the wire; Rust struct layout does not. Unknown keys, missing
   required keys, and noncanonical bytes are rejected before semantic
   validation, as today. The decision owner must confirm whether version 2
   schemas use text or unsigned-integer map keys before any schema, golden
   vector, or codec is written. The existing version 1 launcher schema uses
   text keys and does not settle the version 2 choice.
3. **Version 1 is unchanged.** Version 1 producers, the frozen version 1
   verifier path, and historical receipts keep RFC 8785 canonical JSON and
   their existing meaning. No version 1 object is converted.
4. **JSON is a view, not a wire.** `inspect`, machine results read by humans
   or CI, and schema documentation render a JSON projection of a decoded CBOR
   object using the CDDL's names. The projection carries no commitment and is
   never an input to verification, composition, or acceptance.
5. **Producer and verifier keep separate codecs.** The independent verifier's
   decoder shares no code with the producer, as the contributor guide
   requires. An external CBOR crate, if one is used, joins the recorded
   trusted computing base for that role.
6. **The version 2 cut carries the change.** The encoding change lands in the
   same claim wave as the version 2 plan and receipt required by
   Specification 0007, so the binding-projection refinement and the
   independent verifier are redone once.
7. **Cross-project objects follow the same rule.** The planned Specification
   0008 linkage record is CBOR. The Proofbound release envelope encoding is
   decided upstream under roadmap epic UP-0, and the Runtime composer accepts
   exactly the encoding the pinned Proofbound release declares. Auths ADR 0002
   is the reference codec design; Runtime does not depend on Auths crates for
   this.

## Assurance meaning

Encoding determinism establishes that one decoded value has exactly one byte
form, which is what a digest or signature needs. It does not establish what
the value means, that the producer observed what it recorded, or that either
verifier is correct. Every existing assumption is retained. The canonical
wire projection admitted under `PBR-BINDING-005` must be re-refined for the
version 2 projection; the version 1 theorem remains bound to version 1 bytes
only.

## Open decision parameter

The deterministic-CBOR decision is accepted. The map-key representation is
not yet selected. Text keys and unsigned-integer keys can both satisfy the
RFC 8949 deterministic-encoding requirements, but they define different wire
contracts and golden vectors. No implementation may infer this choice from
Auths, the version 1 launcher protocol, Rust field names, or implementation
convenience. The decision owner must record the selected representation here
before version 2 CDDL, vectors, producer codecs, or verifier codecs land.

## Consequences

### Positive

- One canonicalization family across the launcher channel, receipts, release
  composition, acceptance, linkage, and future signed envelopes.
- Integers, byte strings, and digests have native forms. The decimal-string
  and hex workarounds leave the version 2 contract.
- Signed envelopes in roadmap 2 wrap CBOR payloads without a second
  canonicalization.
- A deterministic CBOR decoder is smaller and easier to fuzz than a JSON
  canonicalizer combined with schema constraints.

### Negative

- Version 2 requires a CDDL toolchain in CI, new golden vectors, a rewritten
  independent verifier decoder, and a redo of the binding-projection
  refinement.
- The verifier carries two decoder paths, JSON for version 1 and CBOR for
  version 2, until version 1 support is deliberately retired.
- Wire objects are not human-readable without the projection. Every command
  that prints a wire object must print the projection instead.
- The memory and network waves slip by the duration of the migration.

## Alternatives considered

### Keep canonical JSON everywhere

Rejected. RFC 8785 requires the workarounds listed above and leaves every
later signed object to solve canonicalization again.

### JSON wire objects with CBOR only for signed envelopes

Rejected. It keeps two canonicalizations and places the switch after every
roadmap 1 wave has frozen more JSON surface. This was the initial
recommendation during planning and was withdrawn on that ground.

### Select COSE or DSSE now

Deferred. The envelope format and signing identity belong to the roadmap 2
signing ADR. The payload encoding decided here is compatible with either.

## Revisit conditions

Revisit this decision when:

- a required consumer cannot process CBOR and a projection is insufficient;
- Proofbound selects a different committed encoding and the composer would
  have to carry both; or
- a deterministic-encoding defect is found in the CDDL or a codec that the
  golden vectors did not catch.
