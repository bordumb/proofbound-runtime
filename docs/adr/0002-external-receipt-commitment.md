# ADR 0002: Require an external receipt commitment

- **Status:** accepted
- **Date:** 2026-09-07
- **Decision owners:** Proofbound Runtime maintainers
- **Applies to:** version 1 receipt transport and independent verification

## Context

The version 1 threat model includes a malicious receipt carrier. The frozen
attack catalog therefore requires the independent verifier to reject
substitution of plan, platform, runtime, executable, input, and output
identities.

Canonical JSON, closed roles, and internal relationships do not authenticate a
self-contained receipt. A carrier can replace an unconstrained digest, encode
the result canonically, and retain every locally checkable relationship. The
verifier then receives a different but internally valid statement. Hashes name
bytes only when a trusted party already knows the expected hash.

This limitation was exposed when the complete attack corpus was mapped to the
standalone verifier after its decoder, canonicalizer, and semantic validator
were implemented. Treating those substitutions as rejected would make the
tests assert behavior that the one-argument verifier cannot provide.

## Decision

Independent verification of a version 1 receipt requires an exact SHA-256
commitment supplied through a channel independent of the receipt carrier.

- `pbr run` emits the canonical receipt and its commitment separately to the
  invoking control channel.
- `pbr-verify` requires the expected commitment explicitly. It never discovers
  a commitment from an adjacent file or from the receipt itself.
- The verifier checks closed structure and canonical bytes, checks the expected
  commitment against the exact receipt bytes, then validates internal
  identities, relationships, and eligibility.
- A canonical substitution that remains internally valid fails with
  `receipt.commitment.mismatch`.
- A receipt without an independently obtained commitment can be inspected, but
  it cannot satisfy independent verification or reuse.
- Proofbound receipt composition may carry the expected commitment later, but
  the composed parent receipt then becomes the trust anchor and must itself be
  verified.

The commitment authenticates the byte statement relative to the trusted
channel. It does not prove that the producer observed the claimed effects, that
the host is correct, or that a digest-named artifact has the asserted behavior.

## Consequences

### Positive

- Every byte-level carrier mutation becomes detectable.
- Canonicalization remains useful for stable identity without being
  misrepresented as authentication.
- The verifier stays independent from producer semantics and does not need
  ambient artifact paths.
- The trust edge is explicit and can later compose with a Proofbound receipt.

### Negative

- The original `pbr-verify <receipt>` interface is insufficient and must gain a
  required expected-commitment argument.
- Callers must retain or transport a small trust anchor separately.
- Field-specific diagnostics are available only for locally decidable defects;
  otherwise a well-formed substitution reports the commitment mismatch.
- A carrier controlling both the receipt and the alleged expected commitment
  still wins. The channel supplying the commitment is a visible premise.

## Alternatives considered

### Rely on canonical JSON and embedded digests

Rejected. They detect malformed representations and internal inconsistency,
not replacement by another canonical, internally consistent statement.

### Embed the receipt digest in the receipt

Rejected. A carrier can recompute the digest after mutation. Self-reference
does not create a trust anchor.

### Embed a public key and signature in the receipt

Rejected for version 1. A carrier can replace an untrusted embedded key and
signature together. A trusted public key would still need an external channel,
while adding signing-key lifecycle and protection requirements.

### Re-read every recorded artifact during verification

Rejected. Receipt identities deliberately omit paths, output paths may no
longer exist, and re-reading artifacts would still not authenticate fields such
as observations or eligibility.

## Revisit conditions

Revisit this decision when:

- the runtime has an attested signing identity with a separately trusted public
  key;
- a Proofbound parent receipt supplies the commitment and all of its premises;
- receipt transport gains an authenticated channel with equivalent semantics;
  or
- the malicious-carrier threat is explicitly removed in a versioned threat
  model revision.
