# Receipt semantics

An execution receipt is a canonical account of one observed execution attempt.
It binds registered identities and observations. It does not prove that Linux,
the host, or the executed program behaved correctly.

## Version 1 wire contract

The wire schema is
[`execution-receipt-v1.schema.json`](../schemas/execution-receipt-v1.schema.json).
Unknown fields and unknown enum values are errors. The verifier rejects a
receipt before semantic derivation when it does not satisfy the closed schema.

Version 1 uses the JSON Canonicalization Scheme from RFC 8785. Producers and
verifiers apply these rules:

- Encode one JSON value as UTF-8 without a byte-order mark or trailing newline.
- Sort object member names as RFC 8785 requires and emit no insignificant
  whitespace.
- Reject duplicate object member names before canonicalization.
- Reject invalid Unicode and do not apply Unicode normalization.
- Reject bytes that differ from the canonical serialization of the decoded
  value.
- Encode counters and byte sizes as canonical unsigned decimal strings. This
  avoids loss through the JSON interoperable-integer range.
- Encode SHA-256 digests as 64 lowercase hexadecimal characters without a
  prefix.
- Preserve array order. Arrays that represent sets must already be sorted by
  their specified semantic key and contain no duplicates.

## Carrier integrity

Canonical bytes are stable; they are not self-authenticating. Independent
verification requires an algorithm-qualified SHA-256 commitment obtained
through a channel the receipt carrier cannot alter. The verifier never trusts
a commitment stored beside or inside the receipt.

The verifier first rejects malformed or non-canonical bytes, then compares the
exact bytes with the expected commitment, then validates semantic
relationships and independently derives eligibility. A canonical,
internally-consistent substitution fails with `receipt.commitment.mismatch`.
Without the external commitment, a receipt can be inspected but cannot satisfy
independent verification or reuse.

## Independent decisions

The producer records observations and its derived eligibility. The independent
verifier checks structure, canonical bytes, identities, role completeness, and
relationships after checking the external commitment, then independently
derives eligibility. A mismatch is a verification failure. The producer cannot
make a receipt reusable by writing `"status":"reusable"`.

A structurally valid receipt is reusable only when the complete boundary was
installed, the child exited with code zero, both streams are complete, and all
required receipt relationships validate. Every other represented execution
state is non-reusable with every applicable reason in normative order.

## Identity meaning

An artifact identity records its typed role, SHA-256 digest, byte size, and file
mode. Equality establishes that the recorded bytes and metadata have the same
identity. It does not establish behavioral correctness. Paths are diagnostic
context and are deliberately absent from artifact identity.

The receipt binds the source and normalized plans, compiled policy, platform,
runtime and launcher, executable closure, working directory, inputs, output
root, streams, output artifacts, producer, assumptions, and trusted computing
base. Removing or substituting any required role makes verification fail.

## Secrets

Version 1 records allowed environment names but no environment values. Secret
support is outside the first executable milestone. A secret value must never
appear in a plan, receipt, diagnostic, fixture, or test.
