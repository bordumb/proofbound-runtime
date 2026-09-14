# Proofbound Runtime verifier

This package provides the independent Proofbound Runtime execution-receipt
verifier and the `pbr-verify` command.

The verifier has no dependency on another Proofbound Runtime workspace crate.
It strictly decodes supported receipt schemas, recomputes receipt decisions,
and compares the complete input bytes with an independently supplied SHA-256
commitment. It does not execute plans, install a Linux boundary, compose
receipts, or apply adopter acceptance policy.

## Command

```text
pbr-verify --expected-commitment sha256:<digest> <receipt>
```

The command writes a machine-readable verification report on success. It
writes one stable error code to standard error on failure.

## Supported receipt schemas

- `proofbound-runtime-receipt/1`
- `proofbound-runtime-execution-receipt/2`

Schema support is explicit. The verifier does not reinterpret an unknown
schema as a supported schema.

## Trust boundary

Package and receipt digests establish byte identity. They do not authenticate
a publisher or prove verifier behavior. Use the exact package identity and the
release assurance artifacts required by your acceptance policy.
