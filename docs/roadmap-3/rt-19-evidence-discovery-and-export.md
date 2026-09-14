# RT-19 candidate: evidence discovery and export

**Status:** candidate; export-closure planning permitted, service implementation blocked

**Primary owner:** the Runtime log layer owns indexing of Runtime integration
objects. Each native protocol owns verification and semantic rendering.

**Start gate:** RT-12 has two self-hosted consumers with a concrete discovery
or audit-export need.

## Product outcome

An auditor can find executions by non-secret indexed facts and export the exact
object closure required for independent offline verification.

## Trust separation

The content-addressed log, signed checkpoints, inclusion proofs, and native
receipts remain the verification inputs. A query index is derived, rebuildable,
and untrusted. A wrong query result can omit or mislabel an item; it cannot make
an exported closure verify.

## Candidate capabilities

- Rebuild an index from one pinned checkpoint and object closure.
- Search typed non-secret fields such as project, release, plan, execution,
  service, workload, policy, outcome, and receipt eligibility identities.
- Export native receipts, linkage records, integration records, envelopes,
  proofs, checkpoints, verifier identities, and required schemas.
- Produce a deterministic export manifest with no-replace semantics.
- Verify the export without an account, network connection, index, or log
  operator.

No index stores environment values, provider credentials, child output bytes,
or unregistered metadata by default.

## Required attacks

- omit an object from an export while retaining a dangling reference;
- return a stale or fabricated query row;
- substitute a checkpoint or integration record;
- redact an assumption or non-reuse reason;
- merge two tenants' index results;
- infer a trusted timestamp from index insertion time; and
- make offline verification depend on the query service.

## Promotion gate

Promote RT-19 only when two consumers need the same searchable fields or export
format and can demonstrate that raw content-addressed retrieval is insufficient.

## Rejection gate

Reject a database as the source of receipt truth, an export that cannot be
verified offline, or an indexing model that requires secret or unrestricted
child-output retention.
