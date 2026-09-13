# RT-20 candidate: host and fleet identity

**Status:** candidate research only; implementation closed

**Primary owners:** Runtime owns host and guest execution profiles. Proofbound
owns generic evidence meaning. Auths owns workload and operator identity.

**Start gate:** RT-10 ships an identified guest profile, one adopter needs
remote execution, and a separate threat model defines the remote operator and
hardware adversaries.

## Product outcome

A remote consumer can apply policy to identified host, guest, Runtime, and
workload evidence without interpreting attestation as proof of program behavior
or complete containment.

## Questions to preserve

- Which identity names the physical host, virtual machine, guest image, guest
  kernel, Runtime bundle, service instance, operator, and workload?
- Which observations are measured locally, reported by an operator, signed by
  hardware, or inferred from a release identity?
- What freshness input exists, who supplies it, and how is replay rejected?
- Which roots, firmware, boot components, hypervisor, kernel configuration, and
  device state enter the attested closure?
- Can verification occur offline against pinned endorsement and revocation
  state?
- Which failure is unsupported, untrusted, stale, revoked, mismatched, or
  unverifiable?
- Does confidential execution reduce any current host-root assumption, or only
  move it to different hardware and firmware assumptions?

## Candidate profiles

Evaluate separately:

1. operator-signed host inventory;
2. measured boot with a hardware-backed quote;
3. confidential virtual machine attestation; and
4. no attestation, with one instance on a consumer-controlled host.

Do not merge these into one assurance level. Each profile has a separate claim,
trusted computing base, verifier input set, and acceptance policy.

## Required attacks

- replay an old valid quote for a new execution;
- bind a valid host quote to another guest or Runtime release;
- omit one measured boot component or revocation input;
- substitute the attestation verifier or endorsement set;
- confuse operator identity with workload identity;
- claim guest confidentiality from an integrity-only profile; and
- promote identified platform state into proof of Runtime behavior.

## Promotion gate

Promote RT-20 only when a named remote-host workload cannot use a
consumer-controlled RT-10 guest or single-tenant RT-13 instance and one
attestation profile produces a decision the consumer will actually enforce.

## Rejection gate

Reject a generic `attested = true` field, a profile without replay and
revocation inputs, or public language that says attestation proves the
execution happened as recorded.
