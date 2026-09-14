# RT-10 integration record: guest identity

**Status:** planned

**Primary owner:** Proofbound Runtime

**Roadmap:** [Epic RT-10](../product-roadmap-2.md#8-epic-rt-10-linux-vm-host-profile-for-macos-and-windows)

**Platform contract:** [Specification 0013](../specs/0013_platform_integration_contract.md)

## Product result

A consumer can distinguish native Linux execution from execution inside an
identified Linux guest without treating the host operating system as an
enforcement mechanism.

## Identity separation

The host profile keeps these identities distinct:

- host orchestration tool;
- hypervisor and configuration;
- guest image and guest kernel;
- Runtime release inside the guest;
- Runtime execution and receipt;
- invoking Auths workload, when present; and
- Proofbound release evidence for each maintained artifact.

A guest-image digest does not identify the running guest state by itself. An
Auths workload identity does not identify the guest. Proofbound artifact
linkage does not attest a malicious host.

## Required behavior

- The acceptance profile can require or reject one guest identity.
- The platform integration tuple names the guest profile it supports.
- Host-to-guest receipt and commitment transport is an explicit trusted role.
- Auths and Capsec integrations behave the same inside the guest and remain
  outside the Runtime launcher.

## Additional falsifiers

- Replace the guest image while retaining the Runtime release.
- Replace the Runtime bundle inside an accepted guest image.
- Relabel a guest receipt as native Linux.
- Substitute the host orchestration tool or transport identity.

## Integration exit

RT-10 is platform-ready when the maintained laptop workflow exposes each
identity separately and the consumer can reject a substituted guest, Runtime
release, host tool, or host profile.
