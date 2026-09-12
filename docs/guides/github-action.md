# Receipt acceptance in GitHub Actions

The first-party composite Action runs one reviewed Version 2 plan, reads the
commitment and execution ID from the control-channel run result, invokes the
independent execution verifier, composes the execution with an exact
Proofbound release, and invokes `pbr-accept` to re-run both independent
verifiers before applying adopter policy.

Use an exact reviewed Runtime commit in `uses:`. The Action deliberately has
no mutable release name, download URL, or default digest. The caller supplies
one Runtime archive, its trusted SHA-256, the separately reproduced
`pbr-accept` binary and SHA-256, deterministic-CBOR policy bytes and their
domain-separated identity, and the exact Proofbound inputs. Those values are
the adopter's trust inputs.

```yaml
jobs:
  accepted-execution:
    runs-on: ubuntu-24.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1

      # Repository-specific setup downloads exact release assets, prepares the
      # reviewed plan and Proofbound release, and delegates an empty cgroup.
      - id: proofbound
        uses: bordumb/proofbound-runtime/.github/actions/proofbound-runtime@0123456789abcdef0123456789abcdef01234567
        with:
          runtime-archive: inputs/proofbound-runtime-v0.2.0-x86_64-unknown-linux-gnu.tar.gz
          runtime-archive-sha256: 64-lowercase-hex-digest
          acceptor: inputs/pbr-accept-v0.2.0-x86_64-unknown-linux-gnu
          acceptor-sha256: 64-lowercase-hex-digest
          policy: policy/acceptance-policy.cbor
          policy-identity: sha256:64-lowercase-domain-digest
          plan: policy/execution-plan.cbor
          cgroup-root: /run/user/1001/proofbound-delegated
          proofbound-release: inputs/proofbound-release
          proofbound-release-sha256: 64-lowercase-framed-directory-digest
          proofbound-verifier: inputs/proofbound-release/bin/proofbound-verify
          proofbound-verifier-sha256: 64-lowercase-hex-digest
          proofbound-observation-inputs: inputs/proofbound-observation-inputs.json
          upload-exact-artifacts: "false"
```

Replace every placeholder before use. An exact commit pins the Action source;
the archive, acceptor, policy, Proofbound verifier, and Proofbound
release-directory digests pin its executable and release inputs. A digest
read beside an untrusted download proves byte agreement, not publisher identity.

The Action outputs `decision-id`, `status`, and a compact JSON `reasons` array.
`accepted` returns success. `rejected` still writes a canonical decision and
then fails the job. Operational or malformed-input failures return without an
acceptance decision.

## Reviewable policy source

Edit a copy of `examples/acceptance-policy/golden-policy.json`, then compile it
without replacing an existing destination:

```console
python3 tools/acceptance/compile_policy.py \
  --source policy/acceptance-policy.json \
  --output policy/acceptance-policy.cbor
```

Review and pin both the source commit and the printed policy identity. The JSON
file is compiler source, not a verification input. `pbr-accept` independently
decodes only deterministic-CBOR bytes under the closed CDDL schema.

## Retention and disclosure

By default the Action uploads nothing. It leaves derived outputs in its
runner-temporary result directory and binds every exact input by digest in the
decision. Setting `upload-exact-artifacts: "true"` explicitly authorizes the
Action to upload the supplied plan, policy, release, verifier, Runtime archive,
acceptor, and all derived outputs. Review those paths for secrets first.

GitHub's artifact store is a carrier, not the independent trust anchor. Trusted
digests and the policy identity must come from a separately reviewed channel.
A consumer that does not authorize GitHub upload should copy the outputs into
its own content-addressed retention system.

The Action is ready for external dogfood, but repository-local checks cannot
stand in for an independent consumer. Record the external repository, exact
workflow commit, run, retained decision identity, and adoption findings before
describing this as a proven adoption path.
