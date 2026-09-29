# Declared-egress OpenTofu workload

The native CI lane runs this configuration with OpenTofu 1.10.6 and the two
provider packages pinned in `.terraform.lock.hcl`. The `http` provider reads
`/health`; the `restapi` provider creates and reads `/records/proofbound-fixture`.
Both use `https://api.fixture.test:48443` through the declared-egress CONNECT
proxy. The fixture supplies only that DNS name and a private host address.

`tools/ci/native-opentofu.sh` first runs `tofu init` as a separate
network-denied Runtime execution with provider packages from a pinned local
mirror. It then lists OpenTofu and both exact installed provider binaries in a
version 3 executable set and runs `tofu apply`. The provider installation is
read-only during apply; state and temporary files go beneath a fresh output
root. The script verifies both receipts and checks the resulting state and
fixture events. It retains receipts and executable digests as native evidence.

The fixture generates its TLS key and credential for each run and deletes
both when the run ends. Neither value is included in retained evidence.
