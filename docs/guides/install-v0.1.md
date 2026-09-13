# Install and prepare Proofbound Runtime version 0.1

- **Applies to:** Proofbound Runtime 0.1.0
- **Supported hosts:** native Linux `x86_64` and `aarch64`
- **Distribution:** GitHub release `v0.1.0`

This guide installs one exact binary archive and prepares the cgroup v2
delegation required by the version 1 execution profile. Plan validation and
receipt inspection can run on other platforms, but native execution cannot.

## Trust inputs

The expected archive digests below are copied into the reviewed repository.
They identify the exact bytes produced by release run
[`34361101393`](https://github.com/bordumb/proofbound-runtime/actions/runs/34361101393).
The release tag points to commit
`c78e189e2e098489ebf9f45840bdf9ff6cb0fd6d`.

| Architecture | Target | Archive SHA-256 |
| --- | --- | --- |
| `x86_64` | `x86_64-unknown-linux-gnu` | `e0bf91c787d67be9c96f76992b661c3fa905707491e51310673302bf88776040` |
| `aarch64` | `aarch64-unknown-linux-gnu` | `a30e3b83eaa56a2a97b111a551d75c63261e0247ac65c30c51e787f49db6138f` |

A matching digest establishes byte identity after the expected digest is
trusted. It does not authenticate GitHub, the repository owner, the release
workflow, or the build host. Those remain distribution and toolchain trust
inputs. The assurance archives published with the release retain the exact
build, verification, observation, and composition records.

## Install the exact archive

Use the Quick start in the repository README for a manual download. It refuses
an existing archive or destination, downloads only over HTTPS, verifies the
reviewed digest, and keeps all four binaries together.

From a repository checkout, the maintained installer adds closed archive and
member validation:

```console
destination="$PWD/proofbound-runtime-v0.1.0"
test ! -e "$destination"
python3 tools/install_release.py \
  --version 0.1.0 \
  --destination "$destination"
```

The installer:

- supports only release/architecture pairs with an embedded reviewed digest;
- rejects an unsupported host architecture;
- limits the downloaded and uncompressed member sizes;
- requires the exact ordered archive inventory;
- rejects links and non-regular members;
- verifies the closed release manifest and each binary's size and digest; and
- creates a new absolute destination without replacing existing data.

Use `--archive /absolute/path/to/archive.tar.gz` for an offline archive. The
same embedded digest and member checks still apply.

## Prepare a temporary systemd delegation

Version 0.1 requires a cgroup v2 delegation with the `pids` controller enabled,
an empty delegation root, and a separate supervisor leaf. The maintained
native corpus uses a transient systemd service with `Delegate=pids` and
`DelegateSubgroup=proofbound-runtime-supervisor`.

Start an interactive shell with the same topology:

```console
sudo systemd-run \
  --quiet \
  --wait \
  --collect \
  --pty \
  --service-type=exec \
  --unit="proofbound-runtime-shell-$$" \
  --property="User=$(id -un)" \
  --property="Group=$(id -gn)" \
  --property=Delegate=pids \
  --property=DelegateSubgroup=proofbound-runtime-supervisor \
  --working-directory="$PWD" \
  /usr/bin/env bash
```

Inside that shell, resolve the delegation root from the unified cgroup entry:

```console
destination=/absolute/path/to/proofbound-runtime-v0.1.0
test -x "$destination/pbr"
current_cgroup="$(awk -F: '$1 == "0" { print $3 }' /proc/self/cgroup)"
supervisor_leaf=proofbound-runtime-supervisor
case "$current_cgroup" in
  */"$supervisor_leaf") ;;
  *)
    echo "process is not in the expected supervisor leaf" >&2
    exit 3
    ;;
esac
delegation_relative="${current_cgroup%/"$supervisor_leaf"}"
cgroup_root="/sys/fs/cgroup${delegation_relative}"
if [[ -n "$(<"$cgroup_root/cgroup.procs")" ]]; then
  echo "delegation root contains direct processes" >&2
  exit 3
fi
grep -qw pids "$cgroup_root/cgroup.controllers"
echo +pids >"$cgroup_root/cgroup.subtree_control"
grep -qw pids "$cgroup_root/cgroup.subtree_control"
"$destination/pbr" doctor --cgroup-root "$cgroup_root"
```

Do not continue if any command fails or if `doctor` reports `supported: false`.
Do not substitute a container, mock, cgroup v1 path, populated delegation root,
or newer unreviewed Landlock ABI as native version 1 evidence.

## Run and verify

Create the closed version 1 plan from the README in a new working directory.
The output directory and receipt path must not exist before the run. Then use
the `cgroup_root` derived above:

```console
"$destination/pbr" plan check --plan plan.toml
"$destination/pbr" run \
  --plan plan.toml \
  --receipt receipt.json \
  --cgroup-root "$cgroup_root" >run-result.json
commitment="$(python3 -c \
  'import json; print(json.load(open("run-result.json"))["commitment"])')"
execution_id="$(python3 -c \
  'import json; print(json.load(open("run-result.json"))["execution_id"])')"
"$destination/pbr-verify" \
  --expected-commitment "$commitment" \
  receipt.json
"$destination/pbr" inspect receipt.json
```

Keep `run-result.json` on the independent control channel used by the caller.
Do not derive the expected execution ID or commitment from a receipt supplied
by the receipt carrier.

## Failure recovery

- A digest mismatch means the archive is not the reviewed release. Do not
  extract it.
- An existing destination is never replaced. Choose a new path or inspect and
  remove the old path deliberately.
- An unsupported `doctor` result identifies an unavailable required mechanism.
  It does not authorize a weaker run.
- A failed native run can leave diagnostic output, but it cannot turn an
  incomplete boundary into an eligible receipt.

Exit the transient shell to let systemd collect its delegated service.
