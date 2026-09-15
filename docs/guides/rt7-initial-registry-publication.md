# Prepare the first RT-7 registry publication

- **Status:** external setup procedure; no registry publication is yet admitted
- **Last checked:** 2026-09-15
- **Applies to:** the first protected publication of the four packages selected
  by Specification 0014
- **Source workflow:** `.github/workflows/release.yml`
- **GitHub environment:** `package-publish`

This guide prepares the external state that repository evidence cannot create
or verify. It does not authorize a release. The release maintainer must still
select one independently approved exact commit on `main`, approve the protected
environment deployment, and inspect the retained registry observations.

The initial package names are currently absent from crates.io, PyPI, and npm.
PyPI can create a project through a pending trusted publisher. npm cannot attach
a trusted publisher until the package already exists. The first npm upload
therefore uses one separately selected, absence-gated token path. Every later
npm upload uses OIDC and rejects that bootstrap selection.

Authoritative external instructions:

- [GitHub deployment environments](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [PyPI pending trusted publishers](https://docs.pypi.org/trusted-publishers/creating-a-project-through-oidc/)
- [npm trusted publishers](https://docs.npmjs.com/trusted-publishers/)
- [npm trust prerequisites](https://docs.npmjs.com/cli/v11/commands/npm-trust/)
- [Cargo publish authentication](https://doc.rust-lang.org/cargo/commands/cargo-publish.html)

## 1. Protect the GitHub publication environment

Create the `package-publish` environment in `bordumb/proofbound-runtime`.
Configure all of these controls before adding a credential:

1. Restrict deployment branches to `main`.
2. Require an explicit deployment approval. Prefer a reviewer who did not
   author the selected source wave and enable prevention of self-review when a
   second release principal is available.
3. Disable administrator bypass when the repository plan supports that control.
4. Give only release maintainers permission to change the environment, workflow,
   or repository secret settings.

An environment name without these controls is not the protected approval named
by `PBR-DISTRIBUTION-018`.

## 2. Prepare crates.io

Confirm that the release owner controls the intended package names and has
two-factor authentication enabled. Create the shortest-lived token that can
publish new packages for this one release. Store it only as the environment
secret `CARGO_REGISTRY_TOKEN`.

The workflow exposes that value only to the two ordered Rust publication steps.
It publishes `proofbound-runtime-verify` first and
`proofbound-runtime-sdk` second. Delete or revoke the token after the protected
run finishes. Repository checks cannot prove its scope, custody, or revocation.

## 3. Prepare the PyPI pending publisher

Create one pending PyPI trusted publisher with these exact values:

| Field | Value |
| --- | --- |
| PyPI project | `proofbound-runtime-sdk` |
| GitHub owner | `bordumb` |
| GitHub repository | `proofbound-runtime` |
| Workflow filename | `release.yml` |
| Environment | `package-publish` |

Do not publish a placeholder wheel. The pending publisher creates the project
from the exact protected workflow and then becomes the normal publisher.

## 4. Prepare the one-time npm bootstrap

Confirm control of the `@proofbound` npm scope and enable two-factor
authentication on the publishing account. Because
`@proofbound/runtime-sdk` does not yet exist, npm cannot accept an OIDC trusted
publisher for it.

Create the shortest-lived granular token that can perform the initial public
write in the `@proofbound` scope and can complete non-interactive publication
under the account's two-factor policy. Store it only as the environment secret
`NPM_INITIAL_PUBLISH_TOKEN`. Do not put it in repository, organization, local
shell, package, plan, receipt, log, or fixture state.

The workflow uses this secret only when both conditions hold:

- `publish_packages` is `true`; and
- `bootstrap_npm_package` is `true` while the anonymous npm package endpoint
  returns exactly `404`.

Any other package state, redirect, timeout, or HTTP result fails closed before
the token-bearing step. The source check also requires the exact package script
inventory to contain no npm publish lifecycle hook that could inherit the
token. Both npm publish commands also disable lifecycle scripts. A race in
which another publisher creates the package causes npm to reject the upload.

## 5. Dispatch the first protected run

Use the complete 40-character identity of the independently approved commit on
`main`. Dispatch `Reproducible release artifacts` with:

| Input | First publication value |
| --- | --- |
| `revision` | exact approved `main` commit |
| `publish_packages` | `true` |
| `bootstrap_npm_package` | `true` |

Approve the `package-publish` deployment only after the non-publishing release,
provenance, and exact-source jobs pass. Do not approve a different revision,
branch, workflow, package inventory, or environment configuration.

The publication sequence is verifier crate, Rust SDK crate, Python wheel, npm
tarball, then credential-free anonymous observation. The current-integration
record is built and independently verified only after all four downloaded
registry artifacts match the approved retained bytes.

If a publisher reports an ambiguous result after sending bytes, stop. Inspect
the anonymous registry bytes before any retry. Do not dispatch a fresh release,
publish a placeholder, change a package label, or overwrite retained evidence
to work around a partial publication. A partial registry state is explicitly
not a current supported tuple.

## 6. Replace the npm bootstrap with OIDC

Immediately after the first npm package exists:

1. Add its GitHub Actions trusted publisher with owner `bordumb`, repository
   `proofbound-runtime`, workflow filename `release.yml`, environment
   `package-publish`, and direct `npm publish` permission.
2. Delete `NPM_INITIAL_PUBLISH_TOKEN` from the GitHub environment.
3. Revoke the token at npm.
4. Use `bootstrap_npm_package=false` for every later publication.

The normal route first requires the anonymous package endpoint to return
exactly `200`, then publishes through the workflow's OIDC identity. It never
references the bootstrap token.

## 7. Close the external evidence

Retain these identities from the successful protected run:

- exact source revision and workflow run;
- all four registry observation entries;
- both Runtime release artifacts and both acceptor artifacts;
- deterministic-CBOR current-integration record, JSON projection, and Markdown
  rendering; and
- deployment approver and external registry configuration review.

Then install each registry package from an unrelated consumer repository or
independently controlled consumer environment. Record the consumer revision,
dependency lock identities, run identity, and observed package bytes. Do not
replace that observation with a workspace path, local package archive, registry
label, or adjacent checksum.

RT-7 closes only after the protected publication, exact anonymous observation,
unrelated consumer exercise, and retained current-integration tuple all refer to
the same exact Runtime source.
