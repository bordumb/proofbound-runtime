# Aeneas Lean support profile

This directory vendors the Lean support library from Aeneas commit
`f9a8e338188447c77f31246892cb9a7a742e58ef`. The production Rust translation
under `formal/generated/` remains byte-pinned to Aeneas `3a8586fa` and Charon
`0.1.225`; this support snapshot does not change the translator identity.

Runtime carries a narrow Lean 4.33 compatibility patch over that support
snapshot. The patch updates renamed Lean APIs, adapts array, vector, slice, and
weakest-precondition definitions, and excludes upstream test-only imports that
do not compile on the selected release. The core `step` tactic is included;
its embedded self-tests and optional step extensions are excluded. The exact
dependency revisions are recorded in `lake-manifest.json`.

Upstream Aeneas is licensed under Apache-2.0. The vendored license is retained
as `LICENSE.md`.
