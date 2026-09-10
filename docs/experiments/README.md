# Experiments

This directory contains pre-registered Runtime investigations and their exact
results. An experiment is not a specification, architecture decision, product
claim, or Proofbound evidence merely because it is reproducible.

## Rules

- Freeze the question, fixtures, mechanisms, attacks, measurements, and
  decision criteria before recording results.
- Keep credentials and real secret values out of fixtures, logs, receipts, and
  committed output.
- Record exact source, tool, kernel, architecture, configuration, and artifact
  identities for each run.
- Preserve negative and ambiguous results. Do not rewrite a protocol to make a
  preferred mechanism appear inevitable.
- Put accepted trust-boundary choices in a new ADR. Put normative wire and
  product behavior in a reviewed specification.
- Treat a passing experiment as bounded observation, not proof of universal
  enforcement or production readiness.

## Index

| Experiment | Question | Status |
| --- | --- | --- |
| [0001](0001-network-authority-mechanisms.md) | Which Linux profile can honestly enforce one declared HTTPS service identity? | pre-registered |
