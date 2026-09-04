# Model-check units

This directory will contain bounded model-check manifests.

Every unit must state its exact harness inventory and finite unwind or domain
bounds. A successful unit can support `BOUNDED_CHECKED`; it cannot establish an
unbounded theorem.
