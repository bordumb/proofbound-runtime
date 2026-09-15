# Specification 0015: Diagnostic execution and plan drafting

- **Status:** accepted for claim-sized implementation
- **Date:** 2026-09-15
- **Applies to:** `pbr-diagnose` and RT-8 drafting artifacts
- **Roadmap:** RT-8
- **Decision:** [ADR 0008](../adr/0008-separate-ptrace-diagnostic-observer.md)

## 1. Purpose and non-claims

The diagnostic profile helps a person prepare a Runtime execution plan for one
identified program and one observed input path. It does not infer a safe plan,
grant authority, prove behavioral completeness, or create reusable execution
evidence.

The diagnostic profile executes target code. It is distinct from the read-only
`pbr plan scaffold` command and from the production `pbr run` command.

## 2. Closed profile and command

`ExecutionProfile` has exactly two values:

- `production`; and
- `diagnostic`.

The profile is an invocation property. It is not added to an existing plan or
production receipt schema. `pbr run` always selects `production`.
`pbr-diagnose` always selects `diagnostic`.

The first command is:

```text
pbr-diagnose --plan SEED_PLAN --receipt ABSENT_RECEIPT --draft ABSENT_DRAFT
```

The seed plan must already pass the normal strict plan parser and `plan check`.
It supplies the only authority available during the observed execution. The
diagnostic supervisor does not add a path, environment name, descriptor,
process allowance, resource allowance, or network authority when the target
encounters a denial.

Both output paths must be absent regular-file candidates outside the child
write authority. Publication uses the existing no-replace durability pattern.
A partial observer result may be published only when it is structurally valid,
states `completion: "incomplete"`, and lists the exact gaps. Setup failure
before target release publishes neither output.

## 3. Boundary order

The diagnostic launch protocol performs these transitions:

1. strictly parse and normalize the seed plan;
2. probe all production and diagnostic host requirements;
3. identify all declared artifacts and output targets;
4. create the bounded cgroup and launcher channel;
5. create the stopped launcher process and establish ptrace ownership;
6. install and read back the normal Landlock, seccomp, cgroup, descriptor, and
   environment boundary;
7. require the launcher's ready acknowledgement while it waits for the
   identity-bound exec release;
8. stop the acknowledged launcher and enable the closed process-tree trace
   options;
9. send the identity-bound exec release and release target code;
10. observe bounded events without changing target behavior;
11. drain the child tree and resource observations;
12. construct and publish the diagnostic receipt and draft; and
13. remove the cgroup through the existing cleanup contract.

Failure at steps 1 through 8 starts no target code. A ptrace detach, unknown
stop, lost child, or observer failure after step 9 terminates the execution,
marks the result incomplete where publication remains possible, and never
falls back to unobserved execution.

The pure observer protocol represents this order with closed states for
prepared, attached, boundary-ready, options-enabled, released, draining,
complete, incomplete, and failed-before-release. A setup failure directs the
adapter to terminate the stopped tree and publish nothing. A post-release gap
directs the adapter to terminate and drain the tree. The protocol permits
complete or incomplete publication only after every retained process has a
terminal wait result. After a termination directive, incomplete publication
also requires an adapter acknowledgement that the complete child tree is
empty. The pure protocol orders and requires this acknowledgement. It does not
establish that the effectful observation is true.

The root process counts against the lifetime process bound. An exited process
does not release a process slot for later reuse. Reaching an event or process
capacity naturally does not create a gap. An attempted item after capacity
creates the exact gap and starts drain. During drain, the protocol collects no
more events. It retains a newly discovered child only while the lifetime
process bound permits that state, and it continues to direct termination. An
observed overflow or unknown process is not added to the bounded retained
ledger. Its existence invalidates any earlier tree-drain acknowledgement and
blocks publication until the adapter confirms the tree is empty again.

The Linux implementation keeps its effectful observer in a separate crate.
That crate alone enables the diagnostic observer feature on the Linux boundary
crate. The production CLI uses the default empty feature set. The safe startup
API uses non-copy typestates and can construct an active trace only after the
exact initial exec stop, trusted launcher pause, matching boundary identity,
closed ptrace option set, identity-bound release, and syscall-stop activation
occur in order. Preparation accepts one identified launcher file, revalidates
it during preparation and immediately before spawn, executes it through its
retained descriptor, and creates the launcher
command and private channel as one session. The session retains the exact
install request, both channel ends, the launcher descriptor, and every borrowed
inherited descriptor through one consuming spawn. After
spawn, every state moves the same private child, process identity, supervisor
channel, and request. It receives and verifies the boundary acknowledgement
internally and sends the release through that same channel. No safe transition
accepts a caller-supplied acknowledgement, expected identity, or release
channel. The child guard attempts to kill and reap the child when a state is
abandoned. This source property does not prove the corresponding Linux effects,
successful cleanup, or complete process-tree cleanup.

The separate diagnostic Linux adapter is the supported composition surface for
these trace-startup typestates. It validates the observation bounds before child
creation. After the exact initial trace stop, each adapter state privately
owns one matching trace typestate and one pure observer protocol. The exact
spawned process identity seeds that protocol only after the same process reaches
the stop. It records boundary readiness only after acknowledgement. The Linux
option operation returns the exact installed bits through the trace typestate;
the adapter must parse those bits through the closed pure option type before it
records trace-option readiness. It authorizes release in the pure protocol
before the same consuming transition releases target code. The adapter exposes
process identity and read-only protocol state. It does not expose public owner
fields, raw trace typestates, or mutable protocol access. This coupling is a
source property and does not implement or prove the live process-tree event
loop.

## 4. Observer contract

The first observer mechanism identity is `linux-ptrace-syscall-v1`. It uses
`PTRACE_GET_SYSCALL_INFO` and follows clone, fork, vfork, and exec events. The
closed initial event set is:

- `open`, `openat`, and `openat2`;
- `creat`;
- `execve` and `execveat`;
- `statx`, `newfstatat`, `readlink`, and `readlinkat`;
- `connect`, `bind`, `sendto`, and socket creation; and
- process creation and image replacement events needed to retain tree
  coverage.

An event records the architecture, process identity, monotonically increasing
sequence, syscall class, supplied operands within the read bound, result or
error, and one closed resolution state. The states are:

- `kernel-selected`: a successful returned descriptor or executed image names
  the kernel-selected object while the tracee is stopped;
- `stable-candidate`: the supervisor resolved a denied operand and observed no
  identity drift across its bounded check;
- `unresolved`: resolution was impossible or ambiguous; and
- `redacted`: the value is outside the safe diagnostic output policy.

Only `kernel-selected` describes the target actually selected by the traced
syscall. A `stable-candidate` remains advisory. Secret environment values,
request bodies, response bodies, file contents, and credential material are
never read or recorded.

The implementation fixes bounds for total processes, total events, events per
process, tracee string bytes, path bytes, symlink hops, socket-address bytes,
and output bytes. Exhausting a bound while another item remains emits its exact
gap and stops collecting that class. A run that ends naturally with a count
equal to its bound does not claim a gap. A declared count gap is valid only
when the retained count equals the bound. Silent truncation is forbidden.

## 5. Diagnostic receipt

The receipt schema is `proofbound-runtime-diagnostic-receipt/1`. It is one
duplicate-free canonical JSON object with these required top-level members:

- `schema` with the exact schema identity;
- `execution_profile` equal to `diagnostic`;
- `safe_policy` equal to `false`;
- `reusable` equal to `false`;
- exact diagnostic execution, seed-plan, target, Runtime, launcher, observer,
  platform, and mechanism identities;
- the arguments and registered environment names that selected the path;
- declared observation bounds;
- ordered observation events;
- a closed completion state and sorted gap set; and
- the diagnostic trusted-computing-base roles and assumptions.

The receipt is a diagnostic accountability record. Its SHA-256 commitment can
identify exact bytes, but neither the bytes nor the commitment are accepted by
the production receipt verifier.

The producer applies `bounds.output_bytes` while it encodes the canonical
receipt. It does not first allocate a complete receipt-sized JSON value and
check its size afterward. A bound failure publishes no partial object.

## 6. Draft report

The draft schema is `proofbound-runtime-plan-draft/1`. It is duplicate-free
canonical JSON and contains `safe_policy: false`. Every candidate item has one
or more of these closed provenance values:

- `human-authored`;
- `static-executable-closure`;
- `diagnostic-runtime-observation`;
- `capsec-source-observation`; and
- `platform-required-closure`.

The draft may suggest a read root, executable, loader, or runtime library when
the observation supplies an exact target and the collapse rule is safe. It
must not automatically create a write root or network rule. It must not add an
environment name or resource limit. These remain open human choices.

Path collapse finds the narrowest common ancestor within one registered
project or runtime closure. It never collapses to `/`, a home directory, a
system directory, `/tmp`, `/var/tmp`, or another configured temporary root.
When no permitted collapse exists, individual paths remain visible.

Every draft retains:

- the exact diagnostic receipt commitment;
- the seed plan and optional static scaffold identities;
- the arguments, registered environment names, and identified inputs;
- counts of suggested roots, broad roots, unresolved events, and denials;
- every gap from the diagnostic receipt; and
- open choices for write roots, environment names, limits, and network mode.

An optional Capsec report is usable for comparison only when its closed schema,
source identity, analyzer identity, and report identity match the selected
integration profile. A missing, stale, unknown, or incomplete report remains a
visible open item. Capsec observations never become Runtime authority.

The draft always carries `capsec` as either `null` or one closed identity
record. A record retains the schema identity, exact source, analyzer, and
report content identities, plus one closed usability result. A candidate can
carry `capsec-source-observation` only when that result is `usable`. The draft
also carries a closed `differences` list with the three comparison classes from
Specification 0013. These entries are review information and cannot grant
authority.

The same bounded streaming rule applies to the plan draft. The producer stops
with the typed output-bound error before it retains bytes beyond the declared
limit. A caller-supplied large comparison collection cannot cause construction
of one complete unbounded JSON value before this check.

## 7. Mandatory rejection

The production consumers recognize the diagnostic schema only to reject it.
They do not decode diagnostic events or trust the diagnostic producer.

- `pbr-verify` exits with the verification-failure class and
  `profile.diagnostic.not-reusable`.
- `pbr-compose` propagates the same stable reason and produces no composed
  receipt.
- `pbr-accept` produces a rejected decision with reason
  `diagnostic-profile-not-reusable` and no composition identity.
- `pbr plan check` and `pbr run` reject both diagnostic artifacts as invalid
  plans.

Changing the schema string cannot turn a diagnostic object into a production
receipt because the production schema is closed and independently decoded.

## 8. Required falsifiers

The registered corpus includes:

- diagnostic receipt substitution into verify, compose, accept, plan check,
  and run;
- diagnostic schema relabeling and duplicate schema members;
- observer source linked into either production executable;
- a target that detects ptrace and changes behavior;
- event, process, string, path, symlink, socket-address, and output overflow;
- clone, fork, vfork, exec, and short-lived child races;
- successful and denied open operations;
- a stable symlink to a system directory and a concurrently changed symlink;
- relative paths under a changed working directory and directory descriptor;
- unknown syscall and architecture values;
- direct network attempts that produce open decisions and no authority;
- stale Capsec source, unknown Capsec schema, incomplete Capsec coverage, and
  attempted provenance relabeling; and
- a draft with each mandatory human choice absent.

## 9. Evidence meaning

Passing evidence establishes only the behavior of the registered bounded
fixtures on the identified implementations and platforms. It does not prove
complete observation, equivalent behavior without ptrace, correctness of the
Linux kernel, absence of unobserved effects, or safety of a completed plan.

RT-8 closes only after one maintained dynamic workload displays all available
provenance classes, requires human completion, passes the independent
non-reuse checks, and runs the native attack corpus on both supported
architectures.
