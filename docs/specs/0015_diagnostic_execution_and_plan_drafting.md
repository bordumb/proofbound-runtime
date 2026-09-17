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
pbr-diagnose --plan SEED_PLAN --receipt ABSENT_RECEIPT --draft ABSENT_DRAFT \
  --cgroup-root DELEGATED_CGROUP_ROOT
```

The seed plan must already pass the normal strict plan parser and `plan check`.
It supplies the only authority available during the observed execution. The
diagnostic supervisor does not add a path, environment name, descriptor,
process allowance, resource allowance, or network authority when the target
encounters a denial.

The delegated cgroup root is explicit invocation input. The command does not
discover one from ambient environment or user configuration. The first command
uses fixed declared observation bounds of 100,000 total events, 10,000 events
per process, 256 lifetime processes, 4,096 path bytes, 4,096 tracee-string
bytes, 256 socket-address bytes, 40 symlink hops, and 16 MiB for each canonical
diagnostic artifact. A later interface may expose stricter values but must not
silently increase these bounds.

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
11. drain the child tree, remove the cgroup, and collect complete resource and
    stream observations through the existing cleanup contract; and
12. construct and publish the diagnostic receipt and draft.

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

The effectful trace receives that validated process bound before target
release. When every retained creator can have at most one process-creation
event pending while stopped, the exact drain set is bounded by twice the
declared process count. An attempt to exceed that closed drain capacity fails
the observer and makes publication ineligible. This capacity argument depends
on the registered Linux ptrace stop premise; native adversarial evidence must
test it on each supported architecture.

The trace sets an unreconciled-tree condition before it reads or registers a
reported child identity. A missing event message, invalid or duplicate
identity, closed-capacity excess, invalid thread-group identity, or failed
identity-stable handle acquisition leaves that condition set. The condition is
permanent for the trace. A terminal wait for every previously registered
process does not clear it, cannot produce a successful empty-tree report, and
makes all diagnostic publication ineligible.

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

Child creation also takes the exact configured stdout and stderr pipes, makes
both nonblocking, and starts one concurrent drain for each before the spawned
trace state becomes available. The drains have independent byte bounds and one
shared cancellation signal. The byte limits come
from the seed plan's separate stdout and stderr resource limits. An active
drain retains at most its limit but continues to read and discard bytes until
end of file. It reports `complete` only when no
bytes were discarded and `truncated` otherwise. A zero limit is valid, retains
no bytes, and still drains the stream. Natural completion can return the two
captures only after the trace tree is exactly empty. Forced termination can
return them only after the exact drain succeeds. A missing configured pipe,
drain-thread creation failure, read failure, or join failure is a closed
observer failure and permits no publication. Early typestate destruction
attempts child termination and wait before it cancels and joins outstanding
drains. A terminal setup wait that reaps the exact root disarms later numeric
child cleanup before it returns. A cancelled nonblocking drain observes the
cancellation no later than the next poll under the registered scheduler and
atomic-visibility premises. These are source-order and bounded-memory
properties. They do not establish Linux pipe progress, scheduler fairness, or
process-tree truth.

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
source property.

The active trace keeps a private set of exact tracee identities. It waits only
for an identity in that set and never uses a process-global wait. A
process-creation stop supplies a child identity before the stopped parent can
resume. The trace reads and retains the child's thread-group identity and an
identity-stable process handle before it adds the child. It pairs system-call
entry and exit information before it returns a complete system-call event. A
successful multithreaded exec requires the exact wait to report its requested
retained leader and the kernel event message to name a former thread retained
in that leader's group. It transfers the former state to the reported leader,
preserves a pending syscall entry for the following exit stop, and removes
superseded thread state. A terminal
wait removes exactly one retained tracee. Every returned nonterminal event
keeps its tracee stopped until the next request.

An unknown stop, invalid event, missing child, failed wait, failed information
read, or event timeout makes further collection ineligible and requires
termination and drain. Termination addresses retained thread groups through
pidfds. It does not send `SIGKILL` through a stored numeric process identifier.
The active trace continues exact waits after termination and follows any
process-creation or exec event already pending until its private set is empty.
Dropping an active trace sends termination through every retained pidfd.

Stream collection does not replace the command's wall-time or resource
lifecycle. The trace preparation surface takes the exact fresh cgroup version 2
owner and the seed plan's full resource limits. It rejects a cgroup identity or
readback mismatch. Preparation and the immediate pre-spawn transition each
require the initial resource snapshot to remain zero, membership to remain
empty, and the group to remain unpopulated. The control files are read again
immediately before spawn and immediately before target release; a drift from
the installed values fails closed. One absolute monotonic execution deadline
starts immediately before spawn and remains private across every setup
transition, option installation, target release, active observation, and
natural terminal collection. Each blocking or effectful transition checks the
same deadline after a ready stop or event and immediately before target release
or resume. A late-ready result is a timeout, not successful progress. The exact
child is placed in and read back from the cgroup before the spawned trace state
becomes available.
The source API checks the deadline only when its owner drives a consuming
transition. It is not an asynchronous watchdog. Command integration MUST drive
the trace loop without unbounded delay or install an independent watchdog
before the product describes the deadline as released wall-time enforcement.

When termination becomes mandatory, process-group signalling and a distinct
bounded cleanup deadline start before the adapter returns a drain-only state.
Every retained process-group signal must succeed. The same absolute cleanup
deadline then bounds exact waits, cgroup drain and removal, resource
observation, stream cancellation, and both joins; no cleanup owner starts a
fresh timeout. The cleanup deadline does not refresh or extend the execution
deadline. Natural or forced terminal capture requires an empty exact trace
tree, successful cgroup drain and removal, complete version 2 resource
observations, and joined stdout and stderr drains, in that order. Any
freshness, placement, signalling, cleanup, resource-observation, read, join, or
deadline failure blocks both complete and incomplete diagnostic publication.
This source contract does not prove native cgroup membership, clock progress,
termination, resource-counter truth, or stream progress. Those remain native
evidence obligations.

The diagnostic host must provide `PTRACE_GET_SYSCALL_INFO`, procfs `Tgid`
identity, `pidfd_open`, and `pidfd_send_signal`. Missing support fails before
release for the root handle or during observation for a child handle. This
source contract does not prove kernel event completeness, correct procfs or
pidfd behavior, successful termination, or tree-drain truth. The adapter must
still couple these events to the pure protocol before it can acknowledge a
drained tree.

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

The decoder accepts Linux audit architecture `0xc000003e` for x86_64 and
`0xc00000b7` for aarch64. The initial architecture-qualified syscall numbers
are:

| Class | x86_64 | aarch64 |
| --- | ---: | ---: |
| `open` | 2 | absent |
| `socket` | 41 | 198 |
| `connect` | 42 | 203 |
| `sendto` | 44 | 206 |
| `bind` | 49 | 200 |
| `clone` | 56 | 220 |
| `fork` | 57 | absent |
| `vfork` | 58 | absent |
| `execve` | 59 | 221 |
| `creat` | 85 | absent |
| `readlink` | 89 | absent |
| `openat` | 257 | 56 |
| `newfstatat` | 262 | 79 |
| `readlinkat` | 267 | 78 |
| `execveat` | 322 | 281 |
| `statx` | 332 | 291 |
| `clone3` | 435 | 435 |
| `openat2` | 437 | 437 |

The x32 syscall form is unsupported. `openat2` accepts the 24-byte `open_how`
form. `clone3` reads only its first flags word and accepts a multiple-of-eight
structure size from 8 through 88 bytes. Other registered forms fail closed.
An unregistered syscall number on a supported architecture produces no retained
event. An unknown architecture cannot distinguish registered from unregistered
numbers and therefore fails observation.

The observer reads operands only while the tracee is stopped at syscall entry.
A path read must find its terminating NUL within `tracee_string_bytes`, and the
bytes before that NUL must fit `path_bytes`. A socket address must fit
`socket_address_bytes`. A partial `process_vm_readv` result is completed by
another bounded read or rejected. `sendto` retains the supplied payload length
but never reads the payload pointer. No request body, response body, file
content, environment value, or credential value is read through this path.
Another tracee thread can mutate shared operand memory between the observer read
and kernel consumption. The captured value is therefore a bounded supplied
operand observation, not a kernel-selected identity.

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

The initial `kernel-selected` resolver is conservative. It runs before the
active trace can resume the event's exact stopped tracee. A successful
`open`, `openat`, `openat2`, or `creat` result is eligible only when it is a
nonnegative Linux descriptor value and that tracee is the only retained member
of the observed process tree. The single-tracee condition excludes another
retained process or thread that could share and replace the descriptor table
during observation. The resolver opens the exact `/proc/<pid>/fd/<fd>` object,
retains that handle while it reads the procfs link, and reads the device,
inode, mode, and mount identity from the retained handle. A successful
`execve` or `execveat` event is eligible only after exec identity
reconciliation removes superseded threads; the resolver retains the exact
`/proc/<pid>/exe` object before the stopped post-exec tracee can resume.

The retained link must name a valid UTF-8 normalized absolute path within the
declared path bound. Deleted targets, non-filesystem procfs link forms, missing
mount identity, identity-read failure, descriptor-width mismatch, multiple
retained tracees for a descriptor result, or any other ambiguity produces
`unresolved`. It does not guess an object and does not fail the production
boundary. `kernel-selected` requires the supplied operand and retained object
path, but it does not invent a followed-symlink count. A symlink-hop count is
present only when the separate denied-path candidate resolver actually walks
the supplied path.

The denied-path candidate resolver runs only while the exact caller is stopped
and is the sole retained tracee. It anchors an absolute operand below
`/proc/<pid>/root`. It anchors a relative operand below that root and the
stopped tracee's `/proc/<pid>/cwd`, or below the named nonnegative directory
descriptor. Parent traversal clamps at the tracee root. The resolver walks no
more than the declared symlink-hop bound, retains the final object, records its
normalized tracee-root-relative path and complete identity, and repeats the
complete pass. Equal paths, hop counts, and identities produce only
`stable-candidate`. A difference produces `identity-drift`; hop exhaustion
produces `symlink-limit`; and inaccessible, missing, deleted, escaped,
unsupported, or ambiguous cases remain unresolved. Because version 1 JSON
requires UTF-8 path text, a non-UTF-8 path causes the closed event-mapping error
and produces no candidate artifact. No candidate claims which object the failed
system call selected.

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

The command-generated receipt carries the closed active runtime premise set:
`PBR-DIAGNOSTIC-TRACE-AX-016`, `PBR-DIAGNOSTIC-DECODE-AX-017`,
`PBR-DIAGNOSTIC-STREAM-AX-022`, `PBR-DIAGNOSTIC-LIFECYCLE-AX-023`,
`PBR-DIAGNOSTIC-OBJECT-AX-025`, `PBR-DIAGNOSTIC-CANDIDATE-AX-027`, and
`PBR-DIAGNOSTIC-COMMAND-AX-029`. Compiler and independent-check premises stay
in the evidence ledger and are not represented as runtime platform premises.

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

`PBR-OBSERVER-023` checks only the active-trace source structure and closed
value tests. `PBR-DIAGNOSTIC-TRACE-AX-016` retains the Linux ptrace, exact-wait,
procfs thread-group, pidfd, signal, and terminal-reporting premises. Native
adversarial evidence on both architectures is required before Runtime claims
that the effectful observer retains or drains a complete process tree.

`PBR-OBSERVER-024` checks the source-level coupling between complete live trace
events, the bounded pure protocol, overflow identity retention, the drain-only
typestate, and the ordering of an effectful empty-tree report before a pure
tree-empty acknowledgement. It does not strengthen the Linux premise or make
the diagnostic executable a released artifact.

`PBR-OBSERVER-025` checks the aggregate source path from pure bound accessors
through adapter derivation, irreversible failure-to-drain coupling, pre-resume
entry capture, the closed x86_64 and aarch64 decoder tables, supported
structure sizes, argument-width and byte-order helpers, independent operand
bounds, exact-or-error tracee reads, raw read-only syscall confinement, and
payload exclusion. The syscall-information form accepts zero reserved and
flags fields and the exact operation-specific returned size; extensions fail
closed until registered. The evidence byte-pins the compiler and
crate-selection closure and compiles the selected adapter release and drain
paths. It does not establish the Linux ABI, tracee-memory stability,
kernel-selected object identity, or native observation completeness.

`PBR-OBSERVER-029` checks the source-level stopped-tracee retention and mapping
rules for successful descriptor and post-exec objects. It inherits
`PBR-DIAGNOSTIC-OBJECT-AX-025` and the independent-check premise
`PBR-DIAGNOSTIC-OBJECT-CHECK-AX-024`. It does not establish Linux procfs,
`O_PATH`, `statx`, mount, pathname, or stopped-tracee truth.

`PBR-OBSERVER-030` checks the source-level root confinement, bounded symlink
walk, repeated candidate observation, drift handling, and advisory-only
mapping. It inherits `PBR-DIAGNOSTIC-CANDIDATE-AX-027` and the independent-check
premise `PBR-DIAGNOSTIC-CANDIDATE-CHECK-AX-026`. Two equal passes do not prove
race freedom or identify the object selected by a failed system call.

`PBR-OBSERVER-031` checks the separate command's seed-authority reuse, terminal
publication gate, absent-target publication, production dependency separation,
and release inventory. It inherits `PBR-DIAGNOSTIC-COMMAND-AX-029` and the
independent-check premise `PBR-DIAGNOSTIC-COMMAND-CHECK-AX-028`. Its receipt
also preserves the active trace, decode, stream, lifecycle, object, and
candidate runtime premises. Native and released-artifact behavior remain
separate obligations.

RT-8 closes only after one maintained dynamic workload displays all available
provenance classes, requires human completion, passes the independent
non-reuse checks, and runs the native attack corpus on both supported
architectures.
