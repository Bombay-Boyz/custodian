# Custodian: A Haskell Binding for eBPF, Built to Be Read Like a Proof

**Status:** Implemented and verified. Release to Hackage is held until the
functional gaps in §7 are closed — see the Implementation Spec's appendix
for that work, itemized and estimated.
**Package name:** `custodian` — no conflicting Haskell package found in a
search pass. A direct, live check against `hackage.haskell.org/package/custodian`
is still required immediately before the eventual upload; it has not been
run, and a result today would be stale by the time release actually happens.
**Delivered scope:** 1,291 lines of library code, 926 lines of tests.
**Compiler baseline:** GHC 9.14.x — the first designated LTS release, with a
minimum two-year bugfix-support window. `LinearTypes` has been stable since
GHC 9.0.
**Standard:** every design decision below describes what was actually built
and verified, not an aspiration. A contribution that violates one of these
without an explicit, documented exception is not mergeable.

---

## 1. Problem Statement

Haskell has no binding to `libbpf` — the reference C library used by every
other serious eBPF ecosystem (Go's `cilium/ebpf`, Rust's `aya`) to load,
verify-interact-with, attach, and manage eBPF programs and maps. The only
Haskell projects touching eBPF operate at the bytecode-assembly layer
(`ebpf-tools`, `hBPF`), both unmaintained, neither wrapping `libbpf`'s
program/map lifecycle. The gap was real, current, and uncontested.

Custodian closes it. It sits underneath other people's tooling, marshaling
raw pointers across an unsafe FFI boundary into a kernel subsystem that can
deny work outright if handled incorrectly. Correctness here is not a
nice-to-have; it is the entire value proposition. A binding that leaks
kernel resources, silently swallows errors, double-frees a handle, or admits
an invalid state transition is strictly worse than no binding, because it
will be trusted.

## 2. Design Philosophy — Hard Constraints

### 2.1 Totality, enforced at the compiler level

Every function is total unless partiality is fundamentally unavoidable
(an FFI call that can fail for reasons outside our control). Where
partiality is unavoidable, it is made explicit in the type —
`Either CustodianError a`, never a silently-swallowed `Maybe`, never an
unchecked `error` call, never a partial pattern match outside of a
proof-carrying context (§2.4).

This is enforced with `-Wall -Werror` plus a curated `hlint` rule set that
bans partial functions (`head`, `fromJust`, `(!!)`) at the CI level. No total
prelude is used — the project imports plain `Prelude`/`Prelude.Linear`
throughout; the totality guarantee comes from the compiler-warning and lint
gates, not from swapping the standard library.

### 2.2 Dependency inversion, exercised for real — not just claimed

Every part of the system that touches the kernel is defined as a capability
typeclass — `ObjectLifecycle` (open/load/close), `AttachDetach`
(attach/detach), `MapLookup` (resolve a map by name to its fd *and* its
kernel-declared shape), `MapSyscalls` (the four element-level operations) —
and each capability is implemented **twice**: once against an in-process
accounting table (`Custodian.Mock`) with no kernel involved, and once against
real `libbpf` (`Custodian.Live`). The lifecycle functions in `Custodian.Core`
(`openObject`, `loadObject`, `attachObject`, `withLoadedBpfObject`,
`withAttachedBpfObject`) are written once, against the typeclasses, and run
unchanged against either instance. The 24-test property suite exercises this
directly against the mock; the live package's own build against real
`libbpf` is the same abstraction's second instantiation, not a parallel
implementation.

### 2.3 A single, closed error hierarchy

`Custodian.Errors.CustodianError` is one closed ADT, extended by adding
constructors, never worked around at a call site:

- `MockFailure String` — mock backend only.
- `LibbpfFailure String` — a real `libbpf`/kernel call failed; kept distinct
  from `MockFailure` so a real failure can never be mislabelled as a mock one.
- `SyscallFailure String CInt` — a map element syscall failed with a
  preserved raw `errno`, kept as a number (not a rendered string) so a
  caller can match on `EPERM`, `E2BIG`, etc. `ENOENT` is deliberately *not*
  reported here — for lookup and iteration it is the normal "absent"/"end"
  signal, folded into the result before it can reach this constructor.
- `MapShapeMismatch String MapMismatch` — a caller's key/value types
  disagreed with the kernel map's declared sizes, reported *before* any read
  or write can touch memory.

### 2.4 Illegal states are unrepresentable, not merely checked

- **Phantom-typed lifecycle.** `BpfObject objRes linkRes (s :: LifecycleState)`
  is a GADT indexed by `Opened | Loaded | Attached`. `loadObject` only
  type-checks against an `Opened` object; `attachObject` only against a
  `Loaded` one. There is no runtime "wrong state" check because there is no
  way to construct the wrong state in the first place.
- **Linear consumption.** Every handle-consuming step in the manual API
  (`openObject`/`loadObject`/`attachObject`/`teardown`) takes its argument
  with multiplicity `%1`, so double-teardown and dropped handles are
  compiler errors, not runtime bugs. Two of the five negative-compile-tests
  (Case 1: double teardown, Case 2: scope escape) exist specifically to
  prove this at the type level, not just assert it in prose.
- **`ValidKey`.** `BPF_MAP_TYPE_ARRAY` is indexed by a 32-bit slot number;
  keying one by anything but `Word32` fails to compile (Case 4).
- **`Deletable`.** `bpf_map_delete_elem` on an array-map slot returns
  `EINVAL` — a slot cannot cease to exist. Rather than a runtime `EINVAL`,
  `Deletable` has an instance only for `HashMap`, so `deleteMap` on an array
  map is a compile error (Case 5).

### 2.5 Scoped safety without forcing everything through linearity

Two deliberately different disciplines apply to the two resources that need
protecting, because they have different usage shapes:

- **The BPF object/link** (open once, close once) is protected by the
  **manual linear API** for auditability, and by a **scoped, exception-safe
  wrapper** (`withLoadedBpfObject`/`withAttachedBpfObject`) for ordinary use.
  The wrapper is a plain `Control.Exception.bracket`: acquisition happens
  once, release happens exactly once on every exit path (normal, exceptional,
  or asynchronous — `bracket` masks its own release), and the callback
  receives a rank-2-branded `Scope br objRes` that has no `Teardownable`
  instance (cannot be freed by the callback) and whose brand `br` never
  unifies outside the callback (cannot escape it). This is the same
  `runST`-style trick used for `ST`'s `STRef`, applied here to a kernel
  resource: no hand-rolled `mask`/`onException` pairing to get right, no
  named escape-hatch function — the standard library's own `bracket`
  combinator is the entire exactly-once guarantee.
- **A map handle** (`LiveMap sys br t k v`) is read/written repeatedly, so
  forcing it through linear multiplicity would mean pointless token-threading
  for no safety benefit. Instead it carries the same rank-2 brand
  (introduced by `withMap`'s callback type) so it cannot escape its scope,
  but is otherwise an ordinary, freely-reusable value within that scope.

**One residual gap, documented rather than hidden:** nothing stops a caller
from extracting the raw file descriptor via `liveMapFd` inside a callback
and stashing it somewhere that outlives the scope. The brand prevents the
*typed* handle from escaping; it does not stop a caller who deliberately
reaches around the API. This is an accepted limit on the guarantee, not a
silent one.

### 2.6 Header-derived offsets, never hand-transcribed

`struct bpf_map_info`'s field offsets are computed by `hsc2hs` from
`<linux/bpf.h>` at build time (`Custodian.Raw.MapInfo`), not hand-written. A
wrong offset in a hand-written `Storable` instance wouldn't fail to compile
and wouldn't throw — it would silently corrupt memory across the FFI
boundary, in exactly the part of a binding with the least type-level
protection by design. Deriving the offset from the header removes that
failure mode rather than merely documenting the risk.

### 2.7 The FFI transcript stays unrestricted and auditable

`Custodian.Raw` contains no linear types, no phantom lifecycle index, and no
`CustodianError` — it is meant to be auditable line-by-line against the C
headers, nothing more. Every declaration corresponds to exactly one `libbpf`
entry point, named identically with a `c_` prefix. The linear discipline,
the state machine, and the single error hierarchy are all properties of the
layer built *on top* of this (`Custodian.Core`, `Custodian.Live`), never
smuggled into the FFI declarations themselves.

## 3. What Is Actually Built

| Module | Role |
|---|---|
| `Custodian.Core` | Phantom-typed lifecycle GADT; `ObjectLifecycle`/`AttachDetach`/`Teardownable` capability classes; the manual linear API; the scoped, `bracket`-based API (`withLoadedBpfObject`, `withAttachedBpfObject`); the `Scope` brand. Backend-agnostic — runs unchanged against the mock or the real backend. |
| `Custodian.Errors` | The single `CustodianError` ADT and `MapMismatch`. |
| `Custodian.Map` | `MapType`/`SMapType`/`ValidKey`/`Deletable` classification; `MapShape` and `checkMapShape` (pure, total); `LiveMap`; `MapLookup`/`MapSyscalls` capability classes; `withMap`, `readMap`, `writeMap`, `deleteMap`, `mapKeys`. |
| `Custodian.Mock` | In-process instantiation of every capability class: `MockHandle` for the lifecycle side (no real resource — linearity alone is what prevents double-teardown), a genuine in-process hash table keyed by fd for the map side, so `readMap`/`writeMap`/etc. exercise real branching and `Storable` marshalling without a kernel. |
| `Custodian.Raw` | The unrestricted `libbpf` FFI transcript — every `foreign import` matches one C entry point, `c_`-prefixed, unrestricted. |
| `Custodian.Raw.MapInfo` | `hsc2hs`-derived `struct bpf_map_info` field offsets. |
| `Custodian.Live` | The real backend: `LiveObj`/`LiveLink`/`LiveSys` instantiating every capability class from `Custodian.Core` and `Custodian.Map` over `Custodian.Raw`. |

### Multi-program attach

Attaching a loaded object attaches **every** program it declares
(`c_bpf_object__next_program` is walked to exhaustion), collecting one link
per program into a single `LiveLink` bundle — a multi-program object is one
linear resource, matching how the mock's own accounting backend models a
link bundle. If any single program fails to attach, the links already
created are rolled back (detached) before the failure is returned, so a
partial attach never leaks; the object itself is handed back so the caller
can still close it through the ordinary API. Teardown destroys every link in
the bundle, newest-first, then closes the object.

### Map shape safety

A map is only ever resolved through `MapLookup.rawFindMap`, which returns
both the file descriptor *and* the kernel's own declared shape — sourced,
for the real backend, via `bpf_map_get_info_by_fd` decoded through the
`hsc2hs`-derived offsets in `Custodian.Raw.MapInfo`, never a userspace guess.
`withMap` calls `checkMapShape` against the caller's chosen key/value types
before ever constructing a `LiveMap`; on a mismatch it returns
`MapShapeMismatch` carrying all four sizes, and the callback never runs — so
no read or write on a mis-sized buffer is reachable. Element operations
(`Custodian.Map.MapSyscalls`) work at the raw byte level (`[Word8]`), so the
`Storable` marshalling in `readMap`/`writeMap` is genuinely exercised rather
than assumed.

## 4. Verification

- **24 Hedgehog property/unit tests** against the mock backend, covering:
  map-shape validation (match iff sizes equal; exact match accepts;
  off-by-one rejected), the `withMap` gate (accepts a matching shape and
  runs the callback; rejects a mismatch and the callback provably never
  runs), map element semantics (write-then-read, missing-key-is-`Nothing`,
  overwrite, delete-present-then-gone, delete-absent-is-error, key
  enumeration round-trip, empty-map-has-no-keys), errno preservation
  (lookup surfaces the errno verbatim; a hard failure is never mistaken for
  absent), array maps (write/read and key round-trips, `Word32`-keyed),
  bracket-wrapper correctness (closes exactly once on success and on a
  callback exception; open failure closes nothing; attach failure closes
  the object and never runs the callback; a multi-program object detaches
  every link on both the normal and the exceptional path), and the manual
  linear lifecycle balancing open/load/attach/teardown.
- **5 negative compile-must-fail cases** (plus one positive control that
  must still compile): double teardown, scope escape, a live map escaping
  its scope, a `Word32`-violating array-map key, and array-map deletion —
  each proving the corresponding illegal state is a compiler error, not a
  documented convention.
- **The live package** builds and links against real `libbpf`; its example
  and end-to-end test invoke real `libbpf` calls and propagate a real
  `LibbpfFailure` through the full stack. Loading and attaching a program
  additionally requires `CAP_BPF` + `CAP_PERFMON` (or root) and a compiled
  BPF object file — a permanent, universal fact about how Linux gates BPF,
  not a limitation of any one environment. Without those privileges the live
  test suite skips rather than asserting on a real load.

## 5. Known, Accepted Gaps (Not Yet Built)

Custodian does not currently implement:

- **CO-RE/BTF relocations** — "compile once, run on any kernel version."
- **XDP and TC (traffic-control) program types** — only tracepoint and
  kprobe/kretprobe are supported (auto-selected by `bpf_program__attach`
  from the ELF section).
- **Perf-event and ring-buffer maps** — streaming kernel→userspace events.
  Only `BPF_MAP_TYPE_HASH` and `BPF_MAP_TYPE_ARRAY` are supported.
- **Broader map-type coverage** (LRU hash, per-CPU, stack/queue).

These are the functional gaps versus `cilium/ebpf` (Go) and `aya` (Rust).
Closing them is committed, scoped, LOC-estimated work — see the
Implementation Spec's appendix — not a "maybe later" backlog item. Hackage
release does not happen until they are closed.

Separately, and explicitly **not** something this document can schedule:
production hardening that can only come from real-world usage — kernel-
version-matrix battle-testing, edge cases surfaced only by fleet-scale
deployment over time. That is a genuine, acknowledged cost, tracked as an
open risk (§6), not a checklist item.

## 6. Key Risks

1. **Kernel-version and ABI drift.** `libbpf`'s API surface and behavior can
   shift between versions; without a pinned build environment, a change
   upstream could silently alter behavior this project's tests don't cover.
2. **Privileged CI.** Testing the live path requires `CAP_BPF`/`CAP_PERFMON`
   and a real Linux kernel. Local verification (via `setcap` or `sudo`) is
   proven; continuous, automated privileged CI is not yet in place.
3. **The residual `liveMapFd` escape (§2.5).** Accepted and documented, not
   fixable within this design without forcing map handles through linear
   discipline they don't otherwise need.
4. **Production hardening is adoption-bound, not engineering-bound.** No
   amount of additional code written in isolation replicates the edge cases
   real-world, fleet-scale usage would surface. This is named explicitly so
   it is never mistaken for a solvable checklist item.

## 7. Release Policy

Custodian does not ship to Hackage on a calendar date — it ships when it is
at competitive functional parity with `cilium/ebpf` and `aya` on the gaps
named in §5. The live, direct Hackage name-availability check (see header)
is deliberately not run until immediately before that upload, since a
result today would be stale by the time release actually happens.
