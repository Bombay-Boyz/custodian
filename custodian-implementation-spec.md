# Custodian — Implementation Spec

Derived from `custodian-vision.md`. This document describes what was built,
module by module, how it's verified, and what remains before release. Read
the vision doc first for the rationale behind each constraint.

---

## Delivered system

**1,291 lines of library code, 926 lines of tests** (a ~0.7:1 test-to-code
ratio). All of the following is built, compiling, and passing its test
suite today.

### `Custodian.Core` — backend-agnostic lifecycle

- `LifecycleState` (`Opened | Loaded | Attached`) and the GADT
  `BpfObject objRes linkRes (s :: LifecycleState)` indexed by it.
- Capability classes: `ObjectLifecycle` (`rawOpen`/`rawLoad`/`rawClose`),
  `AttachDetach` (`rawAttach`/`rawDetach`, with a functional dependency
  tying `linkRes` and `objRes` together one-to-one), `Teardownable` (one
  instance per lifecycle state — `Loaded` just closes; `Attached` detaches
  the link, then closes).
- The manual linear API: `openObject`, `loadObject`, `attachObject` — every
  handle-consuming argument at multiplicity `%1`.
- The scoped API: `withLoadedBpfObject`, `withAttachedBpfObject`. Each
  acquires the resource(s), then hands the callback a rank-2-branded `Scope`
  via a single `Control.Exception.bracket` — release happens exactly once,
  on every exit path, with no hand-rolled `mask`/`onException` pairing.
  `withAttachedBpfObject` additionally closes the object if the attach step
  itself fails, before the bracket around the callback is ever entered.

### `Custodian.Errors`

`CustodianError` (`MockFailure`, `LibbpfFailure`, `SyscallFailure String
CInt`, `MapShapeMismatch String MapMismatch`) and `MapMismatch` (the four
sizes involved in a shape disagreement). `Consumable`/`Dupable`/`Movable`
instances via the sanctioned `Unsafe.toLinear` escape, since the type owns
no resource and duplication/discarding is genuinely free.

### `Custodian.Map` — the typed map API

- `MapType` (`HashMap | ArrayMap`, promoted via `DataKinds`) and its
  singleton `SMapType`.
- `ValidKey (t :: MapType) k` — `HashMap` accepts any `Storable` key;
  `ArrayMap` accepts only `Word32`. An array map keyed by anything else
  fails to compile.
- `Deletable (t :: MapType)` — instance only for `HashMap`. Deleting from
  an array map is a compile error, matching `bpf_map_delete_elem`'s real
  `EINVAL` on a fixed-size table.
- `MapShape` (`shapeKeySize`, `shapeValueSize`) and `checkMapShape` — a
  pure, total function: the caller's chosen types fit the kernel map iff
  their `sizeOf`s match exactly; otherwise a `MapMismatch` with all four
  numbers.
- `LiveMap sys br (t :: MapType) k v` — a rank-2-branded, fd-backed handle.
  Not linear: reads and writes are repeatable, so forcing `%1` here would
  just be token-threading with no safety benefit.
- Capability classes: `MapLookup` (`type Sys objRes`; `rawFindMap` returns
  both the fd and the kernel-declared `MapShape`) and `MapSyscalls`
  (`sysLookup`/`sysUpdate`/`sysDelete`/`sysKeys`, all working over raw
  `[Word8]` so `Storable` marshalling is genuinely exercised, all
  errno-preserving with `ENOENT` folded into the *result*, not the error).
- `withMap`, `readMap`, `writeMap`, `deleteMap`, `mapKeys` — `withMap`
  validates shape before ever constructing a `LiveMap`; the others operate
  only inside that scope.

### `Custodian.Mock`

`MockHandle` for the lifecycle side (an opaque tag; linearity alone
prevents double-teardown, the mock adds nothing there) and `MockSys` for
the map side — a genuine in-process `Map fd (name, shape)`-style table, so
`readMap`/`writeMap`/`deleteMap`/`mapKeys` exercise real branching and
`Storable` round-tripping without a kernel.

### `Custodian.Raw` (live package) — the FFI transcript

One `foreign import capi` per `libbpf`/`bpf.h` entry point, `c_`-prefixed,
unrestricted: `c_bpf_object__open/__load/__close`,
`c_bpf_object__next_program`, `c_bpf_program__attach`,
`c_bpf_link__destroy`, `c_bpf_object__find_map_by_name`, `c_bpf_map__fd`,
`c_bpf_map_get_info_by_fd`, `c_bpf_map_lookup_elem`,
`c_bpf_map_update_elem`, `c_bpf_map_delete_elem`,
`c_bpf_map_get_next_key`. No linear types, no `CustodianError`, no
lifecycle index — auditable line-by-line against the C headers.

### `Custodian.Raw.MapInfo` (live package)

`hsc2hs`-derived layout of `struct bpf_map_info` against `<linux/bpf.h>` —
`sizeOfMapInfo` and `peekMapInfo` compute/read every offset from the header
at build time, never hand-transcribed.

### `Custodian.Live` (live package) — the real backend

- `LiveObj` (`Ptr Bpf_object`), `LiveLink` (`[Ptr Bpf_link]` — a bundle,
  because attach binds every program in the object into one linear
  resource), `LiveSys` (a phantom naming the real element-syscall
  instance).
- `ObjectLifecycle LiveObj`, `AttachDetach LiveObj LiveLink`: `attachImpl`
  walks `c_bpf_object__next_program` to exhaustion, attaching each and
  collecting links; on any single failure, everything attached so far is
  rolled back (detached) before the failure is returned, with the object
  still handed back so the caller can close it. `detachImpl` destroys every
  link newest-first.
- `MapLookup LiveObj`: resolves a map by name to its fd, then reads its
  kernel-declared shape via `c_bpf_map_get_info_by_fd` decoded through
  `Custodian.Raw.MapInfo`'s offsets — the canonical source, not a userspace
  guess.
- `MapSyscalls LiveSys`: the four element operations over real
  `bpf_map_*_elem` syscalls, errno-preserving, `ENOENT` folded into the
  result.

### Tests

- **`test/Spec.hs`** — 24 Hedgehog properties/units against `Custodian.Mock`:
  map-shape validation, the `withMap` gate, map element semantics, errno
  preservation, array maps, bracket-wrapper exactly-once/no-leak behavior
  (including the multi-program attach/detach property), and the manual
  linear lifecycle.
- **`negative-tests/cases/*.hs` + `negative-tests/run.sh`** — one positive
  control (must compile) and five cases that must be rejected by the
  compiler: double teardown, scope escape, a live map escaping its scope, a
  `Word32`-violating array-map key, array-map deletion.
- **`live/live-tests/LiveSpec.hs`** — end-to-end, against real `libbpf`;
  skips gracefully without `CAP_BPF`/`CAP_PERFMON` and a compiled BPF
  object file, rather than asserting on a real load it can't perform.
- **`live/examples/SyscallCounter.hs`** — the tracepoint-based "hello
  world," loading, attaching, and reading aggregated counts from a hash map
  against the real kernel.

### Tooling gates

`-Wall -Werror`; `hlint` with a curated rule set (partial-function bans
kept strict; stylistic hints like "avoid lambda"/"use `>=>`" deliberately
ignored where they'd obscure the linear/`Control.do` sequencing);
`fourmolu` formatting, checked clean; `weeder` (dead-code) has a real
config (`weeder.toml`, rooted at the four public modules plus `Main.main`)
and a CI step, run non-blocking (`continue-on-error: true` — a finding is
visible in the log without failing the build, since two of its current
findings are accepted, intentional public surface, not oversights).
`cabal-docspec` is **not currently wired anywhere** in the repository —
earlier design-doc drafts described it as a planned gate, but no CI step,
config, or script actually invokes it. Real test-suite names, wired into CI
as such: `cabal test verified-test` (the 24-test suite),
`bash negative-tests/run.sh` (the 5 compile-fail cases),
`cabal test live-spec` (the live end-to-end suite).

## Repository layout

```
src/Custodian/Core.hs          phantom-typed + linear lifecycle; bracket-scoped wrappers
src/Custodian/Errors.hs        closed CustodianError ADT; MapMismatch
src/Custodian/Map.hs           checkMapShape, ValidKey, Deletable, withMap, element ops
src/Custodian/Mock.hs          in-process instantiation of every capability class
test/Spec.hs                   24 Hedgehog properties/units
negative-tests/                cases/ that must fail to compile + run.sh harness
live/src/Custodian/Raw.hs              unrestricted libbpf FFI transcript
live/src/Custodian/Raw/MapInfo.hsc     hsc2hs header-derived struct bpf_map_info offsets
live/src/Custodian/Live.hs             real backend: capability instances over Raw
live/examples/SyscallCounter.hs        the tracepoint "hello world" example
live/live-tests/LiveSpec.hs            end-to-end tests (run on a privileged kernel)
hlint.yaml                     lint config, curated ignore list + partial-function bans
fourmolu.yaml                  formatting config
weeder.toml                    dead-code gate config
.github/workflows/ci.yml       all gates, wired to the real test-suite names above
verify.sh                      runs all of the above locally
```

## CI gate summary

| Gate | Enforcement |
|---|---|
| `-Wall -Werror`, partial-function bans | Compiler-level |
| `hlint` (curated rule set) | CI, gating |
| `weeder` | CI, non-blocking (`continue-on-error`) — real config, two accepted findings |
| `fourmolu` | CI, gating |
| Should-not-compile linearity/scope-escape/key/deletion tests | CI, gating (`negative-tests/run.sh`) |
| `hsc2hs`-derived `Storable` instances only | Structural — no hand-transcribed struct offsets exist in the tree |
| Single `CustodianError` classification | Structural (grep-checkable — one ADT, extended by constructor) |
| `cabal-docspec` | **Not wired** — described in earlier drafts as planned, not actually present in CI, config, or scripts |
| Privileged live-path verification | Local (`setcap`/`sudo`), not yet continuous/automated in CI |

## Release policy

Custodian does not ship to Hackage until it reaches competitive functional
parity with `cilium/ebpf` (Go) and `aya` (Rust) — see the appendix below for
exactly what that requires and its estimated size. The live Hackage
name-availability check (`cabal update && cabal info custodian`) is
deliberately deferred to immediately before the actual upload, since a
result today would be stale by the time parity is reached.

Explicitly out of scope for any phase of this work: production hardening
that can only come from real-world usage and adoption (kernel-version-
matrix battle-testing, edge cases surfaced by fleet-scale deployment). That
is a genuine, time-and-adoption-bound cost this document cannot schedule
away, and is tracked as an open risk (vision doc §6), not a deliverable.

---

## Appendix — Work Remaining Before Release (LOC-estimated)

**Purpose.** The delivered system (above) is functionally complete for a
single fixed kernel, tracepoint/kprobe programs, and hash/array maps. This
appendix itemizes what's missing for parity with `cilium/ebpf` and `aya`,
with LOC estimated by scaling against the delivered modules' own sizes.

**Caveat on the estimates.** LOC is a weak proxy for effort on a
linear-types codebase — the gating difficulty is getting the *types* right
(proven by a negative-compile test), not raw line volume. Treat the ranges
below as scale-of-effort indicators, not a committed budget.

| # | Item | Library code (LOC) | Tests / negative-cases (LOC) | Fixtures / examples (LOC) | Design notes |
|---|---|---|---|---|---|
| A.1 | **CO-RE / BTF support** | 150–350 | 150–250 | 50–100 (C fixture using `BPF_CORE_READ` with a deliberately shifted struct layout) | Smaller than the other items: since Custodian wraps *real* `libbpf` (unlike `aya`'s pure-Rust reimplementation), the actual BTF relocation work happens inside `bpf_object__load` already. The work here is exposing `bpf_object__open_file`'s BTF-path options, adding a `CustodianError` variant for BTF-load failure, and a new positive/negative test pair proving a CO-RE-relocated field access actually works across the shifted-layout fixture. |
| A.2 | **XDP + TC attach targets** | 300–450 | 250–400 | 50–100 (XDP hello-world) | New `AttachTarget` sum type (interface index + flags); new FFI (`bpf_program__attach_xdp`, `bpf_tc_hook_create`/`attach`, ~10–15 new imports); generalizing `AttachDetach` to cover non-tracepoint targets without breaking the existing tracepoint/kprobe path or its negative tests. |
| A.3 | **Perf-event / ring-buffer streaming maps** | 400–650 | 300–450 | 80–150 (streaming consumer example) | The largest single item. Not just a new map kind — a new *lifecycle*: a polling-loop resource (`ring_buffer__new`/`poll`) needing the same linear-scoping discipline as `BpfObject`, plus a callback-escape story matching `Custodian.Map`'s existing scope-brand guarantee. Comparable in design weight to the entirety of `Custodian.Map` today. |
| A.4 | **Broader map-type coverage** (LRU hash, per-CPU, stack/queue) — optional, lowest priority | 100–200 per kind | 80–150 per kind | — | Incremental once A.1–A.3's shape-check machinery generalizes; mostly new `MapType`/`SMapType` cases. Not required for parity with the two named competitors' *core* feature set — include only if a specific need surfaces. |
| A.5 | **Benchmarks vs. `libbpf`/`aya`** | 150–300 (Haskell `criterion` harness) | — | requires equivalent C/Rust harnesses, outside this repo's LOC | Needed to substantiate the "compile-time safety costs nothing extra" claim with a number, not just an assertion. |
| A.6 | **Privileged CI runner + kernel-version test matrix** | ~100–200 (workflow YAML + provisioning scripts — not comparable LOC to the rest of this table) | — | — | Infra effort, not code volume. This is genuinely controllable (unlike production-hardening-via-usage) — it's where a large share of real calendar time will go, even though it barely moves the LOC total. |

**Totals.** A.1–A.3 (the load-bearing parity items, excluding the optional
A.4 and the non-library A.5/A.6): **~850–1,450 new lines of library code,
~700–1,100 new lines of tests.** Landing library code at roughly
**2,150–2,750 lines** total (1,291 delivered plus this range) — the
codebase roughly doubles. Including A.4 at full breadth (3 additional map
kinds) adds a further 300–600 lines; A.5/A.6 add infra/benchmark code
outside the "library" LOC count but represent real engineering time.

**Sequencing recommendation.** A.1 (CO-RE) and A.3 (streaming maps) are the
two gaps that most directly block real-world adoption and should be
prioritized over A.2 (XDP/TC) and A.4 (broader map types), which round out
breadth rather than closing an adoption blocker.

**Definition of done for this appendix.** A.1–A.3 merged, tested to the
same rigor bar as the delivered system (Hedgehog properties + negative
compile tests where applicable), and documented — at which point the
release policy above allows the Hackage name-check and upload to proceed.
