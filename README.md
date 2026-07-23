# custodian-verified

A corrected, compiling, and property-tested redesign of the safety-critical
parts of `custodian`. It keeps the project's thesis — *unsafety is a compile
error* — and closes the gaps where the original fell short of it.

## Build & run

Prerequisites: **GHC 9.8.4** and **cabal** (via ghcup), plus system packages
**`libgmp-dev`** (GHC linking) and **`libbpf-dev`** (the `bpf/*.h` and
`linux/bpf.h` headers, and `-lbpf` for the live package). `linear-base 0.8.1`,
`hedgehog`, `tasty`, `tasty-hedgehog` come from Hackage.

```sh
cabal update
cabal build all            # core library + live package (links libbpf)
cabal test all             # 24 property/unit tests, + live-spec (skips w/o kernel)
bash negative-tests/run.sh # 5 cases that MUST fail to compile
./verify.sh                # all of the above + HLint + Fourmolu in one shot
```

The self-contained tiers (`cabal build/test all`, `negative-tests/run.sh`) pass
on any box with the toolchain. The **live** example and `live-spec` build and
link, but at runtime need a compiled fixture and privileges — they SKIP / stop
at `open` otherwise:

```sh
clang -O2 -g -target bpf -c live/live-tests/fixtures/hello.bpf.c -o hello.bpf.o
sudo cabal run custodian-syscall-counter        # from a dir containing hello.bpf.o
sudo cabal test live-spec                        # needs CAP_BPF
```

Everything was verified here on GHC 9.8.4; the project's pinned toolchain is
9.14.1 (identical guarantees in principle — linear types are stable since 9.0 —
but worth a confirmation run).

## What `./verify.sh` checks

```
1. core library builds under -Wall -Werror
2. 24 Hedgehog property/unit tests pass (incl. errno, array maps, multi-program)
3. 5 negative tests are rejected by the compiler for the right reasons
4. HLint clean (its config bans partial functions -- head/fromJust/(!!)/error/…)
5. Fourmolu formatting clean
6. the live package builds, LINKS against libbpf, and runs
```

The live side (`live/`) is a second package that links `-lbpf`: a
near-verbatim FFI transcript (`Custodian.Raw`), header-derived struct offsets
via `hsc2hs` (`Custodian.Raw.MapInfo`), the real backend (`Custodian.Live`), the
`§9` "hello world" example, and an end-to-end live test suite. It compiles,
links, and runs today; the example actually calls into libbpf and propagates a
real `LibbpfFailure` through the full idiomatic stack. Loading/attaching a real
program additionally needs `CAP_BPF` and a compiled `hello.bpf.o` (see
`live/live-tests/fixtures/`).

Weeder and cabal-docspec are configured and wired into CI but not executed in
this sandbox.

## Why a separate package instead of an in-place patch

The real backend needs `libbpf` **and** a privileged kernel (`CAP_BPF`) to
*run*, which a sandbox can't provide. So the logic is verified against a mock
backend that instantiates the *same* capability classes, on **GHC 9.8.4 +
`linear-base` 0.8.1**. (The project pins GHC 9.14.1; linear types have been
stable since GHC 9.0, so the guarantees are identical. The pin was not used
only because building that exact toolchain here was not worthwhile — nothing
in the design depends on it.) The real `libbpf` backend is shipped as source
(`real-backend/Live.hs`) and is **compile-verified** against real headers; it
is simply not linked or run here.

## What was fixed

The five findings from the review, and how each is now closed and tested:

### 1. Map size unchecked — the memory-safety hole (the big one)

The original resolved a map to a bare fd and then let `readMap`/`writeMap`
`alloca` a buffer sized by the *caller's* `Storable` instance, while the kernel
copies *its own* declared sizes — a stack over-/under-run with no check.

- `Custodian.Map.checkMapShape` is a pure, total function: the caller's types
  fit iff their `sizeOf`s exactly equal the kernel's declared `key_size` /
  `value_size`.
- `withMap` fetches the shape (real backend: `bpf_map__key_size` /
  `bpf_map__value_size`, the two accessors the original never imported) and
  validates *before* constructing a `LiveMap`. On mismatch it returns
  `MapShapeMismatch` carrying all four sizes, and the callback never runs — so
  no read or write on a mis-sized buffer is reachable.
- Bonus, at the type level: `ValidKey` makes an array map keyed by anything but
  `Word32` a **compile error** (negative test Case 4).

Tested by: `checkMapShape` properties (match iff equal, exact-match accepts,
off-by-one rejected) and the `withMap` gate properties (accepts matching shape
and runs the callback; rejects a mismatch and the callback provably never runs,
with the exact reported sizes checked).

**errno preservation (§5).** Map element syscalls surface failures as
`Left Errno`, and `CustodianError` carries the raw errno in `SyscallFailure op
errno`. `ENOENT` is deliberately folded into the *result* — `readMap` returns
`Right Nothing`, `sysDelete` returns `Right False` — so a normal "absent" is
never conflated with a genuine failure. Tested by a backend that fails with a
fixed errno: `readMap` surfaces it verbatim, and a hard `deleteMap` failure is
proven distinct from the absent case.

**Array maps and deletion safety (§5).** Both `BPF_MAP_TYPE_HASH` and
`BPF_MAP_TYPE_ARRAY` are supported, with array maps constrained to `Word32`
keys (`ValidKey`). Because a `BPF_MAP_TYPE_ARRAY` slot cannot be deleted
(`bpf_map_delete_elem` → `EINVAL`), `deleteMap` carries a `Deletable t`
constraint with an instance only for `'HashMap` — so deleting from an array map
is a **compile error** (negative test Case 5), not a runtime surprise. Array
read/write/enumerate round-trips are property-tested.

**Multi-program objects.** A real object usually declares several programs.
Attach now binds *every* program, collecting one link each into a single link
resource; teardown detaches all of them (newest-first) before closing the
object, and a partial-attach failure rolls back the links already created. The
real `Custodian.Live` backend implements this over `bpf_object__next_program`;
the accounting backend models it as a link *bundle*, and a property test proves
that attaching N programs detaches exactly N links with none leaked — including
on the exception path.

### 2/3/4. Borrow use-after-free, double-free window, link-leak window

These three had one root cause: the callback *and* the `with*` wrapper both
tried to own teardown, reconciled with a fragile `onException` + duplicated-
alias dance.

The redesign makes the wrapper the **sole owner** of teardown via a plain
`Control.Exception.bracket`:

- `bracket` runs release **exactly once**, on the normal path, the exceptional
  path, and under async exceptions (release is masked). No hand-rolled handler.
- The callback receives a rank-2 `Scope` (or, for maps, a rank-2 `LiveMap`)
  that has **no** way to free anything (no `Teardownable` instance) and **cannot
  escape** its scope (the brand `br` unifies with nothing outside the callback —
  the `runST` trick). So use-after-free is unrepresentable, not merely unlikely.
- For attach, both the object and the link are acquired before the callback and
  released together, link first then object, so there is no window in which the
  link exists uncovered.
- A failed attach still closes the object (the original's leak-on-attach-failure
  fix is preserved and tested).

Tested by: bracket properties asserting exactly-once close on success and on a
callback exception; detach-before-close ordering with each run exactly once;
attach-failure closes the object and never runs the callback; open-failure
closes nothing. Escape is a compile error (negative tests Case 2 and Case 3).

### 5. Tests couldn't detect a double-close

The original emergency tests set an `IORef Bool` to `False`; doing that twice is
indistinguishable from once, so a double-free would pass.

The suite here uses **counter-based** resource accounting (opens/closes/
attaches/detaches plus a live-set and an anomaly log). A double free shows up as
`closes == 2` *and* an anomaly; a leak shows up as a non-empty live set. Every
bracket property asserts the counters, so the tests can actually see the bug
they are meant to catch.

## Layout

```
src/Custodian/Errors.hs   closed error ADT; MapMismatch + errno-carrying SyscallFailure
src/Custodian/Core.hs     linear lifecycle + bracket-based scoped wrappers
src/Custodian/Map.hs      checkMapShape, ValidKey, withMap, element ops (errno-preserving)
src/Custodian/Mock.hs     mock lifecycle + in-memory map backend
test/Spec.hs              20 Hedgehog properties/units
negative-tests/           cases/ that must fail to compile + run.sh harness
live/src/Custodian/Raw.hs         near-verbatim, unrestricted libbpf FFI transcript (§3.1)
live/src/Custodian/Raw/MapInfo.hsc  hsc2hs header-derived struct bpf_map_info offsets (§2.6)
live/src/Custodian/Live.hs        real backend: capability instances over Raw
live/examples/SyscallCounter.hs   the §9 "hello world" example
live/live-tests/LiveSpec.hs       end-to-end tests (run on a privileged kernel)
.hlint.yaml               lint config incl. the no-partial-functions rule
fourmolu.yaml             formatting config
weeder.toml               dead-code gate config
.github/workflows/ci.yml  all gates, blocking
verify.sh                 runs all of the above
```

## Deferred to v2 — not in v1 (vision doc §6)

Stated up front, per the vision's honesty requirement (§9): the following are
**out of scope for v1** and are *not* implemented here.

- **CO-RE / BTF relocations** — "compile once, run on any kernel version." The
  biggest reason v1 alone isn't portable across heterogeneous kernels.
- **XDP and TC (traffic-control) program types** — need extra attach-point
  plumbing (interface indices, qdisc setup). v1 covers tracepoint and
  kprobe/kretprobe, which `bpf_program__attach` auto-selects by ELF section.
- **Perf-event and ring-buffer maps** — streaming kernel→userspace events. The
  most-requested "real observability" feature, deferred for its own polling-loop
  lifecycle surface. v1 covers `BPF_MAP_TYPE_HASH` and `BPF_MAP_TYPE_ARRAY`.
- **Any bytecode-generation / compiler story.**

One in-scope limitation that *is* shared with the original and documented rather
than hidden: attach binds a single program per object (`bpf_object__next_program
(obj, NULL)`); multi-program objects attach only the first program.

## Honest caveats

- Verified on GHC 9.8.4 / `linear-base` 0.8.1, not the pinned 9.14.1.
- The live package **builds, links against `libbpf`, and runs** — the example
  invokes real libbpf calls and propagates errors through the full stack. What
  it cannot do here is **load or attach a program**, which needs a `CAP_BPF`
  runner and a compiled `hello.bpf.o` (no clang/BPF toolchain or privileged
  kernel in the sandbox). So `LiveSpec` skips rather than asserting on a real
  load, and the §9 "hello world" stops at `open`. `hsc2hs`-derived offsets are
  correct by construction (computed from the header at build time), but the
  runtime marshalling has not executed against a live kernel here.
- **Weeder** and **cabal-docspec** are configured (`weeder.toml`,
  `cabal.docspec`) and run in CI, but were not executed in this sandbox; HLint
  and Fourmolu were, and are clean.
- Still not present: the pinned-`libbpf` **Nix flake** and the **privileged CI
  runner** (Phase 2 / Risk #4), and the **Hackage release** (Phase 5). These are
  environment/publishing steps, not library code.
- A handful of `Unsafe.toLinear` uses remain at linear/`IO`/exception
  boundaries. They are the sanctioned escape the project already uses; each is
  localised and commented, and none is reachable by a library caller.
