# Custodian: A Haskell Binding for eBPF, Built to Be Read Like a Proof

**Status:** Ready for implementation handoff.
**Package name:** `custodian` — no conflicting Haskell package found in a search pass; re-verify directly against `hackage.haskell.org/package/custodian` immediately before the first upload, since this wasn't reachable for a live check from this environment.
**Scope target:** ≤ 2000 LOC (excluding tests)
**Compiler baseline:** GHC 9.14.x specifically — the first designated LTS release, with a minimum two-year bugfix-support window, deliberately *not* an open-ended "9.14 or later." `LinearTypes` has been stable since GHC 9.0. A `10.0` branch is already in development upstream; adopting it is an explicit, evaluated decision for a later phase, not an automatic consequence of this baseline, since committing to an unreleased major version sight-unseen would undercut the same compiler-stability reasoning that motivates pinning to the LTS line in the first place.
**Standard:** every design decision below is a hard constraint, not a preference. A contribution that violates one of these without an explicit, documented exception is not mergeable.

**Amendment (post-handoff):** §3.5 added to resolve an ambiguity the original handoff left open — whether `LiveMap` handles carry the same linear discipline as `BpfObject`. Resolved: no; see §3.5 for the design and rationale. §2.2, §4, §5, §7, and §10 updated to cross-reference it.

---

## 1. Problem Statement

Haskell has no binding to `libbpf` — the reference C library used by every other serious eBPF ecosystem (Go's `cilium/ebpf`, Rust's `aya`/`libbpf-rs`) to load, verify-interact-with, attach, and manage eBPF programs and maps. This was confirmed directly: the only Haskell projects touching eBPF operate at the bytecode-assembly layer (`ebpf-tools`, `hBPF`), both unmaintained, neither wrapping `libbpf`'s program/map lifecycle. The gap is real, current, and uncontested.

Custodian exists to close it — but closing it sloppily would be worse than not closing it at all. This is a library that will sit underneath other people's production tooling, marshaling raw pointers across an unsafe FFI boundary into a kernel subsystem that can panic or deny work outright if handled incorrectly. Correctness here is not a nice-to-have; it is the entire value proposition. A binding that leaks kernel resources, silently swallows errors, double-frees a handle, or admits invalid state transitions is strictly worse than no binding, because it will be trusted.

## 2. Design Philosophy — Hard Constraints

These are not aspirations. Every one of them is a gate a pull request must pass — and, per §2.6, most of them are gates a *machine* checks, not a reviewer.

### 2.1 Code must read like a proof, not a transcript of the C API

- **Totality first.** Every function is total unless partiality is fundamentally unavoidable (e.g. an FFI call that can fail for reasons outside our control). Where partiality is unavoidable, it is made explicit in the type — `Either CustodianError a`, never a silently-swallowed `Maybe`, never an unchecked `error` call, never a partial pattern match outside of a proof-carrying context (see §2.4). This is enforced with a total prelude (`Relude`, already precedented in-house in `analytics-core`) plus `-Wall -Werror`, and partial functions (`head`, `fromJust`, `(!!)`) are banned at the compiler level via `{-# WARNING #-}`/`-Wcompat`-style pragmas turned into hard errors, not left to code-review convention.
- **Equational, not imperative, where the domain allows it.** Pure computation (struct marshaling logic, error-code classification, map-key encoding) is written as pure functions with no `IO`, so it can be reasoned about algebraically and tested via equational properties, not just example-based unit tests. The `IO`-laden shell (the actual FFI calls) is kept as thin as possible and pushed to the edges — the classic "functional core, imperative shell."
- **Haddock documentation states pre-conditions, post-conditions, and invariants as if they were lemma statements**, not prose descriptions. Example of the required standard:

  ```haskell
  -- | Load a BPF object file into the kernel.
  --
  -- Pre-condition:  the 'BpfObject' must be in the 'Opened' state (see 'openObject').
  -- Post-condition: on success, the returned 'BpfObject' is in the 'Loaded' state, and
  --                 every map declared in the ELF object has a corresponding live
  --                 kernel-side map descriptor accessible via 'mapFd'.
  -- Invariant:       this function is idempotent-safe under exception: if the kernel
  --                 rejects any single program in the object, no partial set of maps
  --                 or programs is left live — the whole object is torn down as a unit.
  loadObject :: BpfObject 'Opened %1 -> IO (Either CustodianError (BpfObject 'Loaded))
  ```

  Note this is a function in the idiomatic `Custodian` layer, not `Custodian.Raw` — the linear arrow and the single `CustodianError` hierarchy are both idiomatic-layer properties (§2.5, §3.1), never present on the near-verbatim FFI declarations underneath.

  A function whose Haddock comment cannot state a post-condition is a function that hasn't been designed yet.

- **Illegal states must be unrepresentable.** Resource lifecycle (open → loaded → attached → torn down) is encoded in the type via a phantom-typed state index (see §3.2), so that calling `attachObject` on an object that was never loaded is a **compile error**, not a runtime exception. Layered on top of that, linear types (§2.5) make it a compile error to skip teardown entirely, or to use a handle twice. Between the two, this is the single most important architectural decision in this document — see §3.2 and §3.3 for the full mechanism.
- **Property-based tests are proof sketches, not example fuzzing.** Every law claimed in a Haddock comment (e.g. "teardown always fully releases kernel resources regardless of which stage failed") must have a corresponding Hedgehog property that attempts to falsify it, not merely a happy-path unit test. §2.6 makes the *presence* of such a property, for every claimed law, a release-blocking checklist item, not just a convention.

### 2.2 SOLID, translated honestly for Haskell — not cargo-culted from OOP

SOLID was written for class hierarchies and mutable objects. Applying it to Haskell verbatim is a category error. What follows is what each principle *actually* demands once translated into a language with algebraic data types, typeclasses, and no inheritance. Where the OOP-native reading doesn't apply, that is stated explicitly rather than papered over.

- **Single Responsibility → one type, one concept; one function, one operation.** A type must represent exactly one concept — no "kitchen sink" records mixing configuration, live kernel state, and diagnostic metadata in one constructor. A smart constructor is the single place responsible for an invariant's validity; nothing downstream re-checks it. Concretely: `MapSpec` (a description) and `LiveMap k v` (a validated, kernel-backed handle) are different types, never conflated, even though a naive port of the C API would represent both as `struct bpf_map *`. `LiveMap`'s own safety discipline — deliberately *not* linear typing — is specified in §3.5.
- **Open/Closed → typeclasses for extension, GADTs/closed sums for exhaustiveness.** New program types or map types are added by extending a typeclass instance set (open for extension), while the core state-machine transitions operate over a closed, exhaustively-matched sum type for lifecycle states (closed for modification) — GHC's exhaustiveness checker is strictly stronger here than OOP's virtual dispatch, because adding a new lifecycle state forces a compile error at every non-exhaustive match site, rather than a silent runtime fallback.
- **Liskov Substitution → lawful instances, not behavioral subtyping.** There is no subtyping in Haskell, so this becomes: any typeclass instance we write must satisfy the *laws* implied by that typeclass, and any two things claimed to be substitutable (e.g. two different map-type witnesses satisfying the same `IsMapType` class) must be provably interchangeable with respect to those laws — checked by property tests, not asserted in a comment.
- **Interface Segregation → narrow, single-capability typeclasses.** No monolithic `MonadEbpf` god-class. Instead, orthogonal capability classes (illustrative, not final): a class for object lifecycle operations, a separate class for map read/write, a separate class for attach/detach — so a consumer (or a test mock) can implement only the capability it needs, and the type signature of every function states exactly which capability it requires, nothing more. `weeder` (§2.6) is the structural check on this: if a capability class grows an export nothing in-tree actually calls, that is a signal the segregation has drifted, and CI fails on it rather than waiting for a reviewer to notice.
- **Dependency Inversion → the `Custodian` layer depends on abstractions, `Raw` is one instantiation of them.** This is the most load-bearing translation. The idiomatic layer is written against typeclass-abstracted capabilities, not directly against `libbpf` FFI calls. The `Raw` FFI layer is *a* concrete instance of those capabilities — the only one that ships in v1, but structurally replaceable (e.g. by a pure in-memory mock for testing lifecycle logic without a live kernel, root privileges, or CI infrastructure with `CAP_BPF`). Concretely: business logic that says "load, then attach, then read the map" is written once, polymorphically, over the capability typeclasses, and is exercised in tests against a mock instance and in production against the real `Raw` instance — the same source code, not a parallel test-only copy.

### 2.3 DRY — one source of truth per fact, enforced structurally, not by discipline

- **One `Storable` instance per C struct**, reused by every function that touches that struct — never re-derive marshaling logic per call site. Per §2.6, these instances are *derived* from the real `libbpf` headers via `hsc2hs` (GHC's bundled tool, preferred), not hand-transcribed, so the single source of truth is the C header itself, not a Haskell author's reading of it.
- **One error-classification table** mapping `errno`/`libbpf` return codes to `CustodianError` constructors, consulted by every FFI wrapper — never a second ad-hoc `if errno == ...` scattered through call sites.
- **One generic load/attach/teardown skeleton**, parameterized over a program-type witness, instantiated for `Tracepoint` and `Kprobe` — not two hand-copied near-duplicate functions. If a third program type is added later, it must slot into the same skeleton; if it structurally cannot, that is a signal the abstraction was wrong and must be revisited, not worked around with a copy-paste.

### 2.4 Where partiality is genuinely unavoidable, it is quarantined and documented

FFI calls into a C library and the kernel are inherently partial from Haskell's perspective — the kernel can always say no. This is not something totality can eliminate; it can only be *quarantined*. Every FFI-adjacent function that can fail:

1. Returns `Either CustodianError a` or throws a specifically-typed exception from a closed, documented exception hierarchy — never `SomeException`, never a bare `error` call, never an unchecked `fromJust`/`head`/partial pattern match leaking past the FFI boundary.
2. Documents, in the Haddock lemma-style block, exactly which failure modes are possible and what state the system is guaranteed to be in after each one (see the `loadObject` example in §2.1 — the "no partial set of maps left live" guarantee is exactly this kind of documented failure-mode contract).

### 2.5 Linear types — resource *consumption*, not just resource *sequencing*

The phantom-typed state machine in §3.2 makes out-of-order *sequencing* a compile error: you cannot call `attachObject` on something that was never loaded. It does not, by itself, stop you from calling `teardown` twice on the same handle, forgetting to call `teardown` at all, or passing the same `BpfObject 'Loaded` to two different functions that each believe they have exclusive access to the underlying kernel descriptor. Ordinary Haskell values are unrestricted — nothing stops a handle from being duplicated, discarded, or reused after it has logically been consumed.

Linear types close that gap, and they are a hard constraint for this project, not an experiment:

- **Handle-carrying functions in `Custodian` are linear in the handle argument.** `BpfObject s %1 -> ...` means the caller must consume the handle exactly once — passing it along to the next lifecycle function, or into `teardown`. GHC's linearity checker rejects, at compile time, both discarding a live handle (a resource leak) and using it twice (a double-free or a data race against kernel state the type system otherwise has no way to know is shared).
- **`Custodian.Raw` remains unrestricted.** Linearity is layered on at the idiomatic-layer boundary (§3.1), consistent with §2.2's Dependency Inversion translation — the `Raw` FFI layer stays a near-verbatim, auditable transcript of the C API, and the linear discipline is a property of the abstraction built on top of it, not a requirement smuggled into the FFI declarations themselves.
- **`Ur` (Unrestricted) marks the boundary explicitly.** Values that come *out* of a linear function but are ordinary, freely-duplicable Haskell values (e.g. a count read from a map, a `Bool` success flag) are wrapped in `Ur` from `linear-base`, so the type signature itself states which parts of a result are resource-linked and which are plain data — this is the linear-types analogue of §2.1's "the Haddock comment states a post-condition": here, the *type* states which values are resources.
- **This is additive to, not a replacement for, the phantom-typed lifecycle index.** Phantom types answer "is this operation valid in this state." Linearity answers "has this specific handle value been consumed exactly once." A design that used only one of the two would leave a real gap: phantom types alone permit handle aliasing and leaks; linearity alone has no notion of *which* operations are legal in *which* state. Custodian uses both because the failure modes they close are different and both are live risks in a kernel-resource binding.
- **`linear-base` is the dependency, not a hand-rolled linear-IO shim.** It is already used in-house in `analytics-core`, so there is no discovery cost. `bracket`-style scoped acquisition (§3.4) mixes ordinary unrestricted `IO` with linear-typed arguments rather than routing everything through `linear-base`'s own linear-`IO` functor — confirmed workable by direct compiler testing (Risk 1b/1d, §8), with one caveat: multi-step sequences over a single linear value (§3.2's `Teardownable 'Attached` instance) must be pushed into a single unrestricted `Custodian.Raw` call rather than chained with Prelude `do`-notation, which doesn't typecheck there.
- **This is named explicitly as a risk, not just a feature.** See §8, Risk #1 — linear types are the least-familiar tool in this document to most Haskell contributors, and the ergonomics of "the compiler rejected my program and I don't yet know why" are worse for linearity errors than for ordinary type errors. Phase 1 (§10) treats getting this ergonomic, not just correct, as a first-class deliverable.

### 2.6 Tooling as structural enforcement, not reviewer discipline

Every constraint above is only as real as its weakest enforcement mechanism. The following are CI gates — a pull request that fails any of them does not merge, full stop, with no "we'll clean it up later":

- **`-Wall -Werror`** over a total prelude (§2.1), with partial functions banned at the compiler level.
- **`hlint`**, gating on lint warnings, not just displaying them.
- **`weeder`**, gating on unused exports — the structural check on Interface Segregation described in §2.2.
- **Ormolu (or Fourmolu) formatting**, checked, not just applied locally — the same practice `linear-base`'s own changelog documents adopting ("Format the codebase with ormolu and add an ormolu check to CI"), a direct precedent from a library in the same problem space.
- **`cabal-docspec`**, so every Haddock code example is an executable test. This is the direct enforcement mechanism for §2.1's "reads like a proof" standard applied to documentation: an example that doesn't compile and run correctly is not documentation, it's a claim.
- **Haddock coverage as a release gate**, scoped precisely: every *public* function must have a Haddock comment that states a post-condition, checked by a coverage tool plus a lightweight lint for the pre-condition/post-condition/invariant structure shown in §2.1 — not literal 100% coverage of every internal identifier, which would reward comment-shaped noise over the actual lemma-statement standard this document demands.
- **`hsc2hs`-derived struct offsets are near-mandatory, not optional; prefer `hsc2hs` over `c2hs` as the primary tool.** Hand-transcribed `Storable` instances against `libbpf`'s C structs are the single most dangerous source of silent failure in this codebase: a miscounted offset does not fail to compile and does not throw — it corrupts memory across the FFI boundary into a kernel subsystem. This is DRY (§2.3) applied to the highest-risk fact in the project, and it is treated as a Phase 2 merge-blocking requirement (§10), promoted into Risk #1a in §8. `hsc2hs` ships as part of GHC itself, so it's always version-matched to whichever GHC is pinned (see the compiler baseline note at the top of this document) with no separate compatibility risk; `c2hs` is a separate, GPL-licensed tool with a noticeably slower release cadence — usable as a secondary/optional tool for awkward macro or static-inline-function bindings, but `hsc2hs` should be the default for the `Storable` instances themselves.
- **A Nix flake pinning the exact `libbpf` version**, giving every contributor a reproducible build without hunting for the right system package, and directly closing Risk #3 (ABI drift, §8). This lands when `Custodian.Raw` starts touching real headers (Phase 2), not before — introducing it during Phase 1's mock-only type design would add infrastructure weight to a phase whose entire point is to move fast without a live kernel dependency.
- **A Hedgehog property for every law claimed in a Haddock comment**, checked by a lightweight in-house lint (grep-and-flag is an acceptable v1 implementation) that a "Pre-condition/Post-condition/Invariant" block without a corresponding falsification-oriented property test fails CI. This is the one enforcement mechanism with no off-the-shelf tool; §9 already required it in prose, this makes it a checked gate rather than an aspiration.

## 3. Architecture

### 3.1 Two-layer structure

- **`Custodian.Raw`** — near-verbatim FFI declarations against `libbpf`'s C API (`bpf_object__open`, `bpf_object__load`, `bpf_program__attach`, `bpf_object__close`, `bpf_link__destroy`, `bpf_map__fd`, `bpf_map_lookup_elem`, `bpf_map_update_elem`, etc.), plus `Storable` instances for the C structs involved, derived from the real headers per §2.3/§2.6. Intentionally unopinionated and near-1:1 with the C headers, so it is trivially auditable against `libbpf`'s own documentation by anyone who knows the C API, independent of anything Haskell-specific layered on top. Unrestricted (non-linear) throughout, per §2.5.
- **`Custodian`** (top-level, idiomatic layer) — proper ADTs instead of raw ints/flags, linear-typed handles (§2.5, §3.3) so kernel resources cannot leak or be double-consumed, `bracket`-based scoped acquisition (§3.4) so they cannot leak across exceptions either, and the phantom-typed lifecycle state machine described next.

### 3.2 The lifecycle state machine — sequencing correctness

An eBPF object moves through a strict lifecycle: **opened → loaded → attached → torn down**, where "torn down" is a terminal *effect* (the kernel resource is released) rather than a further phantom-typed state to transition into — `LifecycleState` below has three constructors, not four, precisely because nothing can be done with a value after teardown, so there is nothing for a fourth state to usefully index (§3.3 explains this choice in full). In the raw C API, calling an operation out of order is a runtime error discovered only when `libbpf` returns a negative errno. Custodian instead encodes lifecycle state as a phantom type parameter, so that out-of-order operations are rejected **at compile time**:

```haskell
data LifecycleState = Opened | Loaded | Attached

newtype BpfObject (s :: LifecycleState) = BpfObject { rawObjectPtr :: Ptr RawObject }

openObject   :: FilePath                    -> IO (Either CustodianError (BpfObject 'Opened))
loadObject   :: BpfObject 'Opened   %1 -> IO (Either CustodianError (BpfObject 'Loaded))
attachObject :: BpfObject 'Loaded   %1 -> IO (Either CustodianError (BpfObject 'Attached))

-- | Every non-terminal lifecycle state has a valid, direct exit to teardown —
-- a caller who loads an object, populates its maps, and decides not to attach
-- a program is not stuck with an unconsumable linear value (see §3.3).
--
-- The two instances are deliberately *not* the same operation: an attached
-- object holds a live kernel-side BPF link that a merely-loaded object does
-- not, so tearing it down is strictly more work, not a shared no-op wrapper.
class Teardownable (s :: LifecycleState) where
  teardown :: BpfObject s %1 -> IO ()

-- Shared building block, wrapping a Custodian.Raw primitive (§2.3 DRY):
idiomaticClose :: BpfObject 'Loaded %1 -> IO ()   -- wraps bpf_object__close

-- | Loaded-only teardown: no link exists yet, so this is just an object close.
-- Verified pattern (GHC 9.4.7 spike, §8 Risk 1d/1b): the linearly-extracted
-- field must be forwarded directly into the FFI call, never inspected,
-- shown, copied, or silently discarded — that is the shape that actually
-- compiles under LinearTypes.
instance Teardownable 'Loaded where
  teardown = idiomaticClose

-- | Attached teardown: the live link must be destroyed *and* the object
-- closed. This is deliberately ONE call into `Custodian.Raw`, not two
-- chained Haskell-level linear IO steps: per §8 Risk 1b (confirmed
-- empirically), sequencing two linear IO actions over the same linearly-typed
-- value requires `linear-base`'s own do-notation via RebindableSyntax —
-- Prelude's plain `do`/`>>=` fails to typecheck there. The general fix this
-- illustrates: once a linear value is forwarded into a single `toLinear`-lifted
-- Custodian.Raw call, everything *inside* that call is ordinary, unrestricted
-- Haskell again — the linear-value's field has already been "spent" — so
-- Custodian.Raw is free to sequence bpf_link__destroy and bpf_object__close
-- with plain `do`-notation internally. Sequencing problems under linearity
-- are avoided by pushing the sequence into the unrestricted Raw layer, not
-- by adopting RebindableSyntax at the idiomatic layer — this is the pattern
-- to reach for whenever a future teardown-like function needs multiple steps.
instance Teardownable 'Attached where
  teardown = idiomaticDestroyLinkAndClose

idiomaticDestroyLinkAndClose :: BpfObject 'Attached %1 -> IO ()
-- forwards the linear field once into a single Custodian.Raw function that
-- internally calls bpf_link__destroy then bpf_object__close via ordinary,
-- unrestricted do-notation (see comment above for why that's safe here)
```

The consequence: it is a **type error**, not a runtime exception and not a documentation warning, to attempt to attach a program that hasn't been loaded, or to read a map from an object that's already been torn down. This single mechanism eliminates an entire class of bugs that plague hand-written C/Go/Rust eBPF loaders, where "did I load before I attached" is a convention enforced by discipline and code review rather than the compiler. Because `teardown` is defined per-state rather than only at `'Attached'`, every reachable non-terminal state has a well-typed way out — a `Loaded`-but-never-attached object is not a value the type system can trap a caller with — and because the two instances are distinct, an attached object's link is never silently leaked by a teardown path that only knew how to close the object.

### 3.3 Linear consumption — handle correctness

Note the `%1` multiplicity annotations in §3.2: each function that takes a `BpfObject` in a given state consumes it exactly once. This is what makes the following two programs compile errors rather than runtime bugs:

```haskell
-- Compile error: `obj` used twice.
useTwice obj = do
  r1 <- attachObject obj
  r2 <- attachObject obj   -- obj already consumed above
  ...

-- Compile error: `obj` discarded without being consumed.
leakIt :: BpfObject 'Loaded %1 -> IO ()
leakIt _obj = pure ()       -- linear binder must be used, not merely bound
```

`teardown` returning `()` rather than `BpfObject 'TornDown` is a deliberate simplification over v1.0's draft: once linearity guarantees exactly-once consumption, there is no remaining reason to hand back a token for a state nothing can transition out of. Values threaded out of linear functions that are *not* themselves resources — an `Int` count, a `Bool`, a decoded map value — are returned wrapped in `Ur` from `linear-base`, making explicit in the type which parts of a result are unrestricted data versus which are linear resources.

### 3.4 Resource safety: what linearity guarantees, and what still needs `bracket`

Linearity and `bracket`-style scoping close two genuinely different failure modes, and this document is explicit that neither one subsumes the other:

- **Linearity (§3.3) is a compile-time, syntactic guarantee.** Every well-typed function that receives a `BpfObject s` must consume it exactly once along every code path — the type checker rejects a callback that returns without having threaded the handle to a further lifecycle call or to `teardown`. This rules out leaks-by-omission and double-consumption *in code that runs to completion*.
- **Linearity does not, by itself, guarantee cleanup runs if an exception is thrown mid-callback.** If an `IO` action inside the callback throws before the handle reaches `teardown`, the exception unwinds the stack immediately — the linear handle is never reached, and the type checker has nothing to say about it, because "consume exactly once" is a static property of the code as written, not a runtime guarantee about which lines actually execute. This is a known, unresolved-in-general tension between linear resource types and exceptions, not an oversight specific to this design, and it is why `withBpfObject` still needs genuine `bracket`/`onException` machinery underneath, not linearity alone.
- **The scoped wrapper therefore combines both mechanisms rather than relying on either alone:**

  ```haskell
  withBpfObject :: FilePath -> (BpfObject 'Loaded %1 -> IO (Ur a)) -> IO (Either CustodianError a)
  ```

  On the **normal path**, the callback is required (by linearity) to consume the handle down to `teardown` itself before returning — the type checker is the enforcement mechanism. On the **exception path**, `withBpfObject`'s implementation captures the object's `rawObjectPtr` (an ordinary, freely-duplicable `Ptr`, invariant across the phantom-state transitions per the `newtype` in §3.2) *before* the handle enters the linear region and the callback is invoked — not after, since a linear value that has already been handed to the callback is no longer something the wrapper can inspect. That captured pointer is closed over by a `Control.Exception.onException` handler wrapped around the callback invocation, calling a single narrow, explicitly-documented function in `Custodian.Raw`:

  ```haskell
  -- | Best-effort cleanup for the exception path only. Never exposed outside
  -- withBpfObject's implementation. Distinct from the idiomatic Teardownable
  -- instances (§3.2), which know the phantom state and so know exactly which
  -- steps are needed; this function does not have that information (the
  -- captured Ptr carries no phantom-state tag), so it must discover the
  -- object's actual state at the kernel level rather than assume one:
  --   1. Query the object for any live links via bpf_object__for_each_program
  --      + bpf_program__attach status (or the equivalent libbpf introspection
  --      call available at the pinned libbpf version, §2.6).
  --   2. Destroy any link found live, via bpf_link__destroy.
  --   3. Close the object via bpf_object__close, unconditionally, last.
  -- This ordering is safe to run whether the exception fired before or after
  -- attachObject succeeded, which is exactly the ambiguity the captured
  -- pointer can't resolve on its own.
  emergencyClose :: Ptr RawObject -> IO ()
  ```

  so the kernel-side resource is still released even though the linear handle itself was abandoned mid-flight by the exception. This escape hatch is intentionally the *only* place in the idiomatic layer that reaches around the linear discipline, and it exists solely to compensate for the gap linearity leaves under exceptions — it does not weaken the compile-time guarantee for any code path that completes normally. `emergencyClose`'s own correctness (in particular, step 1's link-discovery query) is exactly the kind of claim that needs a property test per §2.1/§9 — inject a failure at each point in a real load/attach sequence and assert no kernel-side resource remains live afterward — not just a design-doc description of the intended algorithm.

What the linear multiplicity on the callback argument *does* fully guarantee at compile time, with no caveat: the caller cannot stash the handle somewhere and use it after the scope ends, and cannot hand it to two different callers concurrently. Those are aliasing guarantees, which linearity is suited to; "cleanup always runs" is a control-flow guarantee, which is `bracket`'s job, not linearity's.

### 3.5 Map handle safety — scoped branding, not linear typing

§2.5 and §3.3 establish linear typing as the discipline for `BpfObject`. `LiveMap k v` (§2.2, §5) is also a live, kernel-backed handle, and an earlier draft of this document left open whether it should carry the same `%1` discipline. It should not, and this section states why and what replaces it, so the decision is recorded rather than re-litigated at Phase 4.

**Why linearity is the wrong fit for map handles.** Linear typing on `BpfObject` works because every lifecycle function is a genuine one-shot *state transition*: `loadObject` consumes an `'Opened` value and produces a `'Loaded` one, exactly once, per §3.2. Map I/O is not that shape — `readMap`/`writeMap` are *repeatable* operations. A real program polls a hash map for aggregated counts in a loop against the same handle, calling it many times without consuming anything. Forcing `%1` onto `LiveMap` would mean every lookup has to thread a fresh token back out solely to satisfy the linearity checker on the next call — busywork for a resource that isn't actually being spent, fighting the pattern's own grain rather than expressing anything real about the domain.

There is also a structural reason from `libbpf` itself: a map's file descriptor is owned by the `bpf_object` that declared it. There is no `bpf_map__destroy` call a caller is responsible for invoking — map fds are released as a side effect of `bpf_object__close`/link teardown (§3.2). A `LiveMap` was therefore never a resource with its own consumption obligation; it is a *capability derived from* the object's resource, not an independent resource that linearity's "consume exactly once" model is answering a question about.

**What actually needs preventing, and what closes it.** The genuine bug to rule out is not double-use (harmless — reading twice is fine) but a `LiveMap` **outliving the `BpfObject` it was derived from** and being used against an fd that teardown has already released. That is a scoping/lifetime problem, not a use-count problem, and it is closed the same way §3.4 already closes the analogous problem for `BpfObject` itself under exceptions: a `bracket`-style scoped wrapper, not linearity. Concretely, a rank-2 phantom brand (the same `runST`/`STRef`-style trick that prevents an `ST` reference escaping its `runST` scope) ties every `LiveMap` to the lexical scope in which its parent object is guaranteed live:

```haskell
newtype LiveMap (br :: Type) t k v = LiveMap { mapFd :: Fd }

-- | Open a scoped, typed handle onto a declared map.
--
-- Pre-condition:  the enclosing 'BpfObject' is 'Loaded' or 'Attached'.
-- Post-condition: within the callback, 'LiveMap' operations (lookup, update,
--                 delete, iterate) may be called any number of times.
-- Invariant:       the 'br' brand cannot unify outside this function's scope,
--                 so a 'LiveMap' value cannot be returned from, or otherwise
--                 escape, the callback — mirroring how an 'STRef s' cannot
--                 escape 'runST'.
withMap
  :: BpfObject s
  -> MapName
  -> (forall br. LiveMap br t k v -> IO (Ur a))
  -> IO (Either CustodianError a)
```

`readMap`/`writeMap`/`deleteMap`/iteration take `LiveMap` as an ordinary, unrestricted argument — called as many times as needed inside the scope, no token-threading required. This is not a departure from §3.4's own conclusion; it is that conclusion applied a second time. §3.4 already established that leak-safety under exceptions is `bracket`'s job, not linearity's, once real control flow is involved. Map-handle scoping is the same lesson applied to a lifetime problem instead of a use-count problem.

**Accepted residual gap.** Nothing in this design stops a caller from extracting the raw fd via `mapFd`/`bpf_map__fd` inside the callback and stashing it somewhere that outlives the scope — the brand prevents the *typed* handle from escaping, not a determined caller from copying the raw integer out of it. This is the same category of accepted gap as `emergencyClose`'s captured pointer in §3.4: correctness for a caller who deliberately reaches around the API rests on discipline, not the type checker, and is not treated as a defect in this design.

## 4. Non-Goals (unchanged from the validated v1 scope)

To keep this at ≤2000 LOC and to keep the type-driven architecture in §3 tractable, Custodian v1 explicitly does **not**:

- Implement an eBPF verifier, loader, or compiler from scratch — we wrap `libbpf`; the kernel and `libbpf` do the hard parts.
- Support more than two program types (`tracepoint`, `kprobe`/`kretprobe`) or two map types (`BPF_MAP_TYPE_HASH`, `BPF_MAP_TYPE_ARRAY`) in v1.
- Provide a Haskell-hosted eBPF compiler. Programs are authored in restricted C, compiled with `clang -target bpf`, exactly as in every other language's eBPF binding. Custodian only binds the loading/interaction side.
- Provide CO-RE (Compile Once — Run Everywhere) BTF relocation support in v1. This is the single biggest capability gap versus `aya`/`cilium/ebpf`, and is deferred deliberately (§6).
- Target anything other than Linux x86_64/aarch64 with a 5.x+ kernel.
- Extend linear typing into `Custodian.Raw`. Linearity is an idiomatic-layer discipline (§2.5, §3.1); the `Raw` FFI layer stays unrestricted and near-verbatim against the C API on purpose.
- Extend linear typing to `LiveMap` handles. Deliberate, not an oversight — see §3.5 for why map handles are scope-branded rather than linearly consumed.

Anything not explicitly in-scope in §5 is out of scope for v1, full stop — scope creep is the primary risk to both the LOC budget and the architectural rigor demanded by §2.

## 5. In-Scope Feature Set (v1)

| Area | In scope | Rationale |
|---|---|---|
| Program loading | `bpf_object__open`/`__load` via the `Opened → Loaded` transition, linear-handle-consumed | Universal entry point regardless of program type |
| Program types | `tracepoint`, `kprobe`/`kretprobe` | Majority of observability/tracing use cases; no special attach-target plumbing |
| Attach/detach | `Loaded → Attached` transition, `bracket`-scoped, linear-handle-consumed | Correctness of resource lifetime *and* single-use handle correctness matter more here than breadth |
| Map types | `BPF_MAP_TYPE_HASH`, `BPF_MAP_TYPE_ARRAY` | Cover the overwhelming majority of real programs' data-exchange needs |
| Map I/O | lookup, update, delete, iterate (`bpf_map_get_next_key`), each total over the typed lifecycle state, scoped per §3.5 (`withMap` + rank-2 brand, not linear) | Core CRUD only, but type-safe over object lifecycle and handle lifetime |
| Error handling | Closed `CustodianError` exception/ADT hierarchy, one classification table (§2.3), errno preserved | Non-negotiable per §2.4 |
| Object lifecycle | Phantom-typed state machine (§3.2) + linear handle consumption (§3.3) + `bracket`-scoped acquisition (§3.4) | The architectural core of this document |
| Tooling gates | `-Wall -Werror`, `hlint`, `weeder`, Ormolu/Fourmolu, `cabal-docspec`, Haddock-coverage, header-derived `Storable` instances, pinned-libbpf Nix flake — all CI-blocking | Turns §2 from convention into structural enforcement (§2.6) |

## 6. Deferred to v2+ (tracked explicitly, not silently dropped)

- XDP and TC (traffic-control) program types — require additional attach-point plumbing (interface indices, TC qdisc setup).
- Perf-event and ring-buffer map types for streaming kernel→userspace events — the most-requested feature for "real" observability tooling, deferred because the consumer-side polling loop adds meaningful surface area and its own lifecycle-safety questions.
- CO-RE / BTF relocations — needed for "compile once, run on any kernel version." Likely the biggest reason v1 alone isn't fleet-production-ready across heterogeneous kernel versions.
- Any bytecode-generation/compiler story.

## 7. Estimated LOC Budget

| Module | Est. LOC | Notes |
|---|---|---|
| `Custodian.Raw` (FFI decls + header-derived `Storable` instances) | 500–700 | Bulk of the raw surface; mechanical but must be exact against the C headers, now generated rather than hand-transcribed (§2.3, §2.6) |
| `Custodian` (phantom-typed + linear-typed lifecycle API, capability typeclasses, `bracket` wrappers, `withMap` scoping per §3.5) | 600–850 | Raised from the v1.0 estimate — linear multiplicity annotations and `Ur`-boundary bookkeeping (§2.5, §3.3) cost real LOC on top of the phantom-typed machinery, deliberately, in exchange for compile-time handle-correctness on top of compile-time sequencing-correctness; §3.5's rank-2 map-scoping wrapper is a small, well-understood addition on top (same shape as `runST`), not expected to meaningfully move this estimate |
| `Custodian.Errors` | 100–150 | errno → exception mapping, single table |
| Tooling config (`hlint.yaml`, `weeder.toml`, `fourmolu.yaml`, Nix flake, docspec config) | — | Configuration, not library LOC; excluded from budget same as tests |
| Example programs (outside budget) | — | Canonical tracepoint-based syscall counter, matching every other language's eBPF "hello world" |
| **Total (excl. tests, excl. examples, excl. tooling config)** | **~1200–1700** | Still comfortably under the 2000 LOC ceiling |

Tests are excluded from the LOC budget per the original constraint, but per §2.1 and §2.6, property-based tests stating the lifecycle and resource-safety laws are a **release-blocking, CI-checked requirement**, not optional polish.

## 8. Key Risks

1. **The type-level lifecycle machinery — phantom-typed *and* linear-typed — is the single biggest technical-risk item in this document.** Phantom-typed state machines are a well-understood pattern; linear types layered on top are not, for most Haskell contributors. Getting the combined API ergonomic (not a chore to call, and not a wall of inscrutable linearity errors) while keeping it airtight (no escape hatch that lets a caller construct an out-of-sequence state, alias a handle, or leak one) takes real design iteration. Mitigation: prototype §3.2/§3.3 in isolation, against a stub/mock backend, before writing a single line of real FFI code — see the phase plan, §10.
   - **1a. Hand-transcribed struct offsets are a sharper, quieter risk than the type-level machinery above.** A wrong offset in a hand-written `Storable` instance doesn't fail to compile and doesn't throw — it silently corrupts memory across the FFI boundary into a kernel subsystem, in exactly the part of the codebase (`Custodian.Raw`) with the least type-level protection by design (§3.1). Mitigation: header-derived offsets via `hsc2hs` (GHC's bundled tool, preferred — see §2.6) are a Phase 2 merge-blocking requirement (§2.6, §10), not an optional hardening pass.
   - **1b. CONFIRMED: plain `do`-notation breaks linear sequencing across two IO steps.** Verified with a direct compiler spike (GHC 9.4.7, the closest available proxy for the pinned 9.14 line — see 1d for the caveat on that substitution): a `Teardownable` instance written as a single expression forwarding the linearly-extracted field into one FFI-style call compiles and runs cleanly; the identical instance rewritten with a `do` block sequencing two IO actions over the same linear value fails with a multiplicity error. Root cause: standard `do`-notation desugars through Prelude's `Monad` `>>`/`>>=`, which require unrestricted arguments — `linear-base`'s own user guide independently documents this exact class of gotcha. **Resolution:** multi-step teardown sequences (`Teardownable 'Attached` in §3.2, which must destroy a link *then* close the object) must either (a) use `RebindableSyntax` with `linear-base`'s `Control.Functor.Linear` do-notation instead of the Prelude one, or (b) be restructured as a single combined raw FFI call so no Haskell-level linear sequencing is needed. Option (b) is lower-risk for v1 and is now reflected in §3.2's code sample.
   - **1c. The exception-path escape hatch in §3.4 depends on hand-written correctness, not the type checker.** `emergencyClose` exists because linearity alone cannot guarantee cleanup runs if an exception fires mid-callback; it's scoped as tightly as possible (one function, never exposed outside `withBpfObject`'s implementation), but it's the one place in the idiomatic layer where correctness rests on a `bracket`/`onException` pairing being right, not on compile-time guarantees.
   - **1d. CONFIRMED: linear methods inside a typeclass compile and run correctly**, given the single-expression pattern above — `Teardownable`'s design in §3.2 is not blocked by anything GHC-version-specific in principle. The one real caveat: this was verified against GHC 9.4.7, since 9.14 isn't installable in a sandboxed environment without access to `ghcup`/`downloads.haskell.org`. `LinearTypes` behavior for class methods and data-constructor fields has been stable since its introduction in GHC 9.0 per GHC's own users' guide, so a 9.4→9.14 behavior change here would be a genuine regression, not an expected gap — worth a five-minute re-run of this exact spike on a real 9.14 install before Phase 1 is called complete, but not treated as a live open risk.
2. **CO-RE gap may make v1 feel "toy-grade" to fleet-scale adopters.** Documented up front in the README, not discovered by users the hard way.
3. **`libbpf` version/ABI drift** — mitigated by a pinned Nix flake (§2.6) alongside documenting the supported version range explicitly.
4. **Privileged CI infrastructure.** Testing requires `CAP_BPF`/`CAP_SYS_ADMIN` and a real Linux kernel — this needs a privileged runner, solved early (Phase 1/2), not discovered late.
5. **The rigor bar itself is a delivery risk.** A hard constraint that every function states pre/post-conditions, every claimed law has a falsification-oriented property test, and every one of §2.6's tooling gates passes in CI is significantly slower to write than idiomatic-but-undocumented Haskell. This is an accepted, deliberate trade-off given this library's role sitting underneath other tooling — but it should be named explicitly as a reason v1 may take longer than the LOC count alone suggests.

## 9. Success Criteria for v1

- A working example loading a tracepoint-based program, attaching it, and reading aggregated counts from a hash map — the standard eBPF "hello world," reproduced with Custodian's phantom-typed *and* linear-typed API.
- Published on Hackage, `Custodian.Raw` and `Custodian` clearly separated and documented per §3.1.
- **Zero leaked kernel-side resources across normal and exceptional exit paths — verified by property test, not just asserted**, and zero handles usable-after-consumption, enforced at compile time by §3.3's linearity and spot-checked by property test for the parts linearity alone can't observe (e.g. exception-path teardown ordering).
- **Every public function's Haddock comment states a post-condition** (§2.1), checked by the Haddock-coverage CI gate (§2.6), not a best-effort aspiration.
- **Every claimed law has a corresponding Hedgehog property**, checked by the CI lint described in §2.6, not left to reviewer memory.
- All of §2.6's tooling gates (`-Wall -Werror`, `hlint`, `weeder`, formatting, `cabal-docspec`, header-derived `Storable` instances) green in CI before release.
- An honest README section stating the CO-RE/XDP/ring-buffer gaps up front.

## 10. Phase Plan

- **Phase 0 (validation, complete):** Confirmed the `libbpf` binding gap is current via Hackage/GitHub search; searched for a conflicting `custodian` package name (see header) — final confirmation still needed via a direct, live Hackage check before upload.
- **Phase 1 (type design first, no FFI yet):** Design and prototype the phantom-typed lifecycle state machine (§3.2), the linear handle-consumption discipline (§3.3), and the capability-typeclass segregation (§2.2) against a pure mock backend. No working eBPF interaction exists yet. Deliverables:
  - Re-verify §3.2's `Teardownable` design (confirmed in principle per Risk 1d) against a real GHC 9.14 install specifically — the confirming spike so far used 9.4.7 as a proxy.
  - Implement and property-test **§3.4's `emergencyClose`** against the mock backend (simulate a link being live or not) before any real kernel calls exist.
  - Write the full example program (§9) against the mock, validating the type-level API is airtight *and* ergonomic.
  - Wire the header-independent tooling gates from §2.6 (`-Wall -Werror`, `hlint`, `weeder`, formatting) into CI from day one.
- **Phase 2:** `Custodian.Raw` — FFI layer, validated against a hand-written C test program using the same `libbpf` calls, with `Storable` instances derived from the real headers via `hsc2hs` (§2.3, §2.6, Risk #1a; `c2hs`/`inline-c` may still be used separately for awkward macro/inline-function calls) — hand transcription is not an acceptable interim step, even temporarily. The Nix flake pinning `libbpf` (§2.6) and the privileged CI runner (Risk #4) land here.
- **Phase 3:** `Custodian.Errors` + wire the phantom-typed and linear-typed API from Phase 1 to the real `Raw` FFI backend from Phase 2, via the capability typeclasses (so the Phase 1 mock and the Phase 3 real backend are, provably, two instances of the same abstraction — the Dependency Inversion translation from §2.2, exercised for real).
- **Phase 4:** Typed map API (`readMap`/`writeMap`/`deleteMap`/iteration) over `Storable` keys/values, lifecycle-state-checked at compile time, scoped via `withMap`'s rank-2 branding per §3.5 (not linear typing — see §3.5 for why), `Ur`-boundary-correct for values threaded out of the scope.
- **Phase 5:** End-to-end example, property-test suite covering every documented law (with the §2.6 CI lint enforcing that coverage), `cabal-docspec` and Haddock-coverage gates turned on for the full public surface, docs, Hackage release.
- **Phase 6 (post-v1, tracked, not committed):** Evaluate demand for XDP/ring-buffer/CO-RE based on real v1 user feedback before committing further scope.

---

*Every hard constraint in §2 applies to all phases without exception; a deviation requires a documented, reviewed rationale recorded in the module it applies to, not a silent shortcut.*
