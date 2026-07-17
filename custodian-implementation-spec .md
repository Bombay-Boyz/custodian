# Custodian — Implementation Spec

Derived from `custodian-vision.md`. This document turns the vision doc's hard
constraints into per-phase, checkable deliverables. It does not restate the
rationale already in the vision doc — read that first. This is the "what to
build, in what order, and how you know it's done" companion.

**Revision note:** Phase 0's search-pass validation is complete, but the live
Hackage availability check is *not* — see the correction below; this document
previously claimed it had been run, which contradicted the vision doc and has
been fixed to match it. Phase 4's previously-open question about `LiveMap` linearity is
resolved — `LiveMap` is scope-branded (`withMap`), not linear — matching the
vision doc's new §3.5. A handful of other corrections (negative-compile-test
mechanics, risk-status wording, invented-vs-specified enforcement details)
are folded in from a review pass and called out inline, in place, where each
applies (no separate design log exists — this note and the inline callouts
are the full record of what changed and why).

---

## Phase 0 — Validation (complete)

**Goal:** confirm the project is worth building and the name is available.
No code.

| # | Task | Status |
|---|---|---|
| 0.1 | Confirm no maintained `libbpf`-wrapping Haskell binding exists | ✅ Done — `ebpf-tools`/`hBPF` confirmed unmaintained, bytecode-layer only |
| 0.2 | Search-pass check for a conflicting `custodian` package name | ✅ Done, no conflict found |
| 0.3 | **Live, direct Hackage check** for `custodian` — `cabal update && cabal info custodian` | ⏳ **Not done.** Not reachable from this environment (matches the vision doc's header note). Remains an open action item — see correction below. |

**Correction (reconciled against the vision doc):** an earlier revision of this spec marked 0.3 as done, with a specific timestamp, implying the live Hackage check had already been run and come back clean. That contradicted the vision doc, which states plainly that this check "wasn't reachable for a live check from this environment" and is still outstanding. Treating an unverified, environment-blocked check as a completed one is exactly the kind of silent gap this project's own rigor standard (§2) exists to rule out — a claimed fact with no actual evidence behind it — so the status here has been corrected to reflect that the check has *not* yet been run by anyone, not just "not run recently."

**Exit criterion for Phase 0:** 0.1 and 0.2 (search-pass validation) are genuinely complete and unblock Phase 1 — none of Phases 1–4 depend on Hackage availability. 0.3 does **not** need to block Phase 1; it blocks only the Phase 5 Hackage upload itself, and only has a useful shelf life of a few days. Concretely:
- Do **not** run `cabal update && cabal info custodian` now just to close this checkbox — a result today would be stale well before Phase 5 ships.
- Add running it as an explicit, named Phase 5 deliverable/acceptance criterion (see Phase 5 below), executed immediately before the `cabal upload` step, with upload blocked if a conflict is found.

---

## Phase 1 — Type design, no FFI

**Goal:** the phantom-typed + linear-typed lifecycle API exists, compiles,
and is ergonomic — proven against a mock backend, before any real kernel
interaction is written.

### Deliverables

1. **Project skeleton**
   - Cabal project targeting GHC 9.14.x exactly (not `>=9.14`).
   - `Relude` (or equivalent total prelude) wired in; `-Wall -Werror`.
   - `{-# WARNING #-}`-style bans on `head`, `fromJust`, `(!!)`, partial pattern matches.
2. **`LifecycleState` + `BpfObject` phantom type** (§3.2 of vision doc)
   - `data LifecycleState = Opened | Loaded | Attached`
   - `newtype BpfObject (s :: LifecycleState) = BpfObject { rawObjectPtr :: Ptr RawObject }`
   - `openObject`, `loadObject`, `attachObject` stubbed against a **mock backend** (in-memory state, no real `libbpf` call) — return values are real `Either CustodianError` results, just backed by fake data.
3. **`Teardownable` typeclass**, instances for `'Loaded` and `'Attached` (§3.2)
   - `'Attached` instance implemented as a **single call** into the mock "raw" layer, not chained `do`-notation over the linear value (per Risk 1b) — prototype this pattern here since it's the pattern every later teardown-like function must follow.
4. **Linear consumption** (§3.3)
   - `%1` multiplicity on every handle-consuming function.
   - `Ur`-wrapped return values for non-resource data threaded out of linear functions.
   - Two negative test cases that **must fail to compile**: double-use of a handle, and discarding a handle without consuming it. These cannot live inside the normal test-suite component — if bundled with passing tests, a failing negative case fails the whole build and nothing else runs. Isolate them as their own cabal component (e.g. `negative-tests`, `buildable: False` by default so `cabal build`/`cabal test` skip it normally) and drive it from a small CI script that invokes `cabal build negative-tests` per case, asserts a non-zero exit code, and optionally greps stderr for the expected multiplicity-error text. This is the same shape as GHC's own `should_fail` testsuite category — don't try to fit it inside Hedgehog/Tasty's normal pass/fail model.
5. **`withBpfObject` scoped wrapper + `emergencyClose`** (§3.4)
   - `withBpfObject :: FilePath -> (BpfObject 'Loaded %1 -> IO (Ur a)) -> IO (Either CustodianError a)`
   - `emergencyClose` implemented and **property-tested against the mock**: inject a simulated failure at each point in a load→attach sequence, assert the mock backend reports zero live resources afterward.
6. **Capability typeclasses** (§2.2 Interface Segregation)
   - The vision doc's own split — a lifecycle-operations class, a map read/write class, an attach/detach class — is explicitly **illustrative, not final** (§2.2's wording). Treat it as a starting point, not a fixed target; the actual boundary should fall out of what real call sites need, checked structurally by `weeder` (§2.2: an unused export is the signal the segregation has drifted), not decided upfront and then defended.
   - The mock backend is one instance; this is the seam Phase 3 will plug the real `Raw` backend into.
7. **End-to-end example against the mock** (§9's success criterion, mock-only version)
   - Load → attach → read a fake aggregated count → teardown, entirely against the mock. This is the ergonomics proof, not the real "hello world" — that comes in Phase 5.
8. **CI wired from day one**: `-Wall -Werror`, `hlint` (gating), `weeder` (gating), Ormolu/Fourmolu (checked, not just applied). `cabal-docspec` and Haddock-coverage don't need to be hard *gates* until Phase 5 per the doc — but running them non-blocking (report-only, doesn't fail the build) from Phase 1 costs nothing if the mock example already has Haddock, and surfaces drift early instead of as a Phase-5 surprise. Non-blocking now, gating later — not a contradiction with the "out of scope" note below, which refers specifically to gating.

### Acceptance criteria

- [ ] Every public function in the idiomatic layer has a Haddock block in the pre-condition/post-condition/invariant style shown in §2.1 of the vision doc.
- [ ] The two negative linearity test cases fail to compile, and this failure is asserted by CI (not just observed once by a human).
- [ ] `emergencyClose` has at least one falsifying Hedgehog property, per §2.1/§9.
- [ ] The mock-backend example program runs end-to-end with zero warnings.
- [ ] **Re-run the Risk 1d spike (linear methods inside a typeclass) against a real GHC 9.14 install**, not the GHC 9.4.7 proxy used for the original confirmation. This is explicitly called out in the vision doc as a Phase 1 exit requirement, not optional.

### Explicitly out of scope for Phase 1

- Any real FFI declaration.
- The Nix flake pinning `libbpf` (deliberately deferred to Phase 2 — don't add this infrastructure weight yet).
- `cabal-docspec`/Haddock-coverage as hard CI gates (soft target only).

---

## Phase 2 — `Custodian.Raw` (real FFI layer)

**Goal:** a near-verbatim, auditable FFI surface against real `libbpf`
headers, with zero hand-transcribed struct offsets.

### Deliverables

1. **`hsc2hs`-derived `Storable` instances** for every C struct touched (`bpf_object`, `bpf_program`, `bpf_map`, etc.) — generated from the real `libbpf` headers, not hand-written. `c2hs`/`inline-c` may be used only for awkward macro/inline-function bindings, never as the default tool for `Storable` instances.
2. **FFI declarations**, near-1:1 with the C API: `bpf_object__open`, `bpf_object__load`, `bpf_program__attach`, `bpf_object__close`, `bpf_link__destroy`, `bpf_map__fd`, `bpf_map_lookup_elem`, `bpf_map_update_elem`, and the small additional surface needed for `emergencyClose`'s link-discovery query.
3. **Nix flake pinning the exact `libbpf` version** — lands here, not Phase 1.
4. **Privileged CI runner** (`CAP_BPF`/`CAP_SYS_ADMIN`, real Linux kernel) — set up here, not deferred to Phase 5 (Risk #4 in the vision doc explicitly calls out "solved early").
5. **Validation harness**: a hand-written C test program using the same `libbpf` calls, run side-by-side to confirm the Haskell FFI layer's behavior matches.

### Acceptance criteria

- [ ] Zero hand-transcribed `Storable` instances anywhere in `Custodian.Raw` — this is a hard merge gate, not a style preference (Risk #1a).
- [ ] Every `Storable` instance's field offsets are cross-checked against the C struct layout on the pinned `libbpf` version. *(This specific check — e.g. a script comparing `hsc2hs`-generated offsets to `pahole`/`offsetof` output — isn't specified in the vision doc; it's a suggested way to satisfy Risk #1a's "no hand-transcribed offsets" requirement, not a mandated tool.)*
- [ ] `Custodian.Raw` remains fully unrestricted (no linear types anywhere in this module — that's an idiomatic-layer-only property).
- [ ] Privileged CI runner is green on the FFI layer's own smoke tests before Phase 3 starts.

---

## Phase 3 — Wire idiomatic API to real backend

**Goal:** prove the capability-typeclass abstraction from Phase 1 is real by
instantiating it twice — mock (Phase 1) and real (Phase 2) — over the same
polymorphic business logic.

### Deliverables

1. `Custodian.Errors` — the single errno/`libbpf`-return-code → `CustodianError` classification table (§2.3 DRY).
2. Real-backend instances of the Phase 1 capability typeclasses, backed by `Custodian.Raw`.
3. The Phase 1 mock-backend example program's business logic (load→attach→read→teardown) run **unmodified** against the real backend — same source, different instance, per §2.2's Dependency Inversion translation.

### Acceptance criteria

- [ ] The load→attach→read→teardown logic exists in exactly one place in source, exercised against both the mock and the real backend via typeclass polymorphism — not two copies.
- [ ] Every error path in `Custodian.Raw` maps through the single `Custodian.Errors` table — grep for any ad-hoc `if errno == ...` outside that table (should find none).

---

## Phase 4 — Typed map API

**Goal:** `readMap`/`writeMap`/`deleteMap`/iteration, lifecycle-state-checked
at compile time, scoped per §3.5 of the vision doc so a `LiveMap` cannot
outlive the object it was derived from.

**Resolved design note:** an earlier version of this spec flagged an open
question — whether `LiveMap` should be linearly typed like `BpfObject`. It's
now resolved (vision doc §3.5, added specifically to close this gap):
`LiveMap` is **not** linear. Map reads are repeatable operations, not
one-shot state transitions, so `%1` would force pointless token-threading on
every lookup. Instead, `LiveMap` is scoped via a rank-2 phantom brand — the
same `runST`/`STRef` trick — so it's a compile error for a `LiveMap` value to
escape the scope in which its parent object is guaranteed live. See §3.5 for
the full rationale and the `withMap` signature.

### Deliverables

1. Map I/O over `BPF_MAP_TYPE_HASH` and `BPF_MAP_TYPE_ARRAY` only (v1 scope).
2. `withMap :: BpfObject s -> MapName -> (forall br. LiveMap br t k v -> IO (Ur a)) -> IO (Either CustodianError a)` (§3.5) — the scoping entry point; nothing constructs a bare `LiveMap` outside it.
3. Lookup, update, delete, and iteration (`bpf_map_get_next_key`) as ordinary (unrestricted) functions over `LiveMap br t k v` — callable any number of times within the `withMap` scope, no linear threading. Only reachable when the enclosing `BpfObject` is `'Loaded` or `'Attached`, enforced by `withMap`'s own type, not a runtime check.
4. `MapSpec` (description) vs `LiveMap k v` (validated, kernel-backed handle) kept as genuinely distinct types per §2.2's Single Responsibility translation — never conflated even though the C API uses one struct for both.

### Acceptance criteria

- [ ] A `LiveMap` value cannot be returned from, or otherwise escape, `withMap`'s callback — demonstrated by a should-not-compile test (attempting `withMap obj name (\lm -> pure (Ur lm))` should fail with a rigid-`br`/skolem-escape error, not a runtime bug).
- [ ] Calling map I/O outside a `withMap` scope, or on an object that's `'Opened`-but-not-`'Loaded`, is a compile error, demonstrated by a should-not-compile test.
- [ ] Every value threaded back out of `withMap` (counts, decoded bytes, success flags) is `Ur`-wrapped — since `LiveMap` itself can never legitimately leave the scope, there is no case where an "unwrapped resource" should appear in a `withMap` result; any such case is a bug.
- [ ] Document the accepted residual gap from §3.5 (a caller can still extract and stash the raw fd via `mapFd` inside the callback) in the module's own Haddock, per the vision doc's "quarantined and documented" partiality standard (§2.4) — this is a known, accepted limit on the guarantee, not a silent one.

---

## Phase 5 — Integration, full test coverage, release

**Goal:** ship v1.

### Deliverables

1. The real "hello world": tracepoint-based syscall counter, loaded, attached, reading aggregated counts from a hash map — against the real kernel, real `libbpf`.
2. Property-test suite covering **every** law claimed in a Haddock comment — enforced by the §2.6 lint (grep-and-flag acceptable for v1) that a Pre-condition/Post-condition/Invariant block without a matching Hedgehog property fails CI.
3. `cabal-docspec` and Haddock-coverage gates turned on as hard CI blockers for the full public surface (soft targets in Phase 1 become hard gates here).
4. README documenting the CO-RE/XDP/ring-buffer gaps up front (§4 non-goals), not discovered by users the hard way.
5. **Live Hackage name-availability re-check**, run for the first time (Phase 0.3 was never actually performed — see the Phase 0 correction) immediately before `cabal upload`: `cabal update && cabal info custodian`. If the name is now taken, stop and resolve naming before uploading anything — do not proceed on the strength of the Phase 0 search-pass check alone.
6. Hackage release, `Custodian.Raw` and `Custodian` clearly separated and documented per §3.1.

### Acceptance criteria (= §9 of the vision doc, verbatim intent)

- [ ] Zero leaked kernel-side resources across normal and exceptional exit paths — verified by property test.
- [ ] Zero handles usable-after-consumption — enforced at compile time, spot-checked by property test for exception-path ordering.
- [ ] Every public function's Haddock states a post-condition — CI-checked.
- [ ] Every claimed law has a Hedgehog property — CI-checked.
- [ ] All §2.6 tooling gates green: `-Wall -Werror`, `hlint`, `weeder`, formatting, `cabal-docspec`, header-derived `Storable` instances.
- [ ] LOC budget check: ~1200–1700 excl. tests/examples/tooling config, ceiling 2000.
- [ ] `cabal update && cabal info custodian` run directly against the live Hackage index immediately before `cabal upload`, with a clean (no-conflict) result — this is the first time this check will actually have been performed; the upload step does not proceed without it.

---

## Phase 6 — Post-v1 (tracked, not committed)

Evaluate demand for XDP, ring-buffer maps, and CO-RE based on real v1 user
feedback. No deliverables until a decision is made to pursue one.

---

## Cross-phase CI gate summary

| Gate | Introduced | Enforcement |
|---|---|---|
| `-Wall -Werror`, total prelude, partial-function bans | Phase 1 | Compiler-level |
| `hlint` | Phase 1 | CI, gating |
| `weeder` | Phase 1 | CI, gating |
| Ormolu/Fourmolu | Phase 1 | CI, checked |
| Should-not-compile linearity tests | Phase 1 | CI |
| Should-not-compile `LiveMap` scope-escape test | Phase 4 | CI |
| `hsc2hs`-derived `Storable` instances only | Phase 2 | Merge-blocking |
| Nix flake pinning `libbpf` | Phase 2 | Reproducible build |
| Privileged CI runner (`CAP_BPF`) | Phase 2 | Infra |
| Single `CustodianError` classification table | Phase 3 | Structural (grep-checkable) |
| `cabal-docspec` | Phase 5 (soft in P1) | CI, hard gate at release |
| Haddock-coverage + pre/post/invariant lint | Phase 5 (soft in P1) | CI, hard gate at release |
| Hedgehog-property-per-law lint | Phase 5 | CI, hard gate at release |

## Open risks to track (from vision doc §8, carried forward)

- **Risk 1d re-verification on real GHC 9.14** — the vision doc is explicit that this is *not* a live open risk (the pattern is confirmed in principle, stable since GHC 9.0), just a required confirmation checkbox before Phase 1 is called complete. Listed here as a checklist item, not a genuine unknown.
- **CO-RE gap perception** — mitigated by upfront README documentation in Phase 5, not a code fix.
- **`libbpf` ABI drift** — mitigated by the Phase 2 Nix flake.
- **Rigor-bar velocity cost** — accepted trade-off; no mitigation needed, just budget for it when estimating phase timelines.
