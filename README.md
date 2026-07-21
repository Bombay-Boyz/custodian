# custodian

A Haskell binding for libbpf, built to be read like a proof.

`custodian` provides a phantom-typed, linear-typed API over `libbpf`'s
BPF object lifecycle (open -> load -> attach -> teardown), making
double-frees, use-after-close, and skipped teardown steps into compile
errors rather than runtime bugs. See `custodian-vision.md` and
`custodian-implementation-spec .md` for the full design rationale.

## Building

```bash
cabal build all
```

## Testing

```bash
cabal test custodian-test          # Hedgehog properties against the mock backend
cabal test emergency-tests         # emergencyClose (withLoadedBpfObject / withAttachedBpfObject)
./scripts/check-negative-tests.sh  # confirms the double-teardown case is rejected at compile time
sudo env "PATH=$PATH" cabal test live-tests   # real backend, requires CAP_BPF
```

`live-tests` gracefully skips (without failing) if not run as root -- see
`live-tests/LiveSpec.hs` for details.

## Pinned versions

This project was built and last verified against:

- **GHC**: 9.14.1
- **libbpf**: 1.5.0 (Debian package `libbpf-dev` 1:1.5.0-3)
- **Hackage dependencies**: pinned exactly in `cabal.project.freeze`
  (generated via `cabal freeze`) -- notably `linear-base 0.8.1`,
  `relude 1.2.2.2`, `hedgehog 1.7`, `tasty 1.5.4`, `tasty-hedgehog 1.4.0.2`.

If you're building on a different GHC or `libbpf` version, expect to
need to re-verify the linear-typing workarounds documented inline in
`src/Custodian.hs` et al. -- several of them route around GHC's own
documented-as-experimental case/pattern multiplicity inference, which
is exactly the kind of thing that can shift between compiler versions.

A full Nix flake pinning all of this (including `libbpf` itself, not
just Hackage packages) is a deliberately deferred follow-up -- see
project notes/commit history for the reasoning. `cabal.project.freeze`
plus the versions above cover reproducibility for a single developer;
the flake becomes worth its setup cost once there's a CI runner to keep
in sync with.

## Known gaps

- `hlint` is not currently usable on GHC 9.14.1 (upstream hasn't caught
  up yet) -- see `hlint.yaml`.
- No Nix flake yet (see above).
- No privileged CI runner yet.
- The C-side validation harness is, for now, just the fixture-compile
  step inside `live-tests` -- not a fuller, independent harness.
