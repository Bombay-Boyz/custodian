{-# LANGUAGE DataKinds #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE LinearTypes #-}
{-# LANGUAGE QualifiedDo #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- | The lifecycle core, backend-agnostic.
--
-- Two layers live here, deliberately:
--
--   * A __linear, manual__ layer ('openObject'\/'loadObject'\/
--     'attachObject'\/'teardown'). Every handle-consuming step takes its
--     argument with multiplicity @%1@, so the type checker rejects
--     double-teardown and dropped handles at compile time. This is the
--     layer that "reads like a proof".
--
--   * A __scoped, exception-safe__ layer ('withLoadedBpfObject'\/
--     'withAttachedBpfObject'). These are ordinary 'Exception.bracket's:
--     the wrapper is the /sole/ owner of teardown and runs it exactly
--     once, on both the normal and the exceptional exit. The callback
--     receives a rank-2 'Scope' — a borrowed view that cannot be freed
--     (it has no 'Teardownable' instance) and cannot escape (its brand
--     @br@ never unifies outside the callback). This is what makes the
--     double-free window, the link-leak window, and the borrow
--     use-after-free /unrepresentable/ rather than merely unlikely.
module Custodian.Core
  ( -- * Lifecycle index
    LifecycleState (..)
  , BpfObject (..)

    -- * Capabilities
  , ObjectLifecycle (..)
  , AttachDetach (..)
  , Teardownable (..)

    -- * Manual linear lifecycle
  , openObject
  , loadObject
  , attachObject

    -- * Scoped, exception-safe lifecycle
  , Scope
  , scopeResource
  , withLoadedBpfObject
  , withAttachedBpfObject
  ) where

import Control.Exception qualified as Exception
import Control.Functor.Linear qualified as Control
import Custodian.Errors (CustodianError)
import GHC.Types qualified as GHCT
import Prelude.Linear qualified as L
import System.IO.Linear qualified as Linear
import Unsafe.Linear qualified as Unsafe
import Prelude (Either (..), FilePath, IO, fmap, pure, ($))

-- | The three lifecycle stages a 'BpfObject' can occupy (vision doc §3.2).
data LifecycleState = Opened | Loaded | Attached

-- | A handle to a BPF object, indexed by its current lifecycle stage and
-- parameterised over the backend's resource types (@objRes@ for the
-- object, @linkRes@ for the attach-produced link). The same lifecycle
-- functions therefore run unchanged against the mock and the real
-- backend (Dependency Inversion, §2.2). 'Attached' carries /both/
-- resources, because attaching produces a genuinely separate kernel
-- resource that must be destroyed before, and independently of, the
-- object.
data BpfObject objRes linkRes (s :: LifecycleState) where
  BpfObjectOpened :: objRes -> BpfObject objRes linkRes 'Opened
  BpfObjectLoaded :: objRes -> BpfObject objRes linkRes 'Loaded
  BpfObjectAttached :: objRes -> linkRes -> BpfObject objRes linkRes 'Attached

-- | Capability: open, load, and close a BPF object. Deliberately narrow
-- (Interface Segregation, §2.2) — knows nothing about attach or maps.
class ObjectLifecycle objRes where
  rawOpen :: FilePath -> Linear.IO (Either CustodianError objRes)
  rawLoad :: objRes %1 -> Linear.IO (Either CustodianError objRes)
  rawClose :: objRes %1 -> Linear.IO ()

-- | Capability: attach a loaded object's program, producing a link, and
-- detach that link. 'rawAttach' returns the object resource in /both/
-- branches: attaching neither consumes nor invalidates the object, so a
-- failed attach must still hand the object back for the caller to close
-- — omitting it silently leaks the object on every attach failure.
class AttachDetach objRes linkRes | linkRes -> objRes, objRes -> linkRes where
  rawAttach
    :: objRes %1 -> Linear.IO (Either (objRes, CustodianError) (objRes, linkRes))
  rawDetach :: linkRes %1 -> Linear.IO ()

-- | Open a BPF object file.
--
-- Pre-condition:  none — this is the lifecycle entry point.
-- Post-condition: on success, a 'BpfObject' in the 'Opened' state.
openObject
  :: (ObjectLifecycle objRes)
  => FilePath
  -> Linear.IO (Either CustodianError (BpfObject objRes linkRes 'Opened))
openObject path = Control.do
  r <- rawOpen path
  L.either
    (\e -> Control.pure (Left e))
    (Unsafe.toLinear (\h -> Control.pure (Right (BpfObjectOpened h))))
    r

-- | Load an opened object into the kernel.
--
-- Pre-condition:  the object is 'Opened'.
-- Post-condition: on success, the object is 'Loaded'.
loadObject
  :: (ObjectLifecycle objRes)
  => BpfObject objRes linkRes 'Opened
  %1 -> Linear.IO (Either CustodianError (BpfObject objRes linkRes 'Loaded))
loadObject (BpfObjectOpened h) = Control.do
  r <- rawLoad h
  L.either
    (\e -> Control.pure (Left e))
    (Unsafe.toLinear (\h' -> Control.pure (Right (BpfObjectLoaded h'))))
    r

-- | Attach a loaded object's program.
--
-- Pre-condition:  the object is 'Loaded'.
-- Post-condition: on success, the object is 'Attached', carrying both
--                 the object and the new link. On failure, the caller
--                 gets back a still-valid 'Loaded' object (not a bare
--                 error) and must tear it down through the ordinary
--                 linear API.
attachObject
  :: (ObjectLifecycle objRes, AttachDetach objRes linkRes)
  => BpfObject objRes linkRes 'Loaded
  %1 -> Linear.IO
          ( Either
              (CustodianError, BpfObject objRes linkRes 'Loaded)
              (BpfObject objRes linkRes 'Attached)
          )
attachObject (BpfObjectLoaded h) = Control.do
  r <- rawAttach h
  L.either
    (Unsafe.toLinear (\(h', e) -> Control.pure (Left (e, BpfObjectLoaded h'))))
    ( Unsafe.toLinear
        (\(h', link) -> Control.pure (Right (BpfObjectAttached h' link)))
    )
    r

-- | Types whose values must be torn down exactly once to release kernel
-- resources. Indexed by lifecycle state so the /shape/ of teardown is
-- chosen at compile time.
class Teardownable objRes linkRes (s :: LifecycleState) where
  teardown :: BpfObject objRes linkRes s %1 -> Linear.IO ()

instance (ObjectLifecycle objRes) => Teardownable objRes linkRes 'Loaded where
  teardown (BpfObjectLoaded h) = rawClose h

instance
  (ObjectLifecycle objRes, AttachDetach objRes linkRes)
  => Teardownable objRes linkRes 'Attached
  where
  -- Destroy the link, then close the object — two distinct linear
  -- resources, each consumed exactly once (vision doc §8, Risk 1b).
  teardown (BpfObjectAttached h link) = Control.do
    rawDetach link
    rawClose h

-- | A borrowed, scope-branded view of a live object's resource, handed
-- to the callback of 'withLoadedBpfObject'\/'withAttachedBpfObject'.
--
-- Two properties, both enforced by types:
--
--   * __Cannot be freed.__ There is no 'Teardownable' instance for
--     'Scope', and its wrapped resource is only reachable via
--     'scopeResource' (which yields a value, never a release action).
--     Freeing is the wrapper's job, done exactly once in 'bracket''s
--     release.
--   * __Cannot escape.__ The @br@ brand is introduced by the wrapper's
--     rank-2 callback type and unifies with nothing outside it, so a
--     'Scope' (or anything mentioning @br@, e.g. a 'Custodian.Map.LiveMap'
--     derived from it) cannot be returned or stashed. The object is
--     therefore provably still live for the whole callback.
newtype Scope br objRes = Scope objRes

-- | Read the borrowed resource out of a 'Scope' for the duration of the
-- callback. Yields a plain value, deliberately not a release capability.
scopeResource :: Scope br objRes -> objRes
scopeResource (Scope o) = o

-- | Run a 'Linear.IO' action as ordinary 'IO'. This is the exact
-- inverse of @linear-base@'s own @fromSystemIO@ (which is a plain
-- coercion) — 'Linear.IO' and 'GHCT.IO' share one representation — and
-- is the module-internal @toSystemIO@ @linear-base@ defines but does not
-- export. Confined to the @with*@ combinators below, which sit on the
-- linear\/exception boundary that 'Exception.bracket' guards.
runLinear :: Linear.IO a -> IO a
runLinear (Linear.IO f) = GHCT.IO (\s -> f s)

-- | open → load, closing nothing itself (there is nothing yet to close
-- on failure: 'rawOpen' returning 'Left' produced no resource, and
-- 'rawLoad' returning 'Left' consumed the handle it was given).
acquireLoaded
  :: forall objRes
   . (ObjectLifecycle objRes)
  => FilePath
  -> IO (Either CustodianError objRes)
acquireLoaded path = runLinear $ Control.do
  r1 <- rawOpen path
  L.either
    (\e -> Control.pure (Left e))
    (\h -> rawLoad h)
    r1

-- | Run a callback against a loaded (not-yet-attached) object, closing
-- the object exactly once whether the callback returns or throws.
--
-- The exactly-once guarantee is 'Exception.bracket''s, not a hand-rolled
-- handler: acquire yields the object resource, release is the /only/
-- site that closes it, and the callback is given a 'Scope' it cannot use
-- to close anything. There is consequently no path — normal, exceptional,
-- or asynchronous — on which the object is closed zero or two times.
withLoadedBpfObject
  :: forall objRes a
   . (ObjectLifecycle objRes)
  => FilePath
  -> (forall br. Scope br objRes -> IO a)
  -> IO (Either CustodianError a)
withLoadedBpfObject path use = do
  acquired <- acquireLoaded path
  case acquired of
    Left err -> pure (Left err)
    Right res ->
      fmap Right $
        Exception.bracket
          (pure res)
          (\o -> runLinear (rawClose o))
          (\o -> use (Scope o))

-- | open → load → attach, closing the object on a normal attach failure
-- (via the still-valid 'Loaded' object 'attachObject' hands back) so the
-- caller sees only a 'Left', never a leak.
acquireAttached
  :: forall objRes linkRes
   . (ObjectLifecycle objRes, AttachDetach objRes linkRes)
  => FilePath
  -> IO (Either CustodianError (objRes, linkRes))
acquireAttached path = runLinear $ Control.do
  r1 <- rawOpen path
  L.either
    (\e -> Control.pure (Left e))
    ( \h -> Control.do
        r2 <- rawLoad h
        L.either
          (\e -> Control.pure (Left e))
          ( \h2 -> Control.do
              r3 <- rawAttach h2
              L.either
                (Unsafe.toLinear (\(o, e) -> Control.do rawClose o; Control.pure (Left e)))
                (Unsafe.toLinear (\(o, l) -> Control.pure (Right (o, l))))
                r3
          )
          r2
    )
    r1

-- | Run a callback against a fully attached object, destroying the link
-- and closing the object exactly once — link first, then object,
-- matching 'Teardownable''s 'Attached' instance — on every exit path.
--
-- Both resources are acquired /before/ the callback runs and released
-- together in a single 'Exception.bracket' release, so there is no
-- window (not even an asynchronous one) in which the link is created but
-- not yet covered by cleanup: 'bracket' masks the release.
withAttachedBpfObject
  :: forall objRes linkRes a
   . (ObjectLifecycle objRes, AttachDetach objRes linkRes)
  => FilePath
  -> (forall br. Scope br objRes -> IO a)
  -> IO (Either CustodianError a)
withAttachedBpfObject path use = do
  acquired <- acquireAttached path
  case acquired of
    Left err -> pure (Left err)
    Right (obj, lnk) ->
      fmap Right $
        Exception.bracket
          (pure (obj, lnk))
          (\(o, l) -> runLinear (Control.do rawDetach l; rawClose o))
          (\(o, _l) -> use (Scope o))
