{-# LANGUAGE LinearTypes #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE QualifiedDo #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Custodian
  ( LifecycleState (..)
  , BpfObject
  , ObjectLifecycle (..)
  , AttachDetach (..)
  , openObject
  , loadObject
  , attachObject
  , Teardownable (..)
  , withLoadedBpfObject
  ) where

import Prelude.Linear hiding (IO)
import Prelude (IO, pure)
import qualified Control.Exception as Exception
import qualified Control.Functor.Linear as Control
import qualified System.IO.Linear as Linear
import qualified Unsafe.Linear as Unsafe
import Custodian.Errors (CustodianError)

-- | The three lifecycle stages a 'BpfObject' can occupy (vision doc §3.2).
data LifecycleState = Opened | Loaded | Attached

-- | A handle to a BPF object, indexed by its current lifecycle stage,
-- and parameterized over the underlying backend's resource types --
-- 'objRes' for the object handle, 'linkRes' for the attach-produced
-- link handle. This is what lets the SAME lifecycle functions below run
-- against either the mock backend ('Custodian.Mock') or the real
-- 'Custodian.Raw' backend (vision doc §2.2, Dependency Inversion) --
-- not two parallel copies of this module.
--
-- 'Attached' carries BOTH resources, not just one: in the real API,
-- attaching produces a genuinely separate kernel resource (a
-- @bpf_link@) that must be destroyed independently of, and before,
-- closing the object itself (see 'Teardownable''s 'Attached' instance).
data BpfObject objRes linkRes (s :: LifecycleState) where
  BpfObjectOpened :: objRes -> BpfObject objRes linkRes 'Opened
  BpfObjectLoaded :: objRes -> BpfObject objRes linkRes 'Loaded
  BpfObjectAttached :: objRes -> linkRes -> BpfObject objRes linkRes 'Attached

-- | Capability: open, load, and close a BPF object. Deliberately narrow
-- (Interface Segregation, §2.2) -- knows nothing about attach/detach or
-- maps.
class ObjectLifecycle objRes where
  rawOpen :: FilePath -> Linear.IO (Either CustodianError objRes)
  rawLoad :: objRes %1 -> Linear.IO (Either CustodianError objRes)
  rawClose :: objRes %1 -> Linear.IO ()

-- | Capability: attach a loaded object's program(s), producing a link,
-- and detach (destroy) that link. 'rawAttach' returns the object
-- resource back in BOTH branches -- attaching does not consume or
-- invalidate the object itself (the real @bpf_object__load@d object
-- stays alive whether or not attach succeeds; only the link is a
-- separate, independently-destroyable resource). Returning 'objRes'
-- even on failure matters: without it, a failed attach would silently
-- leak the underlying object resource with no way for the caller to
-- close it -- exactly the bug this signature was changed to rule out.
class AttachDetach objRes linkRes | linkRes -> objRes where
  rawAttach :: objRes %1 -> Linear.IO (Either (objRes, CustodianError) (objRes, linkRes))
  rawDetach :: linkRes %1 -> Linear.IO ()

-- | Open a BPF object file.
--
-- Pre-condition:  none -- this is the lifecycle's entry point.
-- Post-condition: on success, returns a 'BpfObject' in the 'Opened' state.
openObject
  :: ObjectLifecycle objRes
  => FilePath
  -> Linear.IO (Either CustodianError (BpfObject objRes linkRes 'Opened))
openObject path = Control.do
  r <- rawOpen path
  either
    (\e -> Control.pure (Left e))
    -- Same justification as CustodianError's 'Movable' instance: this
    -- lambda uses 'h' exactly once, genuinely linear in spirit, but
    -- GHC's inference can't verify a constructor reconstruction inside
    -- a lambda passed to a higher-order function like 'either' (same
    -- documented-experimental case-inference limitation as before).
    (Unsafe.toLinear (\h -> Control.pure (Right (BpfObjectOpened h))))
    r

-- | Load a BPF object into the kernel.
--
-- Pre-condition:  the 'BpfObject' must be in the 'Opened' state.
-- Post-condition: on success, the returned 'BpfObject' is in the 'Loaded' state.
loadObject
  :: ObjectLifecycle objRes
  => BpfObject objRes linkRes 'Opened %1
  -> Linear.IO (Either CustodianError (BpfObject objRes linkRes 'Loaded))
loadObject obj = case obj of
  BpfObjectOpened h -> Control.do
    r <- rawLoad h
    either
      (\e -> Control.pure (Left e))
      (Unsafe.toLinear (\h' -> Control.pure (Right (BpfObjectLoaded h'))))
      r

-- | Attach a loaded BPF object's program(s).
--
-- Pre-condition:  the 'BpfObject' must be in the 'Loaded' state.
-- Post-condition: on success, the returned 'BpfObject' is in the
--                 'Attached' state, carrying both the original object
--                 resource and the newly-produced link resource. On
--                 failure, the caller gets back a still-valid 'Loaded'
--                 object (not just a bare error) -- attach failing does
--                 not invalidate the underlying object, so the caller
--                 can (and must) still 'teardown' it through the normal
--                 linear-typed API. Returning only the error here, as
--                 an earlier version of this function did, silently
--                 leaked the object resource on every attach failure.
attachObject
  :: (ObjectLifecycle objRes, AttachDetach objRes linkRes)
  => BpfObject objRes linkRes 'Loaded %1
  -> Linear.IO (Either (CustodianError, BpfObject objRes linkRes 'Loaded) (BpfObject objRes linkRes 'Attached))
attachObject obj = case obj of
  BpfObjectLoaded h -> Control.do
    r <- rawAttach h
    either
      (Unsafe.toLinear (\pair -> case pair of (h', e) -> Control.pure (Left (e, BpfObjectLoaded h'))))
      (Unsafe.toLinear (\pair -> case pair of (h', link) -> Control.pure (Right (BpfObjectAttached h' link))))
      r

-- | Types whose values must be torn down exactly once to release
-- kernel resources.
class Teardownable objRes linkRes (s :: LifecycleState) where
  teardown :: BpfObject objRes linkRes s %1 -> Linear.IO ()

instance ObjectLifecycle objRes => Teardownable objRes linkRes 'Loaded where
  teardown obj = case obj of
    BpfObjectLoaded h -> rawClose h

instance (ObjectLifecycle objRes, AttachDetach objRes linkRes) => Teardownable objRes linkRes 'Attached where
  -- Destroy the link, then close the object -- two distinct linear
  -- resources, each consumed exactly once, sequenced via
  -- Control.Functor.Linear's do-notation (vision doc §8 Risk 1b,
  -- option (a) -- Prelude's own do-notation cannot typecheck this).
  teardown obj = case obj of
    BpfObjectAttached h link -> Control.do
      rawDetach link
      rawClose h

-- | Split a captured resource off a loaded object via 'dup2', so a
-- copy can be closed over by an exception handler *before* the
-- (still-intact) object is handed to a genuinely opaque callback. Same
-- 'Unsafe.toLinear' justification as elsewhere in this module: a
-- single-use reconstruction, safe in spirit, outside what GHC's
-- case/pattern inference for linear equations can verify.
splitLoaded
  :: Dupable objRes
  => BpfObject objRes linkRes 'Loaded %1
  -> (objRes, BpfObject objRes linkRes 'Loaded)
splitLoaded = Unsafe.toLinear $ \obj -> case obj of
  BpfObjectLoaded h -> case dup2 h of
    (h1, h2) -> (h1, BpfObjectLoaded h2)

-- | Run a 'Linear.IO' action producing '()' as a plain, ordinary 'IO'
-- action -- the boundary-crossing 'withLoadedBpfObject' needs to call
-- 'rawClose' from inside 'Control.Exception''s (non-linear-aware)
-- exception handling.
runLinearUnit :: Linear.IO () -> IO ()
runLinearUnit action = Linear.withLinearIO (Control.do action; Control.pure (Ur ()))

-- | Run a callback against a loaded (not yet attached) BPF object,
-- guaranteeing the object is closed even if the callback throws.
--
-- On the *normal* path, the callback is required by linearity to
-- consume the handle (typically via 'teardown') before returning --
-- the type checker enforces that, same as everywhere else in this
-- module. On the *exception* path, a duplicated copy of the object
-- resource is captured before the callback runs (via 'splitLoaded')
-- and closed by a 'Control.Exception.onException' handler if the
-- callback throws -- this is the *only* place in this module that
-- reaches around linear discipline, and it exists solely to cover the
-- gap linearity leaves under exceptions (vision doc §3.4). It does not
-- weaken the compile-time guarantee for any path that completes
-- normally. 'Exception.mask' guards the narrow window between
-- capturing the resource and the exception handler actually being
-- registered, matching how 'bracket' itself is implemented internally.
--
-- Deliberately does NOT attempt kernel-side "is a link still live"
-- discovery: real @libbpf@ has no such query on a bare object/program
-- pointer, only a system-wide link enumeration with its own real
-- correctness problems (raw-fd cleanup, TOCTOU, privilege
-- requirements) -- this was verified against the actual installed
-- header, not assumed. 'withLoadedBpfObject' sidesteps the need for it
-- entirely by never letting the callback attach in the first place.
-- The attached case ('withAttachedBpfObject') is a deliberately
-- separate, not-yet-implemented follow-up: it tracks its own progress
-- through the attach step instead of asking the kernel after the fact.
withLoadedBpfObject
  :: forall objRes linkRes a
   . (ObjectLifecycle objRes, Dupable objRes)
  => FilePath
  -> (BpfObject objRes linkRes 'Loaded %1 -> IO (Ur a))
  -> IO (Either CustodianError a)
withLoadedBpfObject path callback = do
  step1 <-
    Linear.withLinearIO $ Control.do
      r1 <- (openObject path :: Linear.IO (Either CustodianError (BpfObject objRes linkRes 'Opened)))
      either
        (Unsafe.toLinear (\e -> Control.pure (Ur (Left e))))
        ( \obj1 -> Control.do
            r2 <- loadObject obj1
            either
              (Unsafe.toLinear (\e -> Control.pure (Ur (Left e))))
              (Unsafe.toLinear (\obj2 -> Control.pure (Ur (Right obj2))))
              r2
        )
        r1
  case step1 of
    Left err -> pure (Left err)
    Right loadedObj -> Exception.mask (\restore -> do
      let (capturedRes, calleeObj) = splitLoaded loadedObj
      Ur result <-
        restore (callback calleeObj)
          `Exception.onException` runLinearUnit (rawClose capturedRes)
      pure (Right result))
