{-# LANGUAGE LinearTypes #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE QualifiedDo #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE GADTs #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
{-# LANGUAGE FunctionalDependencies #-}
module Custodian
  ( LifecycleState (..)
  , BpfObject
  , ObjectLifecycle (..)
  , AttachDetach (..)
  , openObject
  , loadObject
  , attachObject
  , Teardownable (..)
  ) where

import Prelude.Linear
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
-- resource back alongside the new link resource -- attaching does not
-- consume or invalidate the object itself (the real @bpf_object__load@d
-- object stays alive while attached; only the link is a separate,
-- independently-destroyable resource).
class AttachDetach objRes linkRes | linkRes -> objRes where
  rawAttach :: objRes %1 -> Linear.IO (Either CustodianError (objRes, linkRes))
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
--                 resource and the newly-produced link resource.
attachObject
  :: (ObjectLifecycle objRes, AttachDetach objRes linkRes)
  => BpfObject objRes linkRes 'Loaded %1
  -> Linear.IO (Either CustodianError (BpfObject objRes linkRes 'Attached))
attachObject obj = case obj of
  BpfObjectLoaded h -> Control.do
    r <- rawAttach h
    either
      (\e -> Control.pure (Left e))
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
