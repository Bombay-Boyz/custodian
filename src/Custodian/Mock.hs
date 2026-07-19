{-# LANGUAGE LinearTypes #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE QualifiedDo #-}
{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE FlexibleInstances #-}
module Custodian.Mock
  ( MockHandle
  , mockOpen
  , mockLoad
  , mockTeardown
  ) where

import Prelude.Linear
import qualified Control.Functor.Linear as Control
import qualified System.IO.Linear as Linear
import qualified Unsafe.Linear as Unsafe
import Custodian (ObjectLifecycle (..), AttachDetach (..))
import Custodian.Errors (CustodianError (..))

-- | Opaque stand-in for a live kernel-side @bpf_object@ pointer. Carries
-- just an identifying tag (Phase 1 mock; no real kernel resource exists).
-- Not backed by an 'IORef': linear-base's own IORef operations are
-- explicitly unrestricted, which would let a linear value escape its
-- scope. The "can't tear down twice" guarantee comes entirely from
-- linear typing itself.
newtype MockHandle = MockHandle Int

-- | Required superclass of 'Dupable' below.
instance Consumable MockHandle where
  consume = Unsafe.toLinear (\(MockHandle tag) -> consume tag)

-- | Splitting a 'MockHandle' into two independent copies is safe here
-- specifically because there is no real resource behind it (Phase 1
-- mock only) -- 'rawAttach' below uses this to hand back both the
-- still-live "object" token and a new "link" token from one input,
-- mirroring how the real backend's attach produces a genuinely separate
-- kernel resource without invalidating the object.
instance Dupable MockHandle where
  dup2 = Unsafe.toLinear (\(MockHandle tag) -> (MockHandle tag, MockHandle tag))

mockOpen :: FilePath -> Linear.IO (Either CustodianError MockHandle)
mockOpen _path = Control.pure (Right (MockHandle 0))

mockLoad :: MockHandle %1 -> Linear.IO (Either CustodianError MockHandle)
mockLoad (MockHandle tag) = Control.pure (Right (MockHandle tag))

mockTeardown :: MockHandle %1 -> Linear.IO ()
mockTeardown (MockHandle tag) = consume tag `lseq` Control.pure ()

instance ObjectLifecycle MockHandle where
  rawOpen = mockOpen
  rawLoad = mockLoad
  rawClose = mockTeardown

instance AttachDetach MockHandle MockHandle where
  rawAttach h = case dup2 h of
    (hObj, hLink) -> Control.pure (Right (hObj, hLink))
  rawDetach = mockTeardown
