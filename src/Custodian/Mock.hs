{-# LANGUAGE LinearTypes #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE QualifiedDo #-}
module Custodian.Mock
  ( MockHandle
  , mockOpen
  , mockLoad
  , mockAttach
  , mockTeardown
  ) where

import Prelude.Linear
import qualified Control.Functor.Linear as Control
import qualified System.IO.Linear as Linear
import Custodian.Errors (CustodianError (..))

-- | Opaque stand-in for a live kernel-side @bpf_object@ pointer. Carries
-- just an identifying tag (Phase 1 mock; no real kernel resource exists
-- yet). Unlike our first attempt, this is /not/ backed by an 'IORef':
-- linear-base's own IORef operations are explicitly unrestricted (they'd
-- let a linear value escape its scope), which defeats the point. The
-- "can't tear down twice" guarantee here comes entirely from linear
-- typing itself -- once 'mockTeardown' consumes a 'MockHandle', there is
-- no value left to pass anywhere else.
newtype MockHandle = MockHandle Int

mockOpen :: FilePath -> Linear.IO (Either CustodianError MockHandle)
mockOpen _path = Control.pure (Right (MockHandle 0))

mockLoad :: MockHandle %1 -> Linear.IO (Either CustodianError MockHandle)
mockLoad (MockHandle tag) = Control.pure (Right (MockHandle tag))

mockAttach :: MockHandle %1 -> Linear.IO (Either CustodianError MockHandle)
mockAttach (MockHandle tag) = Control.pure (Right (MockHandle tag))

mockTeardown :: MockHandle %1 -> Linear.IO ()
mockTeardown (MockHandle tag) = consume tag `lseq` Control.pure ()
