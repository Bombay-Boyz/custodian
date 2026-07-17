{-# LANGUAGE LinearTypes #-}
{-# LANGUAGE NoImplicitPrelude #-}
{-# LANGUAGE QualifiedDo #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE KindSignatures #-}
module Custodian
  ( LifecycleState (..)
  , BpfObject
  , openObject
  , loadObject
  , attachObject
  , Teardownable (..)
  ) where

import Prelude.Linear
import qualified Control.Functor.Linear as Control
import qualified System.IO.Linear as Linear
import Custodian.Errors (CustodianError (..))
import Custodian.Mock (MockHandle, mockOpen, mockLoad, mockAttach, mockTeardown)

-- | The three lifecycle stages a 'BpfObject' can occupy (vision doc §3.2).
data LifecycleState = Opened | Loaded | Attached

-- | A handle to a (mock, for now) kernel-side BPF object, indexed by its
-- current lifecycle stage.
data BpfObject (s :: LifecycleState) = BpfObject MockHandle

-- | Open a BPF object file.
openObject :: FilePath -> Linear.IO (Either CustodianError (BpfObject 'Opened))
openObject path = Control.do
  result <- mockOpen path
  case result of
    Left err -> Control.pure (Left err)
    Right h -> Control.pure (Right (BpfObject h))

-- | Load a BPF object into the kernel.
loadObject :: BpfObject 'Opened %1 -> Linear.IO (Either CustodianError (BpfObject 'Loaded))
loadObject (BpfObject h) = Control.do
  result <- mockLoad h
  case result of
    Left err -> Control.pure (Left err)
    Right h' -> Control.pure (Right (BpfObject h'))

-- | Attach a loaded BPF object's program(s).
attachObject :: BpfObject 'Loaded %1 -> Linear.IO (Either CustodianError (BpfObject 'Attached))
attachObject (BpfObject h) = Control.do
  result <- mockAttach h
  case result of
    Left err -> Control.pure (Left err)
    Right h' -> Control.pure (Right (BpfObject h'))

-- | Types whose values must be torn down exactly once to release
-- (mock, for now) kernel resources.
class Teardownable (s :: LifecycleState) where
  teardown :: BpfObject s %1 -> Linear.IO ()

instance Teardownable 'Loaded where
  teardown (BpfObject h) = mockTeardown h

instance Teardownable 'Attached where
  teardown (BpfObject h) = mockTeardown h
