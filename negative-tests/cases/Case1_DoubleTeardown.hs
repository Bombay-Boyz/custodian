{-# LANGUAGE LinearTypes #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE QualifiedDo #-}
module Case1_DoubleTeardown where
import Custodian.Core (BpfObject, LifecycleState (Loaded), teardown)
import Custodian.Mock (MockHandle)
import qualified System.IO.Linear as Linear
import qualified Control.Functor.Linear as Control

-- MUST NOT COMPILE: `obj` is linear and consumed twice.
bad :: BpfObject MockHandle MockHandle 'Loaded %1 -> Linear.IO ()
bad obj = Control.do
  teardown obj
  teardown obj
