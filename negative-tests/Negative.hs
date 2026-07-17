module Main (main) where

import Prelude
import qualified Control.Functor.Linear as Control
import qualified System.IO.Linear as Linear
import Custodian (BpfObject, LifecycleState (..), Teardownable (..))

-- | THIS MODULE MUST NOT COMPILE.
--
-- 'obj' is consumed by the first 'teardown' call. Passing it again to a
-- second 'teardown' reuses an already-consumed linear value, which
-- linear typing must reject at compile time -- this is the exact
-- "double free" class of bug the whole 'BpfObject' design exists to rule
-- out (vision doc §1, §3.3). If this file ever compiles, that guarantee
-- has silently broken.
--
-- Expected failure: a linearity error naming 'obj' (multiplicity
-- mismatch, or "variable used more than once"), not a normal type error.
badDoubleTeardown :: BpfObject 'Attached %1 -> Linear.IO ()
badDoubleTeardown obj = Control.do
  teardown obj
  teardown obj

main :: IO ()
main = putStrLn "this file must fail to compile -- see badDoubleTeardown"
