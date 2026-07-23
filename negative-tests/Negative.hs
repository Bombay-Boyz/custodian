module Main (main) where

import Prelude
import qualified Control.Functor.Linear as Control
import qualified System.IO.Linear as Linear
import Data.IORef (newIORef, writeIORef)
import Custodian (BpfObject, LifecycleState (..), Teardownable (..))
import Custodian.Mock (MockHandle)
import Custodian.Map (withMap)

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
badDoubleTeardown :: BpfObject MockHandle MockHandle 'Attached %1 -> Linear.IO ()
badDoubleTeardown obj = Control.do
  teardown obj
  teardown obj

-- | THIS FUNCTION MUST NOT COMPILE.
--
-- Attempts to smuggle a 'LiveMap' out of the scope of the callback that
-- produced it, by stashing it in an 'IORef' declared outside
-- 'withMap''s call. 'withMap''s rank-2 @forall br.@ brand exists
-- specifically to rule this out (vision doc §2.5\/§3.5, the same
-- @runST@\/@STRef@ escape-prevention trick) -- the brand can never
-- unify with anything outside the callback, so the 'IORef' (whose type
-- doesn't itself quantify over @br@) cannot hold a value of that type.
--
-- Expected failure: a type error naming an escaping/ambiguous type
-- variable (GHC typically phrases this as the skolem/rigid type
-- variable "would escape its scope"), not a normal type mismatch.
badMapEscape :: MockHandle -> IO ()
badMapEscape h = do
  ref <- newIORef Nothing
  _ <- withMap h "somemap" (\m -> writeIORef ref (Just m))
  pure ()

main :: IO ()
main = putStrLn "this file must fail to compile -- see badDoubleTeardown, badMapEscape"
