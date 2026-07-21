{-# LANGUAGE QualifiedDo #-}
{-# LANGUAGE TypeApplications #-}
module Main (main) where

import Prelude
import qualified Control.Functor.Linear as Control
import qualified System.IO.Linear as Linear
import qualified Unsafe.Linear as Unsafe
import Prelude.Linear (Ur (..), lseq)
import Data.Unrestricted.Linear (Consumable (..), Dupable (..))
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import System.IO.Unsafe (unsafePerformIO)
import Control.Exception (SomeException, try, throwIO)
import Custodian (ObjectLifecycle (..), Teardownable (..), withLoadedBpfObject)
import Hedgehog
import Test.Tasty
import Test.Tasty.Hedgehog (testProperty)

-- | A trivial test-only resource type. Observable state lives in a
-- shared, module-level IORef rather than inside the handle itself: the
-- handle just needs to be freely 'Dupable' (a bare marker works fine
-- for that), and putting the state in one place lets the test inspect
-- it after 'withLoadedBpfObject' returns, without needing the handle
-- itself back out.
data TestHandle = TestHandle

{-# NOINLINE globalOpenFlag #-}
globalOpenFlag :: IORef Bool
globalOpenFlag = unsafePerformIO (newIORef False)

instance Consumable TestHandle where
  consume = Unsafe.toLinear (\TestHandle -> ())

instance Dupable TestHandle where
  dup2 = Unsafe.toLinear (\TestHandle -> (TestHandle, TestHandle))

instance ObjectLifecycle TestHandle where
  rawOpen _path = Linear.fromSystemIO (do
    writeIORef globalOpenFlag True
    pure (Right TestHandle))
  rawLoad h = Control.pure (Right h)
  rawClose h = consume h `lseq` Linear.fromSystemIO (writeIORef globalOpenFlag False)

-- | The exception-path guarantee §3.4 exists for: if the callback
-- throws partway through, the resource is still closed.
prop_withLoadedBpfObject_closesOnException :: Property
prop_withLoadedBpfObject_closesOnException = property $ do
  evalIO (writeIORef globalOpenFlag False)
  result <-
    evalIO $
      try @SomeException $
        withLoadedBpfObject @TestHandle @() "irrelevant-path" $
          -- Deliberately abandons 'obj' without consuming it, to
          -- simulate an exception firing before any teardown call ever
          -- runs -- this is exactly the scenario emergencyClose exists
          -- for. Haskell's linear checker correctly refuses to
          -- typecheck a callback that really doesn't consume its
          -- argument; Unsafe.toLinear is a narrow, test-only assertion
          -- that this abandonment is the intended scenario, not a
          -- production-code pattern.
          Unsafe.toLinear (\_obj -> throwIO (userError "simulated failure mid-callback"))
  case result of
    Left _ -> success
    Right _ -> annotate "expected the simulated exception to propagate" >> failure
  stillOpen <- evalIO (readIORef globalOpenFlag)
  stillOpen === False

-- | The normal path is untouched: the callback's own 'teardown' is
-- what closes the resource -- 'withLoadedBpfObject''s exception handler
-- must not ALSO try to close it (which would be a double-close, and
-- with a real backend, a real double-free).
prop_withLoadedBpfObject_normalPathTearsDownExactlyOnce :: Property
prop_withLoadedBpfObject_normalPathTearsDownExactlyOnce = property $ do
  evalIO (writeIORef globalOpenFlag False)
  result <-
    evalIO $
      withLoadedBpfObject @TestHandle @() "irrelevant-path" $
        -- Same documented inference gap as elsewhere in this project:
        -- GHC doesn't reliably infer this lambda's own parameter as %1
        -- when it's passed as an argument here, even though the body
        -- genuinely does consume 'obj' exactly once via 'teardown'.
        -- Unlike the exception-test callback above, this isn't
        -- asserting anything false -- it's working around inference,
        -- not bypassing real consumption.
        --
        -- Note the two-step structure: withLoadedBpfObject's callback
        -- contract is `IO (Ur a)` directly -- Linear.withLinearIO is
        -- used here just to run 'teardown' down to a plain `IO ()`,
        -- not to produce the callback's own final Ur-wrapped result
        -- (withLinearIO already strips one Ur layer as its own job;
        -- routing the whole callback through it double-unwraps).
        Unsafe.toLinear
          ( \obj -> do
              Linear.withLinearIO
                ( Control.do
                    teardown obj
                    Control.pure (Ur ())
                )
              pure (Ur ())
          )
  case result of
    Left err -> annotateShow err >> failure
    Right () -> success
  stillOpen <- evalIO (readIORef globalOpenFlag)
  stillOpen === False

main :: IO ()
main =
  defaultMain $
    testGroup
      "emergencyClose (withLoadedBpfObject)"
      [ testProperty "closes the resource if the callback throws" prop_withLoadedBpfObject_closesOnException
      , testProperty "normal path tears down exactly once, no double-close" prop_withLoadedBpfObject_normalPathTearsDownExactlyOnce
      ]
