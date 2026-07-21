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
import Custodian
  ( ObjectLifecycle (..)
  , AttachDetach (..)
  , Teardownable (..)
  , withLoadedBpfObject
  , withAttachedBpfObject
  )
import Custodian.Errors (CustodianError (..))
import Hedgehog
import Test.Tasty
import Test.Tasty.Hedgehog (testProperty)

--------------------------------------------------------------------------------
-- withLoadedBpfObject tests (unchanged from before)
--------------------------------------------------------------------------------

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

prop_withLoadedBpfObject_closesOnException :: Property
prop_withLoadedBpfObject_closesOnException = property $ do
  evalIO (writeIORef globalOpenFlag False)
  result <-
    evalIO $
      try @SomeException $
        withLoadedBpfObject @TestHandle @() "irrelevant-path" $
          Unsafe.toLinear (\_obj -> throwIO (userError "simulated failure mid-callback"))
  case result of
    Left _ -> success
    Right _ -> annotate "expected the simulated exception to propagate" >> failure
  stillOpen <- evalIO (readIORef globalOpenFlag)
  stillOpen === False

prop_withLoadedBpfObject_normalPathTearsDownExactlyOnce :: Property
prop_withLoadedBpfObject_normalPathTearsDownExactlyOnce = property $ do
  evalIO (writeIORef globalOpenFlag False)
  result <-
    evalIO $
      withLoadedBpfObject @TestHandle @() "irrelevant-path" $
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

--------------------------------------------------------------------------------
-- withAttachedBpfObject tests
--------------------------------------------------------------------------------

data TestObjHandle = TestObjHandle
data TestLinkHandle = TestLinkHandle

{-# NOINLINE globalObjOpenFlag #-}
globalObjOpenFlag :: IORef Bool
globalObjOpenFlag = unsafePerformIO (newIORef False)

{-# NOINLINE globalLinkOpenFlag #-}
globalLinkOpenFlag :: IORef Bool
globalLinkOpenFlag = unsafePerformIO (newIORef False)

-- | Toggled per-property to exercise the "attach fails normally, no
-- exception at all" path -- the exact scenario the attachObject leak
-- fix was for.
{-# NOINLINE globalAttachShouldFail #-}
globalAttachShouldFail :: IORef Bool
globalAttachShouldFail = unsafePerformIO (newIORef False)

instance Consumable TestObjHandle where
  consume = Unsafe.toLinear (\TestObjHandle -> ())

instance Dupable TestObjHandle where
  dup2 = Unsafe.toLinear (\TestObjHandle -> (TestObjHandle, TestObjHandle))

instance Consumable TestLinkHandle where
  consume = Unsafe.toLinear (\TestLinkHandle -> ())

instance Dupable TestLinkHandle where
  dup2 = Unsafe.toLinear (\TestLinkHandle -> (TestLinkHandle, TestLinkHandle))

instance ObjectLifecycle TestObjHandle where
  rawOpen _path = Linear.fromSystemIO (do
    writeIORef globalObjOpenFlag True
    pure (Right TestObjHandle))
  rawLoad h = Control.pure (Right h)
  rawClose h = consume h `lseq` Linear.fromSystemIO (writeIORef globalObjOpenFlag False)

instance AttachDetach TestObjHandle TestLinkHandle where
  rawAttach = Unsafe.toLinear (\h -> Linear.fromSystemIO (do
    shouldFail <- readIORef globalAttachShouldFail
    if shouldFail
      then pure (Left (h, MockFailure "simulated attach failure"))
      else do
        writeIORef globalLinkOpenFlag True
        pure (Right (h, TestLinkHandle))))
  rawDetach link = consume link `lseq` Linear.fromSystemIO (writeIORef globalLinkOpenFlag False)

resetFlags :: IO ()
resetFlags = do
  writeIORef globalObjOpenFlag False
  writeIORef globalLinkOpenFlag False
  writeIORef globalAttachShouldFail False

-- | Exception fires after a real attach succeeded -- both the link and
-- the object must be cleaned up.
prop_withAttachedBpfObject_closesOnExceptionDuringCallback :: Property
prop_withAttachedBpfObject_closesOnExceptionDuringCallback = property $ do
  evalIO resetFlags
  result <-
    evalIO $
      try @SomeException $
        withAttachedBpfObject @TestObjHandle @TestLinkHandle "irrelevant-path" $
          Unsafe.toLinear (\_obj -> throwIO (userError "simulated failure mid-callback"))
  case result of
    Left _ -> success
    Right _ -> annotate "expected the simulated exception to propagate" >> failure
  objStillOpen <- evalIO (readIORef globalObjOpenFlag)
  linkStillOpen <- evalIO (readIORef globalLinkOpenFlag)
  objStillOpen === False
  linkStillOpen === False

-- | Normal path: the callback's own teardown does the work, no
-- double-close from withAttachedBpfObject's own exception handler.
prop_withAttachedBpfObject_normalPathTearsDownExactlyOnce :: Property
prop_withAttachedBpfObject_normalPathTearsDownExactlyOnce = property $ do
  evalIO resetFlags
  result <-
    evalIO $
      withAttachedBpfObject @TestObjHandle @TestLinkHandle "irrelevant-path" $
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
  objStillOpen <- evalIO (readIORef globalObjOpenFlag)
  linkStillOpen <- evalIO (readIORef globalLinkOpenFlag)
  objStillOpen === False
  linkStillOpen === False

-- | Attach fails normally (no exception at all, just a genuine Left) --
-- the exact scenario the attachObject leak fix exists for. The object
-- must still end up closed, and the callback must never run.
prop_withAttachedBpfObject_attachFailureClosesObjectNoException :: Property
prop_withAttachedBpfObject_attachFailureClosesObjectNoException = property $ do
  evalIO resetFlags
  evalIO (writeIORef globalAttachShouldFail True)
  result <-
    evalIO $
      withAttachedBpfObject @TestObjHandle @TestLinkHandle "irrelevant-path" $
        Unsafe.toLinear (\_obj -> pure (Ur ()) :: IO (Ur ()))
  case result of
    Left _ -> success
    Right _ -> annotate "expected the simulated attach failure to propagate as Left" >> failure
  objStillOpen <- evalIO (readIORef globalObjOpenFlag)
  objStillOpen === False

main :: IO ()
main =
  defaultMain $
    testGroup
      "emergencyClose"
      [ testGroup
          "withLoadedBpfObject"
          [ testProperty "closes the resource if the callback throws" prop_withLoadedBpfObject_closesOnException
          , testProperty "normal path tears down exactly once, no double-close" prop_withLoadedBpfObject_normalPathTearsDownExactlyOnce
          ]
      , testGroup
          "withAttachedBpfObject"
          [ testProperty "closes link and object if the callback throws" prop_withAttachedBpfObject_closesOnExceptionDuringCallback
          , testProperty "normal path tears down exactly once, no double-close" prop_withAttachedBpfObject_normalPathTearsDownExactlyOnce
          , testProperty "attach failure (no exception) still closes the object" prop_withAttachedBpfObject_attachFailureClosesObjectNoException
          ]
      ]
