{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}

-- | End-to-end tests against a real kernel (vision doc §9, Risk #4).
--
-- These exercise the /live/ backend: a genuine @bpf_object@ opened,
-- loaded, attached, and torn down, with the typed map API run against
-- the kernel-created @counters@ map. They require @CAP_BPF@ (in practice,
-- root) and the compiled @hello.bpf.o@ fixture, so on an unprivileged box
-- they print @SKIP@ and succeed — the point being that this file
-- compiles and links against @libbpf@ everywhere, and actually verifies
-- resource behaviour only where a privileged runner exists.
module Main (main) where

import Control.Exception (SomeException, catch, throwIO)
import Control.Monad (unless)
import Data.Word (Word32, Word64)
import System.Directory (doesFileExist)
import System.Exit (exitFailure, exitSuccess)
import System.Posix.User (getEffectiveUserID)

import Custodian.Core
  ( scopeResource
  , withAttachedBpfObject
  , withLoadedBpfObject
  )
import Custodian.Errors (CustodianError (..))
import Custodian.Live (LiveObj)
import Custodian.Map
  ( LiveMap
  , MapSyscalls
  , MapType (HashMap)
  , deleteMap
  , mapKeys
  , readMap
  , withMap
  , writeMap
  )

fixture :: FilePath
fixture = "hello.bpf.o"

main :: IO ()
main = do
  uid <- getEffectiveUserID
  haveFixture <- doesFileExist fixture
  if uid /= 0 || not haveFixture
    then do
      putStrLn "SKIP: live tests require root/CAP_BPF and a compiled hello.bpf.o"
      exitSuccess
    else runLiveTests

runLiveTests :: IO ()
runLiveTests = do
  -- 1. Loaded-object lifecycle + map round trip. withMap and
  -- withLoadedBpfObject each wrap in Either, so flatten at each layer.
  r1 <-
    withLoadedBpfObject @LiveObj fixture $ \scope -> do
      inner <-
        withMap @LiveObj @'HashMap @Word32 @Word64
          (scopeResource scope)
          "counters"
          mapRoundTrip
      pure (flatten inner)
  -- 2. Attached-object lifecycle (detach-before-close is the wrapper's job).
  r2 <-
    withAttachedBpfObject @LiveObj fixture $ \_scope -> pure ()
  -- 3. Exception path: a throwing callback must propagate, while the
  -- bracket still detaches every link and closes the object (§3.4/§9).
  threw <-
    ( withAttachedBpfObject @LiveObj
        fixture
        (\_scope -> throwIO (userError "boom") :: IO ())
        >> pure False
    )
      `catch` \(_ :: SomeException) -> pure True
  check "loaded + map round trip" (flatten r1 == Right ())
  check "attach/detach lifecycle" (r2 == Right ())
  check "exception propagates from attached scope" threw
  putStrLn "live tests: OK"

-- | Write, read back, enumerate, delete, and confirm-gone against a real
-- kernel map. Returns @Right ()@ iff every step behaved.
mapRoundTrip
  :: (MapSyscalls sys)
  => LiveMap sys br 'HashMap Word32 Word64
  -> IO (Either CustodianError ())
mapRoundTrip m = do
  _ <- writeMap m (42 :: Word32) (100 :: Word64)
  readback <- readMap m 42
  case readback of
    Left e -> pure (Left e)
    Right (Just 100) -> do
      keysResult <- mapKeys m
      case keysResult of
        Left e -> pure (Left e)
        Right keys
          | 42 `elem` keys -> do
              deleted <- deleteMap m 42
              case deleted of
                Left e -> pure (Left e)
                Right () -> do
                  after <- readMap m 42
                  pure $ case after of
                    Right Nothing -> Right ()
                    Right (Just _) -> Left (LibbpfFailure "key still present after delete")
                    Left e -> Left e
          | otherwise -> pure (Left (LibbpfFailure "written key absent from mapKeys"))
    Right other ->
      pure (Left (LibbpfFailure ("unexpected readback: " ++ show other)))

flatten
  :: Either CustodianError (Either CustodianError a) -> Either CustodianError a
flatten = either Left id

check :: String -> Bool -> IO ()
check name ok =
  unless ok $ do
    putStrLn ("FAILED: " ++ name)
    exitFailure
