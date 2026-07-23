{-# LANGUAGE DataKinds #-}
{-# LANGUAGE QualifiedDo #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE ScopedTypeVariables #-}
module Main (main) where

import Prelude hiding (either)
import qualified Control.Functor.Linear as Control
import qualified System.IO.Linear as Linear
import Prelude.Linear (Ur (..), either, move)
import qualified Unsafe.Linear as Unsafe
import Foreign.Ptr (Ptr)
import Data.Word (Word32, Word64)
import Custodian (BpfObject, LifecycleState (..), openObject, loadObject, attachObject, teardown, withLoadedBpfObject, withAttachedBpfObject, borrowObjRes)
import Custodian.Errors (CustodianError (..))
import Custodian.Map (LiveMap, MapType (..), withMap, readMap, writeMap, deleteMap, mapKeys)
import Custodian.Raw (CBpfObject, CBpfLink)
import Custodian.Live ()
import System.Posix.User (getEffectiveUserID)
import System.Process (callProcess)
import System.Exit (exitFailure)

-- | Pinned to the real backend -- this is the whole point of this test.
type LiveBpfObject = BpfObject (Ptr CBpfObject) (Ptr CBpfLink)

fixtureSource :: FilePath
fixtureSource = "live-tests/fixtures/hello.bpf.c"

fixtureObject :: FilePath
fixtureObject = "live-tests/fixtures/hello.bpf.o"

-- | Compiles the fixture at test time rather than committing a binary
-- .o to git -- keeps the fixture reproducible and human-inspectable
-- (the .c source is what's tracked), and doubles as a minimal version
-- of the C-side validation harness the implementation spec calls for
-- (a real, independent compilation step the Haskell side must correctly
-- load), not a substitute for a fuller one.
--
-- The explicit -I/usr/include/x86_64-linux-gnu is required: clang's
-- -target bpf cross-compilation doesn't pick up the normal
-- architecture-specific include path the way a native-target build
-- would, so <linux/bpf.h> -> <linux/types.h> -> <asm/types.h> fails to
-- resolve without it. This bit locally (some distros have a top-level
-- /usr/include/asm symlink papering over it) but failed exactly this
-- way on GitHub's hosted Ubuntu runner -- verified by actually running
-- CI, not assumed upfront.
compileFixture :: IO ()
compileFixture =
  callProcess
    "clang"
    [ "-O2"
    , "-g"
    , "-target"
    , "bpf"
    , "-D__TARGET_ARCH_x86"
    , "-I/usr/include/x86_64-linux-gnu"
    , "-c"
    , fixtureSource
    , "-o"
    , fixtureObject
    ]

runLifecycle :: FilePath -> Linear.IO (Either CustodianError ())
runLifecycle path = Control.do
  r1 <- (openObject path :: Linear.IO (Either CustodianError (LiveBpfObject 'Opened)))
  either
    (\e -> Control.pure (Left e))
    ( \obj1 -> Control.do
        r2 <- loadObject obj1
        either
          (\e -> Control.pure (Left e))
          ( \obj2 -> Control.do
              r3 <- attachObject obj2
              either
                -- attachObject now hands back the still-valid Loaded
                -- object on failure -- must be torn down here, or a
                -- real kernel bpf_object is leaked.
                ( Unsafe.toLinear
                    ( \pair -> case pair of
                        (e, obj2') -> Control.do
                          teardown obj2'
                          Control.pure (Left e)
                    )
                )
                ( \obj3 -> Control.do
                    teardown obj3
                    Control.pure (Right ())
                )
                r3
          )
          r2
    )
    r1

-- | Named helper with an explicit rank-2 signature -- this is what
-- pins the map-type witness ('HashMap) and key\/value types
-- (Word32\/Word64) via ordinary type matching against 'withMap''s
-- expected callback type, rather than relying on 'TypeApplications'
-- argument-order guesswork.
counterMapTest :: forall br. LiveMap br 'HashMap Word32 Word64 -> IO (Either CustodianError Word64)
counterMapTest m = do
  wr <- writeMap m 42 100
  case wr of
    Left err -> pure (Left err)
    Right () -> do
      keysResult <- mapKeys m
      case keysResult of
        Left err -> pure (Left err)
        Right ks ->
          if 42 `notElem` ks
            then pure (Left (LibbpfFailure "key 42 not found via mapKeys immediately after writeMap"))
            else do
              rr <- readMap m 42
              case rr of
                Left err -> pure (Left err)
                Right Nothing -> pure (Left (LibbpfFailure "key 42 not found immediately after writeMap"))
                Right (Just v) -> do
                  dr <- deleteMap m 42
                  case dr of
                    Left err -> pure (Left err)
                    Right () -> do
                      afterDelete <- readMap m 42
                      pure $ case afterDelete of
                        Left err -> Left err
                        Right Nothing -> Right v -- confirms deleteMap genuinely removed the key
                        Right (Just _) -> Left (LibbpfFailure "key 42 still present after deleteMap")

-- | Real map write/read/delete round-trip against a genuine kernel-
-- created BPF_MAP_TYPE_HASH map (declared in the fixture .bpf.c) --
-- not just type-checking withMap/readMap/writeMap/deleteMap, actually
-- exercising them.
testMapRoundTrip :: IO ()
testMapRoundTrip = do
  outer <-
    withLoadedBpfObject fixtureObject $
      Unsafe.toLinear
        ( \(obj :: LiveBpfObject 'Loaded) -> do
            let (objRes, obj') = borrowObjRes obj
            mapResult <- withMap objRes "counters" counterMapTest
            Linear.withLinearIO
              ( Control.do
                  teardown obj'
                  Control.pure (Ur ())
              )
            pure (Ur mapResult)
        )
  -- Three nested Eithers here, not two: withLoadedBpfObject's own
  -- (open/load failure), withMap's own (map-not-found), and
  -- counterMapTest's own (the round-trip's internal failure) --
  -- missing this third layer the first time gave a confusing
  -- "No instance for Num (Either CustodianError Word64)" error, not an
  -- obviously-about-nesting one.
  case outer of
    Left err -> do
      putStrLn ("FAILED (withLoadedBpfObject): " ++ show err)
      exitFailure
    Right withMapResult -> case withMapResult of
      Left err -> do
        putStrLn ("FAILED (withMap): " ++ show err)
        exitFailure
      Right innerResult -> case innerResult of
        Left err -> do
          putStrLn ("FAILED (map round-trip): " ++ show err)
          exitFailure
        Right v ->
          if v == 100
            then putStrLn "PASSED: map write/read/delete round-trip succeeded against a real BPF map"
            else do
              putStrLn ("FAILED: expected value 100 after write, got " ++ show v)
              exitFailure

-- | Exercises 'withAttachedBpfObject' against the REAL backend, AND
-- exercises 'borrowObjRes'\/'HasObjRes' on an /Attached/ object (not
-- just 'Loaded', which 'testMapRoundTrip' already covers) -- the
-- vision doc's own stated precondition is that maps are valid once an
-- object is loaded OR attached, so this closes the one remaining case
-- weeder correctly flagged as never actually exercised.
testAttachedRealBackend :: IO ()
testAttachedRealBackend = do
  outer <-
    withAttachedBpfObject fixtureObject $
      Unsafe.toLinear
        ( \(obj :: LiveBpfObject 'Attached) -> do
            let (objRes, obj') = borrowObjRes obj
            mapResult <- withMap objRes "counters" counterMapTest
            Linear.withLinearIO
              ( Control.do
                  teardown obj'
                  Control.pure (Ur ())
              )
            pure (Ur mapResult)
        )
  case outer of
    Left err -> do
      putStrLn ("FAILED (withAttachedBpfObject, real backend): " ++ show err)
      exitFailure
    Right withMapResult -> case withMapResult of
      Left err -> do
        putStrLn ("FAILED (withMap on attached object): " ++ show err)
        exitFailure
      Right innerResult -> case innerResult of
        Left err -> do
          putStrLn ("FAILED (map round-trip on attached object): " ++ show err)
          exitFailure
        Right v ->
          if v == 100
            then putStrLn "PASSED: withAttachedBpfObject + map access succeeded against the real backend"
            else do
              putStrLn ("FAILED: expected value 100, got " ++ show v)
              exitFailure

main :: IO ()
main = do
  uid <- getEffectiveUserID
  if uid /= 0
    then
      putStrLn
        "SKIPPED: live-tests requires root (CAP_BPF) to actually load/attach \
        \a real BPF program into the kernel. Run `sudo cabal test live-tests` \
        \(or equivalent) to exercise this test for real. This is a graceful \
        \skip, not a pass on false pretenses -- see README/CI config for the \
        \privileged runner this is meant to run under."
    else do
      compileFixture
      outcome <- Linear.withLinearIO $ Control.do
        result <- runLifecycle fixtureObject
        either
          (\err -> case move err of Ur e -> Control.pure (Ur (Left e)))
          (\() -> Control.pure (Ur (Right ())))
          result
      case outcome of
        Left err -> do
          putStrLn ("FAILED: " ++ show err)
          exitFailure
        Right () -> putStrLn "PASSED: full open->load->attach->teardown succeeded against a real BPF program"
      testMapRoundTrip
      testAttachedRealBackend
