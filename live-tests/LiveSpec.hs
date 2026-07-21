{-# LANGUAGE DataKinds #-}
{-# LANGUAGE QualifiedDo #-}
module Main (main) where

import Prelude hiding (either)
import qualified Control.Functor.Linear as Control
import qualified System.IO.Linear as Linear
import Prelude.Linear (Ur (..), either, move)
import qualified Unsafe.Linear as Unsafe
import Foreign.Ptr (Ptr)
import Custodian (BpfObject, LifecycleState (..), openObject, loadObject, attachObject, teardown)
import Custodian.Errors (CustodianError)
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
compileFixture :: IO ()
compileFixture =
  callProcess
    "clang"
    [ "-O2"
    , "-g"
    , "-target"
    , "bpf"
    , "-D__TARGET_ARCH_x86"
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
