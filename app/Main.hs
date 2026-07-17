{-# LANGUAGE QualifiedDo #-}
module Main (main) where

import Prelude hiding (either)
import qualified Control.Functor.Linear as Control
import qualified System.IO.Linear as Linear
import Prelude.Linear (Ur (..), either, consume, lseq)
import Custodian (openObject, loadObject, attachObject, teardown)
import Custodian.Errors (CustodianError)

runLifecycle :: FilePath -> Linear.IO (Either CustodianError ())
runLifecycle path = Control.do
  r1 <- openObject path
  either
    (\e -> Control.pure (Left e))
    ( \obj1 -> Control.do
        r2 <- loadObject obj1
        either
          (\e -> Control.pure (Left e))
          ( \obj2 -> Control.do
              r3 <- attachObject obj2
              either
                (\e -> Control.pure (Left e))
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
main = Linear.withLinearIO $ Control.do
  result <- runLifecycle "example.bpf.o"
  either
    -- Explicitly 'consume' the error rather than trying to 'show' it --
    -- getting a value *out* of a linear resource to log it is a real
    -- open question (see note above), not something solved here.
    ( \err -> Control.do
        consume err `lseq` Linear.fromSystemIO (putStrLn "custodian: lifecycle failed")
        Control.pure (Ur ())
    )
    ( \() -> Control.do
        Linear.fromSystemIO (putStrLn "custodian: lifecycle completed successfully (mock backend)")
        Control.pure (Ur ())
    )
    result
