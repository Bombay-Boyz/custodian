{-# LANGUAGE QualifiedDo #-}
module Main (main) where

import Prelude hiding (either)
import qualified Control.Functor.Linear as Control
import qualified System.IO.Linear as Linear
import Prelude.Linear (Ur (..), either, move)
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
    -- 'move' pulls a plain, freely-reusable copy of the error out of
    -- linear-land (via 'Ur') so it can actually be shown/logged, rather
    -- than only ever discarded via 'consume'.
    ( \err -> case move err of
        Ur e -> Control.do
          Linear.fromSystemIO (putStrLn ("custodian: lifecycle failed: " ++ show e))
          Control.pure (Ur ())
    )
    ( \() -> Control.do
        Linear.fromSystemIO (putStrLn "custodian: lifecycle completed successfully (mock backend)")
        Control.pure (Ur ())
    )
    result
