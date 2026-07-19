{-# LANGUAGE QualifiedDo #-}
module Main (main) where

import Prelude hiding (either)
import qualified Control.Functor.Linear as Control
import qualified System.IO.Linear as Linear
import Prelude.Linear (Ur (..), either, move)
import Custodian (openObject, loadObject, attachObject, teardown)
import Custodian.Errors (CustodianError)
import Hedgehog
import qualified Hedgehog.Gen as Gen
import qualified Hedgehog.Range as Range
import Test.Tasty
import Test.Tasty.Hedgehog (testProperty)

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

prop_mockLifecycleSucceeds :: Property
prop_mockLifecycleSucceeds = property $ do
  path <- forAll (Gen.string (Range.linear 1 64) Gen.alphaNum)
  -- 'move' the error out of linear-land (via 'Ur') so a failure actually
  -- shows what went wrong, rather than just "expected True, got False".
  outcome <- evalIO $ Linear.withLinearIO $ Control.do
    r <- runLifecycle path
    either
      (\e -> case move e of Ur e' -> Control.pure (Ur (Left e')))
      (\() -> Control.pure (Ur (Right ())))
      r
  case outcome of
    Left err -> annotateShow err >> failure
    Right () -> success

main :: IO ()
main =
  defaultMain $
    testGroup
      "custodian"
      [ testProperty "mock lifecycle open->load->attach->teardown succeeds" prop_mockLifecycleSucceeds
      ]
