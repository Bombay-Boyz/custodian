{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
-- Positive control: exercises the SAME APIs the negative cases misuse,
-- but correctly, so a passing harness proves the failures below are real.
module Control_ShouldCompile where
import Data.Word (Word32, Word64)
import Custodian.Core (withLoadedBpfObject)
import Custodian.Map (withMap, MapType (HashMap))
import Custodian.Mock (MockHandle, mockHandle)
import Custodian.Errors (CustodianError)

ok1 :: IO (Either CustodianError Int)
ok1 = withLoadedBpfObject @MockHandle "p" (\_scope -> pure 1)

ok2 :: IO (Either CustodianError ())
ok2 = withMap @MockHandle @'HashMap @Word32 @Word64 mockHandle "m" (\_lm -> pure ())
