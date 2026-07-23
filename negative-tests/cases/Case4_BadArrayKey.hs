{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
module Case4_BadArrayKey where
import Data.Word (Word64)
import Custodian.Map (withMap, MapType (ArrayMap))
import Custodian.Mock (MockHandle, mockHandle)

-- MUST NOT COMPILE: there is no `ValidKey 'ArrayMap Word64` (array keys are Word32).
bad :: IO ()
bad = do
  _ <- withMap @MockHandle @'ArrayMap @Word64 @Word64 mockHandle "m" (\_lm -> pure ())
  pure ()
