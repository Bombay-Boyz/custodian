{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
module Case3_LiveMapEscape where
import Data.Word (Word32, Word64)
import Custodian.Map (withMap, LiveMap, MapType (HashMap))
import Custodian.Mock (MockHandle, MockSys, mockHandle)
import Custodian.Errors (CustodianError)

-- MUST NOT COMPILE: the branded LiveMap cannot escape the callback.
bad :: IO (Either CustodianError (LiveMap MockSys br 'HashMap Word32 Word64))
bad = withMap @MockHandle @'HashMap @Word32 @Word64 mockHandle "m" (\lm -> pure lm)
