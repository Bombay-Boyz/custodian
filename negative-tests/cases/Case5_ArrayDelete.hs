{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
module Case5_ArrayDelete where
import Data.Word (Word32, Word64)
import Custodian.Map (withMap, deleteMap, MapType (ArrayMap))
import Custodian.Mock (MockHandle, mockHandle)
import Custodian.Errors (CustodianError)

-- MUST NOT COMPILE: there is no `Deletable 'ArrayMap` instance, because a
-- BPF_MAP_TYPE_ARRAY slot cannot be deleted (bpf_map_delete_elem -> EINVAL).
bad :: IO (Either CustodianError (Either CustodianError ()))
bad = withMap @MockHandle @'ArrayMap @Word32 @Word64 mockHandle "arr" (\m -> deleteMap m 0)
