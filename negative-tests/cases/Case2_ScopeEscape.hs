{-# LANGUAGE TypeApplications #-}
module Case2_ScopeEscape where
import Custodian.Core (withLoadedBpfObject, Scope)
import Custodian.Mock (MockHandle)
import Custodian.Errors (CustodianError)

-- MUST NOT COMPILE: the branded Scope cannot be returned out of the callback.
bad :: IO (Either CustodianError (Scope br MockHandle))
bad = withLoadedBpfObject @MockHandle "p" (\scope -> pure scope)
