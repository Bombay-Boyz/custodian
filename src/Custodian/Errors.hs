module Custodian.Errors (CustodianError (..)) where

import Relude

-- | Closed classification of everything that can go wrong across the
-- mock and (later) real backends. Extended, never worked around, per §2.3.
data CustodianError
  = MockFailure String
  deriving (Show, Eq)
