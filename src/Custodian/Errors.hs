module Custodian.Errors (CustodianError (..)) where

import Relude
import Data.Unrestricted.Linear (Consumable (..))

-- | Closed classification of everything that can go wrong across the
-- mock and (later) real backends. Extended, never worked around, per §2.3.
data CustodianError
  = MockFailure String
  deriving (Show, Eq)

instance Consumable CustodianError where
  consume (MockFailure s) = consume s
